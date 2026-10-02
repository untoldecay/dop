// `dop token issue/list/revoke` — capability lifecycle.
//
// All ops require an active admin session — the daemon holds the vault
// decrypt key and the ed25519 signing key. This CLI orchestrates:
//
//   1. Ask daemon to decrypt vault.yaml → plaintext YAML
//   2. Mutate the parsed vault (add capability record / mark revoked)
//   3. Write bundle file to disk
//   4. Ask daemon to sign the record's canonical payload
//   5. Ask daemon to re-encrypt vault.yaml
//   6. Commit + push (best-effort)

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/audit"
	"github.com/fray/dop/internal/capability"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/envseal"
	"github.com/fray/dop/internal/trust"
	"github.com/fray/dop/internal/vault"
)

func runToken(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: dop token <issue|list|show|revoke|repin|reseal|add-grant|remove-grant|rotate> ...")
		return 2
	}
	switch args[0] {
	case "issue":
		return runTokenIssue(args[1:])
	case "list":
		return runTokenList(args[1:])
	case "show":
		return runTokenShow(args[1:])
	case "revoke":
		return runTokenRevoke(args[1:])
	case "repin":
		return runTokenRepin(args[1:])
	case "reseal":
		return runTokenReseal(args[1:])
	case "add-grant":
		return runTokenAddGrant(args[1:])
	case "remove-grant":
		return runTokenRemoveGrant(args[1:])
	case "rotate":
		return runTokenRotate(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "dop token: unknown subcommand %q\n", args[0])
		return 2
	}
}

// runTokenShow prints the detail view for a single token: subject,
// expiry, generation, status, binding, and the grants that resolve to
// which env vars via which integrations. Read-only; grant editing
// lives in v1.12.
//
// Match is a lookup-ID prefix (min 6 chars) — same style as list.
func runTokenShow(args []string) int {
	fs := flag.NewFlagSet("token show", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "emit JSON instead of human-readable")
	// Go's stdlib flag parser stops at the first non-flag arg, so
	// `dop token show subject --json` would leave --json unparsed.
	// Pre-split so either order works.
	flagArgs, posArgs := splitFlagsAndPositionals(fs, args)
	_ = fs.Parse(flagArgs)
	if len(posArgs) != 1 {
		fmt.Fprintln(os.Stderr, "usage: dop token show <lookup-id-prefix|subject> [--json]")
		return 2
	}
	needle := posArgs[0]

	paths, _ := config.Resolve()
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token show: %v\n", err)
		return 1
	}
	v, _, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token show: %v\n", err)
		return 1
	}

	var (
		match   vault.Capability
		matchID string
		hits    []string
	)
	for id, c := range v.Capabilities {
		if strings.HasPrefix(id, needle) || strings.HasPrefix(c.LookupID, needle) || strings.EqualFold(c.Subject, needle) {
			hits = append(hits, id)
			match = c
			matchID = id
		}
	}
	if len(hits) == 0 {
		fmt.Fprintf(os.Stderr, "dop token show: no token matches %q\n", needle)
		return 1
	}
	// v1.12 — after a rotation, one subject has two records (old
	// status=rotated, new status=active). Prefer active on ambiguity;
	// only error if there are still multiple active hits.
	if len(hits) > 1 {
		var active []string
		for _, h := range hits {
			if v.Capabilities[h].Status == capability.RecordStatusActive {
				active = append(active, h)
			}
		}
		if len(active) == 1 {
			matchID = active[0]
			match = v.Capabilities[matchID]
		} else {
			fmt.Fprintf(os.Stderr, "dop token show: %d tokens match %q — narrow with more prefix chars:\n", len(hits), needle)
			for _, h := range hits {
				fmt.Fprintf(os.Stderr, "  %s  %s  (status=%s)\n", h[:12], v.Capabilities[h].Subject, v.Capabilities[h].Status)
			}
			return 1
		}
	}

	// Resolve each grant → integration/token/env-var.
	type grantView struct {
		ID          string `json:"id"`
		Integration string `json:"integration"`
		Token       string `json:"token"`
		EnvVar      string `json:"env_var"`
		Missing     bool   `json:"missing,omitempty"`
	}
	grants := make([]grantView, 0, len(match.Grants))
	for _, gid := range match.Grants {
		g, ok := v.Grants[gid]
		if !ok {
			grants = append(grants, grantView{ID: gid, Missing: true})
			continue
		}
		grants = append(grants, grantView{
			ID: gid, Integration: g.Integration, Token: g.Token,
			EnvVar: g.EffectivePrefix() + "_TOKEN",
		})
	}

	bindingKind := ""
	bindingPubkey := ""
	bindingKeyType := ""
	if match.Binding != nil {
		bindingKind = match.Binding.Kind
		bindingPubkey = match.Binding.Pubkey
		bindingKeyType = match.Binding.EffectiveKeyType()
	}

	if *asJSON {
		emitJSON(map[string]any{
			"cap_id":      matchID,
			"lookup_id":   match.LookupID,
			"subject":     match.Subject,
			"status":      match.Status,
			"generation":  match.Generation,
			"created_at":  match.CreatedAt.Format(time.RFC3339),
			"expires_at":  tokenExpiryDisplay(match.ExpiresAt),
			"issued_by":   match.IssuedBy,
			"bundle_hash": match.BundleHash,
			"binding": map[string]any{
				"kind":     bindingKind,
				"pubkey":   bindingPubkey,
				"key_type": bindingKeyType,
			},
			"grants": grants,
		})
		return 0
	}
	fmt.Printf("cap_id:       %s\n", matchID)
	fmt.Printf("lookup_id:    %s\n", match.LookupID)
	fmt.Printf("subject:      %s\n", match.Subject)
	fmt.Printf("status:       %s\n", match.Status)
	fmt.Printf("generation:   %d\n", match.Generation)
	fmt.Printf("created_at:   %s\n", match.CreatedAt.Format(time.RFC3339))
	fmt.Printf("expires_at:   %s\n", tokenExpiryDisplay(match.ExpiresAt))
	fmt.Printf("issued_by:    %s\n", match.IssuedBy)
	if bindingKind != "" {
		fmt.Printf("binding.kind: %s\n", bindingKind)
		if bindingPubkey != "" {
			fmt.Printf("binding.pubkey: %s (key_type=%s)\n", bindingPubkey, bindingKeyType)
		}
	}
	fmt.Printf("grants (%d):\n", len(grants))
	for _, g := range grants {
		if g.Missing {
			fmt.Printf("  - %s  ⚠  grant no longer in vault\n", g.ID)
			continue
		}
		fmt.Printf("  - %s  → %s.%s  env=%s\n", g.ID, g.Integration, g.Token, g.EnvVar)
	}
	return 0
}

func runTokenIssue(args []string) int {
	fs := flag.NewFlagSet("token issue", flag.ExitOnError)
	grantsCSV := fs.String("grants", "", "comma-separated grant IDs (required unless --project)")
	projectFilter := fs.String("project", "", "resolve grants by project name (bundles all grants tagged with this project)")
	tagsCSV := fs.String("tags", "", "when combined with --project or --grants, keep only grants carrying ALL these tags")
	name := fs.String("name", "", "human-readable subject/label")
	expires := fs.String("expires", "72h", "duration until expiry (e.g. 72h, 30d, 4w) or the literal \"never\" for no expiry (revoke manually)")
	note := fs.String("note", "", "free-text note (not used in v1.0)")
	bindPubkey := fs.String("bind-pubkey", "", "pre-bind the bearer to this ed25519 pubkey (hex)")
	noBind := fs.Bool("no-bind", false, "issue an unbound bearer (bearer alone grants access)")
	// v1.13.0-rc11 — default bumped from 5m to 1h after ClaudeMini field
	// report: 5m is CLI-friendly but kills chat UX (PIN expired three
	// times during one back-and-forth with the admin). 1h matches a
	// typical chat session; `dop token repin` is the escape hatch when
	// it still runs out.
	pinTTL := fs.String("pin-ttl", "1h", "PIN validity window when --bind is default (shorter = tighter; use `dop token repin` if it expires)")
	// v1.13.0-rc12 — issuing a bearer that contains protected grants
	// requires the admin passphrase (same gate as creating one).
	passphraseStdin := fs.Bool("passphrase-stdin", false, "read the approval passphrase from stdin instead of the tty (used when any of --grants is protected; TUI passes this)")
	_ = fs.Parse(args)
	_ = note

	if strings.TrimSpace(*grantsCSV) == "" && strings.TrimSpace(*projectFilter) == "" {
		fmt.Fprintln(os.Stderr, "dop token issue: one of --grants or --project is required")
		return 2
	}
	if *noBind && *bindPubkey != "" {
		fmt.Fprintln(os.Stderr, "dop token issue: --no-bind and --bind-pubkey are mutually exclusive")
		return 2
	}
	pinDur, err := time.ParseDuration(*pinTTL)
	if err != nil || pinDur <= 0 {
		fmt.Fprintf(os.Stderr, "dop token issue: --pin-ttl: %v\n", err)
		return 2
	}
	grants := splitCSV(*grantsCSV)
	// v1.11.1 — --expires=never issues a bearer with the far-future
	// sentinel timestamp (9999-12-31). Effectively unbounded; caller
	// should still `dop token revoke` when the bearer is retired.
	// Displayed as "never" in list / show output; stored as a normal
	// (very large) unix timestamp so no schema change is needed.
	var expiresAt time.Time
	neverExpires := strings.EqualFold(strings.TrimSpace(*expires), "never")
	var expDur time.Duration
	if neverExpires {
		expiresAt = tokenNeverSentinel()
	} else {
		var err error
		expDur, err = parseDurationLoose(*expires)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dop token issue: --expires: %v\n", err)
			return 2
		}
		if expDur <= 0 {
			fmt.Fprintln(os.Stderr, "dop token issue: --expires must be positive (or the literal string \"never\")")
			return 2
		}
	}

	paths, _ := config.Resolve()
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token issue: %v\n", err)
		return 1
	}

	v, vaultPath, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token issue: %v\n", err)
		return 1
	}

	// v1.8: augment explicit --grants with any grants matching --project
	// (and, optionally, ALL of --tags). De-duplicate so passing both
	// --grants and --project doesn't double-count.
	tagFilter := splitCSV(*tagsCSV)
	if strings.TrimSpace(*projectFilter) != "" {
		seen := map[string]bool{}
		for _, g := range grants {
			seen[g] = true
		}
		for gid, g := range v.Grants {
			if !containsFold(g.Projects, *projectFilter) {
				continue
			}
			if !hasAllTags(g.Tags, tagFilter) {
				continue
			}
			if !seen[gid] {
				grants = append(grants, gid)
				seen[gid] = true
			}
		}
		if len(grants) == 0 {
			fmt.Fprintf(os.Stderr, "dop token issue: no grants match --project=%q --tags=%v\n", *projectFilter, tagFilter)
			return 1
		}
	} else if len(tagFilter) > 0 {
		// --tags without --project narrows the explicit --grants set.
		filtered := grants[:0]
		for _, gid := range grants {
			g, ok := v.Grants[gid]
			if !ok {
				continue
			}
			if hasAllTags(g.Tags, tagFilter) {
				filtered = append(filtered, gid)
			}
		}
		grants = filtered
	}

	// Validate grants exist + surface env-prefix collisions before
	// silently overwriting.
	unknown := []string{}
	for _, g := range grants {
		if _, ok := v.Grants[g]; !ok {
			unknown = append(unknown, g)
		}
	}
	if len(unknown) > 0 {
		fmt.Fprintf(os.Stderr, "dop token issue: unknown grants: %v\n", unknown)
		return 1
	}
	if colliders := detectPrefixCollisions(v, grants); len(colliders) > 0 {
		fmt.Fprintln(os.Stderr, "dop token issue: env-prefix collision — the last grant will overwrite the earlier one silently:")
		for prefix, gs := range colliders {
			fmt.Fprintf(os.Stderr, "  %s_TOKEN used by: %s\n", prefix, strings.Join(gs, ", "))
		}
		fmt.Fprintln(os.Stderr, "  fix: set an explicit env_prefix on the colliding grant(s), or drop one from --grants.")
		return 1
	}

	// v1.13.0-rc12 — if any grant in the bundle is protected, we must
	// own ALL protected grants + prove possession of the approval
	// passphrase before issuing. A bearer-level gate is enough — the
	// payload is only decoded on resolve, and the audit event ties the
	// subject to the protected grant set.
	var protectedGrants []string
	for _, gid := range grants {
		g := v.Grants[gid]
		if !g.Protected {
			continue
		}
		if err := requireProtectionOwner(client, "grant "+gid, g.Protected, g.Owner); err != nil {
			fmt.Fprintf(os.Stderr, "dop token issue: %v\n", err)
			return 1
		}
		protectedGrants = append(protectedGrants, gid)
	}
	if len(protectedGrants) > 0 {
		if err := promptProtectionPassphrase(paths, fmt.Sprintf("approval passphrase (issue bearer containing %d protected grant(s)): ", len(protectedGrants)), *passphraseStdin); err != nil {
			fmt.Fprintf(os.Stderr, "dop token issue: %v\n", err)
			return 1
		}
	}

	// Ensure vault_context exists (both in the vault AND as a sidecar
	// so agent installs — which can't decrypt the vault — can compute
	// lookup ids).
	if v.VaultContext == "" {
		ctx := make([]byte, 20)
		rand.Read(ctx)
		v.VaultContext = hex.EncodeToString(ctx)
	}
	vaultCtx, _ := hex.DecodeString(v.VaultContext)
	ctxSidecarPath := filepath.Join(paths.Vault, "vault-context.bin")
	if _, err := os.Stat(ctxSidecarPath); os.IsNotExist(err) {
		_ = os.WriteFile(ctxSidecarPath, vaultCtx, 0o644)
	}

	// Generate bearer + capability id.
	bearer, err := capability.NewBearer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token issue: %v\n", err)
		return 1
	}
	capIDRaw, err := capability.NewCapabilityID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token issue: %v\n", err)
		return 1
	}
	capIDHex := hex.EncodeToString(capIDRaw[:])
	subject := strings.TrimSpace(*name)
	if subject == "" {
		subject = "token-" + capIDHex[:8]
	}

	// Resolve grants → env bundle.
	envBundle := resolveGrantsToEnv(v, grants)
	if len(envBundle) == 0 {
		fmt.Fprintln(os.Stderr, "dop token issue: resolved env bundle is empty (are the grants wired to integrations?)")
		return 1
	}

	// Bump the per-subject generation.
	gen := v.BumpGeneration(subject)
	if !neverExpires {
		expiresAt = time.Now().Add(expDur).UTC().Truncate(time.Second)
	}
	lookupID := capability.LookupID(vaultCtx, bearer)

	// Resolve binding mode. Default is PIN-claim: user copies bearer+PIN
	// to their agent, agent runs `dop claim PIN` to bind an identity.
	var pin string
	var envBinding *capability.EnvelopeBinding
	var recBinding *capability.RecordBinding
	switch {
	case *noBind:
		envBinding = &capability.EnvelopeBinding{Kind: vault.BindingKindNone}
		recBinding = &capability.RecordBinding{Kind: vault.BindingKindNone}
	case *bindPubkey != "":
		envBinding = &capability.EnvelopeBinding{
			Kind:   vault.BindingKindPubkey,
			Pubkey: *bindPubkey,
		}
		recBinding = &capability.RecordBinding{
			Kind:      vault.BindingKindPubkey,
			Pubkey:    *bindPubkey,
			ClaimedAt: time.Now().UTC().Truncate(time.Second),
		}
	default:
		p, err := capability.NewPIN()
		if err != nil {
			fmt.Fprintf(os.Stderr, "dop token issue: %v\n", err)
			return 1
		}
		pin = p
		pinExpiry := time.Now().Add(pinDur).UTC().Truncate(time.Second)
		envBinding = &capability.EnvelopeBinding{
			Kind:      vault.BindingKindPIN,
			PinHash:   capability.HashPIN(bearer, pin),
			PinExpiry: pinExpiry.Unix(),
		}
		recBinding = &capability.RecordBinding{
			Kind:      vault.BindingKindPIN,
			PinExpiry: pinExpiry,
		}
	}

	// Write bundle to disk.
	bundlePath := filepath.Join(paths.Vault, "capabilities", lookupID+".bundle")
	if err := os.MkdirAll(filepath.Dir(bundlePath), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "dop token issue: %v\n", err)
		return 1
	}
	f, err := os.Create(bundlePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token issue: %v\n", err)
		return 1
	}
	bundleBytes, err := capability.Write(f, capability.WriteOpts{
		CapabilityID: capIDRaw,
		Bearer:       bearer,
		Generation:   gen,
		ExpiresAt:    expiresAt,
		Subject:      subject,
		Env:          envBundle,
		Binding:      envBinding,
	})
	f.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token issue: write bundle: %v\n", err)
		return 1
	}
	bundleHash := capability.HashBundle(bundleBytes)

	// Build capability record and sign via daemon.
	rec := capability.Record{
		CapabilityID: capIDHex,
		Subject:      subject,
		Grants:       grants,
		CreatedAt:    time.Now().UTC().Truncate(time.Second),
		ExpiresAt:    expiresAt,
		Generation:   gen,
		LookupID:     lookupID,
		BundleHash:   bundleHash,
		Status:       capability.RecordStatusActive,
		Binding:      recBinding,
	}
	if err := signRecordViaDaemon(client, &rec); err != nil {
		fmt.Fprintf(os.Stderr, "dop token issue: sign: %v\n", err)
		return 1
	}
	if v.Capabilities == nil {
		v.Capabilities = map[string]vault.Capability{}
	}
	v.Capabilities[capIDHex] = capability2VaultCapability(rec)

	if err := saveVaultViaDaemon(client, paths, vaultPath, v); err != nil {
		// v1.6.4: clean the orphan bundle so the on-disk state stays
		// consistent with the un-saved vault. Without this, the next
		// issue for the same subject would bump the generation from
		// the stale vault count and collide with this bundle's gen.
		_ = os.Remove(bundlePath)
		fmt.Fprintf(os.Stderr, "dop token issue: %v (rolled back bundle)\n", err)
		return 1
	}
	if err := writeRecordSidecar(paths, rec); err != nil {
		// Vault has the record but sidecar failed. Roll bundle back
		// too — without the sidecar, exec would reject anyway.
		_ = os.Remove(bundlePath)
		fmt.Fprintf(os.Stderr, "dop token issue: write record: %v (rolled back bundle; vault out of sync — run `dop token revoke %s`)\n", err, subject)
		return 1
	}

	audit.Append(paths, audit.Event{
		Kind:     audit.EventIssue,
		Subject:  subject,
		LookupID: lookupID,
		Extra: map[string]string{
			"binding":    envBinding.Kind,
			"grants":     strings.Join(grants, ","),
			"expires_at": tokenExpiryDisplay(expiresAt),
		},
	})
	// v1.13.0-rc12 — second trail for forensic correlation when a
	// protected credential appears in a bundle.
	if len(protectedGrants) > 0 {
		logProtectedTokenIssue(paths, subject, protectedGrants)
	}
	fmt.Fprintf(os.Stderr, "dop token issue: issued %s (grants: %v, expires: %s)\n", subject, grants, tokenExpiryDisplay(expiresAt))
	if pin != "" {
		fmt.Fprintln(os.Stderr, "  bearer + PIN (shown ONCE — copy now):")
		fmt.Println(bearer)
		fmt.Println(pin)
		fmt.Fprintf(os.Stderr, "  PIN valid for %s. Tell your agent: `dop claim %s`\n", pinDur, pin)
	} else {
		fmt.Fprintln(os.Stderr, "  bearer (shown ONCE — copy now):")
		fmt.Println(bearer)
	}
	return 0
}

func runTokenList(args []string) int {
	fs := flag.NewFlagSet("token list", flag.ExitOnError)
	all := fs.Bool("all", false, "include revoked capabilities (default: active only)")
	_ = fs.Parse(args)

	paths, _ := config.Resolve()
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token list: %v\n", err)
		return 1
	}
	v, _, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token list: %v\n", err)
		return 1
	}
	if len(v.Capabilities) == 0 {
		fmt.Println("(no capabilities)")
		return 0
	}
	names := make([]string, 0, len(v.Capabilities))
	for id := range v.Capabilities {
		names = append(names, id)
	}
	sort.Strings(names)
	shown, hidden := 0, 0
	for _, id := range names {
		c := v.Capabilities[id]
		if !*all && c.Status != capability.RecordStatusActive {
			hidden++
			continue
		}
		fmt.Printf("- %s  subject=%s  grants=%v  gen=%d  status=%s  expires=%s\n",
			id[:12], c.Subject, c.Grants, c.Generation, c.Status,
			tokenExpiryDisplay(c.ExpiresAt))
		shown++
	}
	if shown == 0 && hidden > 0 {
		fmt.Printf("(no active capabilities; %d revoked hidden — use --all to include)\n", hidden)
	} else if hidden > 0 {
		fmt.Printf("\n(%d revoked hidden — use --all to include)\n", hidden)
	}
	return 0
}

func runTokenRevoke(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: dop token revoke <subject|cap-id-prefix|lookup-prefix>")
		return 2
	}
	query := args[0]

	paths, _ := config.Resolve()
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token revoke: %v\n", err)
		return 1
	}
	v, vaultPath, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token revoke: %v\n", err)
		return 1
	}

	// v1.13 — match by subject OR capID-prefix OR lookup-prefix.
	// Without this, two active caps sharing a subject (which can
	// happen if an operator issues the same --name twice OR a TUI
	// state carry-over slips through) cannot be revoked by name at
	// all. prefix match lets callers always disambiguate.
	var candidates []string
	for id, c := range v.Capabilities {
		if c.Status != capability.RecordStatusActive {
			continue
		}
		if c.Subject == query || strings.HasPrefix(id, query) || strings.HasPrefix(c.LookupID, query) {
			candidates = append(candidates, id)
		}
	}
	if len(candidates) == 0 {
		fmt.Fprintf(os.Stderr, "dop token revoke: no active capability matches %q\n", query)
		return 1
	}
	if len(candidates) > 1 {
		fmt.Fprintf(os.Stderr, "dop token revoke: %d active capabilities match %q — pass the cap-id or lookup prefix:\n", len(candidates), query)
		for _, id := range candidates {
			c := v.Capabilities[id]
			fmt.Fprintf(os.Stderr, "  cap=%s  lookup=%s  subject=%s\n", id[:12], c.LookupID[:12], c.Subject)
		}
		return 1
	}
	matched := candidates[0]
	c := v.Capabilities[matched]
	c.Status = capability.RecordStatusRevoked
	// Bump generation on revoke so any cached bundle is superseded.
	c.Generation = v.BumpGeneration(c.Subject)

	// Re-sign the record with the new status.
	rec := vaultCapability2Record(c, matched)
	if err := signRecordViaDaemon(client, &rec); err != nil {
		fmt.Fprintf(os.Stderr, "dop token revoke: %v\n", err)
		return 1
	}
	v.Capabilities[matched] = capability2VaultCapability(rec)

	// Delete the bundle + record files.
	bundlePath := filepath.Join(paths.Vault, "capabilities", c.LookupID+".bundle")
	if err := os.Remove(bundlePath); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "dop token revoke: warning: %v\n", err)
	}
	recordPath := filepath.Join(paths.Vault, "capabilities", c.LookupID+".record")
	if err := os.Remove(recordPath); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "dop token revoke: warning: %v\n", err)
	}
	// v1.13 — also remove the local agent key file(s) for this
	// bearer. Only runs on the machine where the agent claimed; a
	// remote admin running revoke never sees these files, so it's a
	// no-op there. Covers both ed25519 and p256 file-backed keys.
	for _, suffix := range []string{".key", ".p256"} {
		p := filepath.Join(paths.Root, "agent-keys", c.LookupID+suffix)
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "dop token revoke: warning: local agent key %s: %v\n", p, err)
		}
	}

	if err := saveVaultViaDaemon(client, paths, vaultPath, v); err != nil {
		fmt.Fprintf(os.Stderr, "dop token revoke: %v\n", err)
		return 1
	}
	audit.Append(paths, audit.Event{
		Kind:     audit.EventRevoke,
		Subject:  c.Subject,
		LookupID: c.LookupID,
	})
	fmt.Fprintf(os.Stderr, "dop token revoke: revoked %s (gen bumped to %d)\n", query, c.Generation)
	return 0
}

func runTokenRepin(args []string) int {
	fs := flag.NewFlagSet("token repin", flag.ExitOnError)
	subject := fs.String("subject", "", "subject whose PIN should be reissued (required)")
	tokenFile := fs.String("token-file", "", "read the current bearer from file")
	// v1.13.0-rc11 — matches the issue-time default (1h for chat UX).
	pinTTL := fs.String("pin-ttl", "1h", "PIN validity window")
	_ = fs.Parse(args)

	if strings.TrimSpace(*subject) == "" {
		fmt.Fprintln(os.Stderr, "dop token repin: --subject is required")
		return 2
	}
	pinDur, err := time.ParseDuration(*pinTTL)
	if err != nil || pinDur <= 0 {
		fmt.Fprintf(os.Stderr, "dop token repin: --pin-ttl: %v\n", err)
		return 2
	}
	bearer, err := readBearer(*tokenFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token repin: %v — supply via $DOP_TOKEN or --token-file\n", err)
		return 1
	}

	paths, _ := config.Resolve()
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token repin: %v\n", err)
		return 1
	}
	v, vaultPath, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token repin: %v\n", err)
		return 1
	}

	// Match subject → capability record.
	var (
		capIDHex string
		crec     vault.Capability
		matched  int
	)
	for id, c := range v.Capabilities {
		if c.Subject == *subject && c.Status == capability.RecordStatusActive {
			capIDHex = id
			crec = c
			matched++
		}
	}
	if matched == 0 {
		fmt.Fprintf(os.Stderr, "dop token repin: no active capability with subject %q\n", *subject)
		return 1
	}
	if matched > 1 {
		fmt.Fprintf(os.Stderr, "dop token repin: subject %q matches multiple active capabilities\n", *subject)
		return 1
	}
	if crec.Binding == nil || crec.Binding.Kind != vault.BindingKindPIN {
		fmt.Fprintln(os.Stderr, "dop token repin: capability is not PIN-bound; nothing to repin")
		return 1
	}
	if crec.Binding.Pubkey != "" {
		fmt.Fprintln(os.Stderr, "dop token repin: capability is already claimed; revoke + re-issue to rebind")
		return 1
	}

	// Verify the supplied bearer really is the one for this capability by
	// decrypting the bundle. This also protects against mismatched
	// --token-file / --subject combos.
	ctxPath := filepath.Join(paths.Vault, "vault-context.bin")
	vaultCtx, err := os.ReadFile(ctxPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token repin: no vault_context: %v\n", err)
		return 1
	}
	lookupID := capability.LookupID(vaultCtx, bearer)
	if lookupID != crec.LookupID {
		fmt.Fprintln(os.Stderr, "dop token repin: bearer does not match this subject")
		return 1
	}
	bundlePath := filepath.Join(paths.Vault, "capabilities", lookupID+".bundle")
	oldBundleBytes, err := os.ReadFile(bundlePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token repin: %v\n", err)
		return 1
	}
	env, hdr, err := capability.Read(oldBundleBytes, capability.ReadOpts{Bearer: bearer})
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token repin: decrypt bundle: %v\n", err)
		return 1
	}

	// Generate new PIN, rewrite the bundle in place.
	newPIN, err := capability.NewPIN()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token repin: %v\n", err)
		return 1
	}
	pinExpiry := time.Now().Add(pinDur).UTC().Truncate(time.Second)
	newGen := v.BumpGeneration(crec.Subject)

	newEnvBinding := &capability.EnvelopeBinding{
		Kind:      vault.BindingKindPIN,
		PinHash:   capability.HashPIN(bearer, newPIN),
		PinExpiry: pinExpiry.Unix(),
	}
	tmpPath := bundlePath + ".tmp"
	f, err := os.Create(tmpPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token repin: %v\n", err)
		return 1
	}
	newBundleBytes, err := capability.Write(f, capability.WriteOpts{
		CapabilityID: hdr.CapabilityID,
		Bearer:       bearer,
		Generation:   newGen,
		ExpiresAt:    time.Unix(hdr.ExpiresAtUnix, 0).UTC(),
		Subject:      env.Subject,
		Env:          env.Env,
		Binding:      newEnvBinding,
	})
	f.Close()
	if err != nil {
		os.Remove(tmpPath)
		fmt.Fprintf(os.Stderr, "dop token repin: rewrite bundle: %v\n", err)
		return 1
	}
	newBundleHash := capability.HashBundle(newBundleBytes)

	crec.Generation = newGen
	crec.BundleHash = newBundleHash
	crec.Binding.PinExpiry = pinExpiry
	rec := vaultCapability2Record(crec, capIDHex)
	if err := signRecordViaDaemon(client, &rec); err != nil {
		os.Remove(tmpPath)
		fmt.Fprintf(os.Stderr, "dop token repin: sign: %v\n", err)
		return 1
	}
	v.Capabilities[capIDHex] = capability2VaultCapability(rec)
	if err := saveVaultViaDaemon(client, paths, vaultPath, v); err != nil {
		os.Remove(tmpPath)
		fmt.Fprintf(os.Stderr, "dop token repin: save vault: %v\n", err)
		return 1
	}
	if err := os.Rename(tmpPath, bundlePath); err != nil {
		fmt.Fprintf(os.Stderr, "dop token repin: swap bundle: %v\n", err)
		return 1
	}
	if err := writeRecordSidecar(paths, rec); err != nil {
		fmt.Fprintf(os.Stderr, "dop token repin: write record: %v\n", err)
		return 1
	}

	audit.Append(paths, audit.Event{
		Kind:     audit.EventRepin,
		Subject:  crec.Subject,
		LookupID: lookupID,
		Extra:    map[string]string{"pin_ttl": pinDur.String()},
	})
	fmt.Fprintf(os.Stderr, "dop token repin: reissued PIN for %s (valid %s)\n", *subject, pinDur)
	fmt.Fprintln(os.Stderr, "  new PIN (shown ONCE):")
	fmt.Println(newPIN)
	return 0
}

// --- daemon-mediated helpers ---

func requireAdminSession(paths *config.Paths) (*admin.Client, error) {
	client := admin.NewClient(admin.SockPath(paths))
	if !client.SessionActive() {
		return nil, fmt.Errorf("no active admin session — run `dop admin login` first")
	}
	return client, nil
}

// vaultFilePath returns the vault.yaml path, bootstrapping empty if missing.
func vaultFilePath(paths *config.Paths) string {
	return filepath.Join(paths.Vault, "vault.yaml")
}

// loadVaultViaDaemon asks the daemon to decrypt vault.yaml; parses it.
// If vault.yaml doesn't exist yet, returns a fresh v1 vault.
func loadVaultViaDaemon(client *admin.Client, paths *config.Paths) (*vault.Vault, string, error) {
	vp := vaultFilePath(paths)
	fi, err := os.Stat(vp)
	if err != nil && !os.IsNotExist(err) {
		return nil, vp, err
	}
	if fi == nil || fi.Size() == 0 {
		// Fresh vault — no need to call daemon.
		return &vault.Vault{SchemaVersion: vault.SchemaVersion}, vp, nil
	}
	// If it's not SOPS-encrypted (fresh test seed), read directly.
	raw, err := os.ReadFile(vp)
	if err != nil {
		return nil, vp, err
	}
	if !bytes.Contains(raw, []byte("\nsops:")) && !bytes.HasPrefix(raw, []byte("sops:")) {
		v, err := vault.ParsePlain(raw)
		return v, vp, err
	}
	plain, err := client.DecryptVault(vp)
	if err != nil {
		return nil, vp, err
	}
	v, err := vault.ParsePlain(plain)
	return v, vp, err
}

// saveVaultViaDaemon marshals vault and asks the daemon to encrypt +
// write. Uses the admin's own age recipient from the session status.
func saveVaultViaDaemon(client *admin.Client, paths *config.Paths, vaultPath string, v *vault.Vault) error {
	// v1.13.0-rc12 — protected credentials: diff against the vault on
	// disk BEFORE we write. Any protected-resource mutations by a
	// non-owner get reverted + logged. This catches `dop vault edit`
	// freehand YAML changes AND any CLI gap that forgot to call
	// requireProtectionOwner upstream.
	//
	// Non-fatal: a daemon that can't read the on-disk vault (first-
	// save bootstrap) just skips the check. If any changes were
	// reverted, we print a loud feedback line but still proceed with
	// the save (the reverted state is now safe to persist).
	if existing, _ := vault.LoadPlain(vaultPath); existing != nil {
		if reverted, err := enforceProtectedOnSave(client, paths, existing, v); err == nil && len(reverted) > 0 {
			fmt.Fprintf(os.Stderr,
				"dop: reverted %d protected-resource change(s) (owned by another admin): %s\n"+
					"  See `dop watch --filter protected_bypass_attempt` for the audit trail.\n",
				len(reverted), strings.Join(reverted, ", "))
		}
	}

	// Bootstrap admin list on first save. Match by pubkey, not by
	// hostname — the old `_, ok := v.Admins["self"]` check never
	// matched because we always wrote under `hostname`. Consequence:
	// dop team remove --name $HOSTNAME on the current admin would
	// remove the entry then have it silently re-added here. Also could
	// duplicate entries if hostname changed on the same machine.
	st, err := client.Status()
	if err != nil {
		return err
	}
	if v.Admins == nil {
		v.Admins = map[string]Admin{}
	}
	if !adminPubkeyPresent(v, st.AdminPubkey) {
		hostname, _ := os.Hostname()
		if hostname == "" {
			hostname = "admin"
		}
		// Avoid overwriting a distinct admin already registered under
		// this hostname — de-duplicate against pubkey.
		key := hostname
		for i := 2; ; i++ {
			existing, ok := v.Admins[key]
			if !ok || strings.EqualFold(existing.Ed25519Pubkey, st.AdminPubkey) {
				break
			}
			key = fmt.Sprintf("%s-%d", hostname, i)
		}
		v.Admins[key] = Admin{
			AgeRecipient:  st.AgeRecipient,
			Ed25519Pubkey: st.AdminPubkey,
			AddedAt:       time.Now().UTC().Truncate(time.Second),
			Note:          "self",
		}
	}

	// v1.10.4 SAFETY GUARD — after the self-bootstrap has ensured we're
	// in the admin list, refuse to write a vault that would lock out
	// OTHER admins vs. what admins.trust currently says. This class of
	// bug caused a silent multi-day divergence in the field: load
	// returned an incomplete v.Admins, save re-encrypted for only one
	// recipient, and the other machine was permanently orphaned. If
	// load ever returns fewer entries than what's committed on disk,
	// we refuse rather than commit the damage. Deliberate removals go
	// through the `dop team remove` path which sets
	// DOP_ALLOW_ADMIN_SHRINK=1 before saving.
	if err := guardAdminShrink(paths, v); err != nil {
		return err
	}

	// v1.6.3 — sync sidecar records against the vault BEFORE writing
	// the vault. Any capability whose metadata drifted (e.g. via
	// `dop vault edit`) gets re-signed and its `.record` file
	// regenerated. Revoked / removed capabilities have their sidecars
	// deleted. Without this, `dop vault edit` could not effectively
	// revoke, because exec reads the sidecar not the vault.
	if err := syncSidecars(client, paths, v); err != nil {
		return err
	}

	b, err := vault.EmitPlain(v)
	if err != nil {
		return err
	}
	// Build the age recipient list from vault.Admins.
	recipients := []string{}
	for _, a := range v.Admins {
		recipients = append(recipients, a.AgeRecipient)
	}
	if len(recipients) == 0 {
		recipients = []string{st.AgeRecipient}
	}
	recipient := strings.Join(recipients, ",")

	// Ensure .sops.yaml matches (so anyone who edits with `sops` uses same recipients).
	if err := writeSopsConfig(paths.Vault, recipients); err != nil {
		return err
	}

	if err := client.EncryptVault(vaultPath, b, recipient); err != nil {
		return err
	}
	// Sync the trust sidecar so agent installs can verify signatures.
	if err := trust.Write(paths, v); err != nil {
		return err
	}
	// v1.9.11 — auto-push vault after every admin-plane save so the
	// M2/team members see the change without an explicit `dop push`.
	// Best-effort: log a warning but do NOT fail the operation if push
	// fails (no upstream, offline, etc.) — the local vault is already
	// updated and the user can push manually later.
	autoPushVault(paths)
	return nil
}

// autoPushGuard prevents the retry path from recursing indefinitely.
// autoPullAndMerge → saveMergedVault → saveVaultViaDaemon calls back
// into autoPushVault — we set this to true so that inner invocation
// doesn't kick off another pull-merge cycle.
var autoPushInMergeRetry bool

// autoPushVault runs `git add -A + commit + push` on the vault repo
// after a successful admin-plane save. Opt out with
// `DOP_NO_AUTO_PUSH=1`. All errors are best-effort — the local save is
// already durable and the operator can retry via `dop push` if the
// remote is unreachable.
//
// v1.10.3 — if push fails because remote moved (non-FF), we transparently
// pull-merge-push once so single-operator cross-machine workflows stay
// silent. If the merge conflicts, we surface a helpful one-liner but
// don't fail the caller — the save is already committed locally.
func autoPushVault(paths *config.Paths) {
	if os.Getenv("DOP_NO_AUTO_PUSH") == "1" {
		return
	}
	if _, err := os.Stat(filepath.Join(paths.Vault, ".git")); err != nil {
		return
	}
	_ = runGit(io.Discard, paths.Vault, "add", "-A")
	_ = runGitAllowExit(io.Discard, paths.Vault, []int{0, 1}, "commit", "-m", "dop: sync (auto)")
	if err := runGit(io.Discard, paths.Vault, "push"); err == nil {
		return
	}
	// Push failed. If we're already inside a merge-retry, don't recurse
	// — just surface the failure and let the outer caller decide.
	if autoPushInMergeRetry {
		fmt.Fprintln(os.Stderr, "  (auto-push after merge still couldn't reach the team; run `dop push` when ready)")
		return
	}
	autoPushInMergeRetry = true
	defer func() { autoPushInMergeRetry = false }()
	if err := autoPullAndMerge(paths); err != nil {
		fmt.Fprintf(os.Stderr, "  (auto-sync deferred: %v — run `dop pull` then `dop push` when ready)\n", err)
		return
	}
	if err := runGit(io.Discard, paths.Vault, "push"); err != nil {
		fmt.Fprintf(os.Stderr, "  (auto-push retry failed: %v — run `dop push` when ready)\n", err)
	}
}

// autoPullVault runs a silent smart-merge on `dop admin login` so the
// operator's next action sees the latest team state. Opt out with
// `DOP_NO_AUTO_PULL=1`. All output is best-effort and non-fatal.
func autoPullVault(paths *config.Paths) {
	if os.Getenv("DOP_NO_AUTO_PULL") == "1" {
		return
	}
	if _, err := os.Stat(filepath.Join(paths.Vault, ".git")); err != nil {
		return
	}
	if err := autoPullAndMerge(paths); err != nil {
		// Only surface if it's not a trivial "nothing to pull" case.
		if !strings.Contains(err.Error(), "up to date") {
			fmt.Fprintf(os.Stderr, "  (auto-sync note: %v)\n", err)
		}
	}
}

// autoPullAndMerge fetches origin, and if the local branch has moved
// beyond it, does a real 3-way vault merge (same code path as
// `dop pull`) — but silently, without the plain-English narrative.
// Returns nil on success or a short reason string on soft failure.
func autoPullAndMerge(paths *config.Paths) error {
	if err := runGit(io.Discard, paths.Vault, "fetch", "origin"); err != nil {
		return fmt.Errorf("fetch: %w", err)
	}
	ours, _ := gitRevListCount(paths.Vault, "origin/main..HEAD")
	theirs, _ := gitRevListCount(paths.Vault, "HEAD..origin/main")
	if ours == 0 && theirs == 0 {
		return nil // up to date
	}
	if ours == 0 {
		// Just behind — fast-forward.
		return runGit(io.Discard, paths.Vault, "merge", "--ff-only", "origin/main")
	}
	if theirs == 0 {
		return nil // ahead only; nothing to pull
	}
	// Diverged — do the real merge quietly.
	client, err := requireAdminSession(paths)
	if err != nil {
		return fmt.Errorf("admin session needed to merge encrypted vaults")
	}
	base, err := gitMergeBase(paths.Vault, "HEAD", "origin/main")
	if err != nil {
		return fmt.Errorf("no shared ancestor with team")
	}
	localV, err := decryptVaultAtRef(client, paths, "HEAD")
	if err != nil {
		return fmt.Errorf("decrypt local: %w", err)
	}
	remoteV, err := decryptVaultAtRef(client, paths, "origin/main")
	if err != nil {
		return fmt.Errorf("decrypt team: %w", err)
	}
	baseV, err := decryptVaultAtRef(client, paths, base)
	if err != nil {
		baseV = &vault.Vault{}
	}
	result := vault.Merge(baseV, localV, remoteV)
	if len(result.Conflicts) > 0 {
		return fmt.Errorf("%d conflict(s) — run `dop pull` to resolve", len(result.Conflicts))
	}
	if err := saveMergedVault(client, paths, result.Merged); err != nil {
		return fmt.Errorf("save merged: %w", err)
	}
	if err := runGit(io.Discard, paths.Vault, "merge", "-s", "ours", "origin/main",
		"--no-ff", "-m", "dop: auto-merged local + team vaults"); err != nil {
		return fmt.Errorf("finalize merge: %w", err)
	}
	return nil
}

// guardAdminShrink refuses to save v if it would remove admin entries
// vs. the current on-disk vault. This is a defensive net: every legit
// path to remove an admin (dop team remove, dop team invite finalization
// when it also drops someone, etc.) sets DOP_ALLOW_ADMIN_SHRINK=1
// beforehand. Every OTHER save path (token issue, revoke, integration
// add, grant edit, vault edit through the daemon, auto-merge writes)
// should preserve the current admin set — if v.Admins is smaller, load
// dropped entries silently and we're one write away from cryptographic
// divergence. Fail loudly, don't commit the damage.
func guardAdminShrink(paths *config.Paths, v *vault.Vault) error {
	if os.Getenv("DOP_ALLOW_ADMIN_SHRINK") == "1" {
		return nil
	}
	vaultPath := filepath.Join(paths.Vault, "vault.yaml")
	fi, err := os.Stat(vaultPath)
	if err != nil || fi.Size() == 0 {
		return nil // fresh vault, nothing to compare against
	}
	// Read the on-disk state WITHOUT going through the daemon (which
	// would be a nested request). Prefer admins.trust — it's the
	// plaintext sidecar and doesn't require decryption. It's written
	// by every successful save alongside vault.yaml.
	trustPath := filepath.Join(paths.Vault, "admins.trust")
	tb, err := os.ReadFile(trustPath)
	if err != nil {
		// No trust file yet (fresh install) — nothing to protect.
		return nil
	}
	var trust struct {
		Admins []struct {
			Ed25519Pubkey string `json:"ed25519_pubkey"`
			AgeRecipient  string `json:"age_recipient"`
			Name          string `json:"name"`
		} `json:"admins"`
	}
	if err := json.Unmarshal(tb, &trust); err != nil {
		return nil // can't parse; be permissive rather than block real saves
	}
	// Collect current-vault pubkeys for O(1) lookup.
	inNew := map[string]struct{}{}
	for _, a := range v.Admins {
		inNew[strings.ToLower(a.Ed25519Pubkey)] = struct{}{}
	}
	missing := []string{}
	for _, a := range trust.Admins {
		if _, ok := inNew[strings.ToLower(a.Ed25519Pubkey)]; !ok {
			label := a.Name
			if label == "" {
				label = a.Ed25519Pubkey[:16] + "…"
			}
			missing = append(missing, label)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf(
		"refusing to save a vault that would lock out %d admin(s): %s\n"+
			"  This save would drop them from the recipient list and cryptographically\n"+
			"  strand them from future updates. That should never happen unless you\n"+
			"  explicitly ran `dop team remove`.\n"+
			"  Likely cause: the vault was loaded incorrectly (partial parse, stale state,\n"+
			"  race). Fix: re-run the command, or `dop pull` first to refresh.\n"+
			"  If you REALLY meant to remove those admins, use `dop team remove --name <label>`\n"+
			"  (or set DOP_ALLOW_ADMIN_SHRINK=1 for the current command)",
		len(missing), strings.Join(missing, ", "))
}

// adminPubkeyPresent returns true if any admin entry in the vault
// carries the given ed25519 pubkey (case-insensitive hex).
func adminPubkeyPresent(v *vault.Vault, pubHex string) bool {
	if pubHex == "" {
		return false
	}
	for _, a := range v.Admins {
		if strings.EqualFold(a.Ed25519Pubkey, pubHex) {
			return true
		}
	}
	return false
}

// syncSidecars keeps the on-disk `.record` sidecars aligned with the
// current in-memory vault. For every ACTIVE capability whose sidecar
// is missing or differs on {generation, bundle_hash, status, binding,
// expires_at}, we re-sign and re-write the sidecar so that `dop exec`
// (which reads the sidecar) sees the same truth as the vault.
//
// For every capability whose vault status is not active, or that no
// longer has a vault entry at all, we remove the sidecar and bundle.
//
// This is what makes `dop vault edit` actually able to revoke a
// capability by flipping Status — otherwise the sidecar would stay
// stale and exec would still succeed.
func syncSidecars(client *admin.Client, paths *config.Paths, v *vault.Vault) error {
	dir := filepath.Join(paths.Vault, "capabilities")
	// Nothing to sync if the vault has no capabilities and no dir.
	if _, err := os.Stat(dir); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	// 1) Update / (re-)sign every active record whose sidecar drifted.
	// v1.12 — status=rotated records also stay alive because their
	// BearerWrapped envelope is the mechanism by which the agent
	// picks up the new bearer. They get pruned only on explicit
	// revoke or after admin confirms the rotation is complete.
	for capID, c := range v.Capabilities {
		p := filepath.Join(dir, c.LookupID+".record")
		if c.Status == capability.RecordStatusRevoked {
			// Explicitly revoked — kill the sidecar (bundle is deleted
			// by revoke path; leave it be if still present so we don't
			// double-delete mid-operation).
			_ = os.Remove(p)
			continue
		}
		// Both active and rotated flow through the resign + sidecar
		// path so the on-disk copy stays coherent.
		if sidecarMatches(p, c) {
			continue
		}
		rec := vaultCapability2Record(c, capID)
		if err := signRecordViaDaemon(client, &rec); err != nil {
			return fmt.Errorf("resign %s: %w", c.LookupID, err)
		}
		// Reflect the new signature back into the vault map so the two
		// stay coherent.
		v.Capabilities[capID] = capability2VaultCapability(rec)
		if err := writeRecordSidecar(paths, rec); err != nil {
			return fmt.Errorf("write sidecar %s: %w", c.LookupID, err)
		}
	}
	// 2) Delete orphan sidecars whose lookup_id no longer maps to any
	// vault entry. Guards against admins deleting entries via
	// `dop vault edit` — the sidecar should disappear too.
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	known := map[string]bool{}
	for _, c := range v.Capabilities {
		// v1.12: keep both active and rotated lookups alive on disk.
		// Rotated records still serve the BearerWrapped envelope until
		// their agent picks up the rotation.
		if c.Status == capability.RecordStatusActive || c.Status == capability.RecordStatusRotated {
			known[c.LookupID] = true
		}
	}
	for _, e := range entries {
		n := e.Name()
		if !strings.HasSuffix(n, ".record") && !strings.HasSuffix(n, ".bundle") {
			continue
		}
		lookup := strings.TrimSuffix(strings.TrimSuffix(n, ".record"), ".bundle")
		if !known[lookup] {
			_ = os.Remove(filepath.Join(dir, n))
		}
	}
	return nil
}

// sidecarMatches returns true if the on-disk sidecar matches every
// field a re-sign would change. Cheap comparison — avoids an
// ed25519-sign RPC round-trip per active cap on saves that touched
// only unrelated state.
//
// Coverage must include every field of `capability.Record` that a
// legitimate admin could edit via `dop vault edit`. Missing a field
// here means the sidecar silently goes out of sync with the vault
// (v1.6.3 originally missed Subject, Grants, IssuedBy, CreatedAt,
// PinExpiry, ClaimedAt — surfaced in third-pass review).
func sidecarMatches(path string, c vault.Capability) bool {
	blob, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	var existing capability.Record
	if err := json.Unmarshal(blob, &existing); err != nil {
		return false
	}
	if existing.Subject != c.Subject ||
		existing.Generation != c.Generation ||
		existing.BundleHash != c.BundleHash ||
		existing.Status != c.Status ||
		existing.IssuedBy != c.IssuedBy ||
		!existing.ExpiresAt.Equal(c.ExpiresAt) ||
		!existing.CreatedAt.Equal(c.CreatedAt) {
		return false
	}
	if !stringSlicesEqual(existing.Grants, c.Grants) {
		return false
	}
	if (existing.Binding == nil) != (c.Binding == nil) {
		return false
	}
	if existing.Binding != nil && c.Binding != nil {
		if existing.Binding.Kind != c.Binding.Kind ||
			existing.Binding.Pubkey != c.Binding.Pubkey ||
			!existing.Binding.PinExpiry.Equal(c.Binding.PinExpiry) ||
			!existing.Binding.ClaimedAt.Equal(c.Binding.ClaimedAt) {
			return false
		}
	}
	// v1.12 — wrapped envelopes participate in the "did anything
	// change?" check so a reseal flushes to the sidecar.
	if (existing.EnvWrapped == nil) != (c.EnvWrapped == nil) {
		return false
	}
	if existing.EnvWrapped != nil && c.EnvWrapped != nil {
		if existing.EnvWrapped.AdminEphemPub != c.EnvWrapped.AdminEphemPub ||
			existing.EnvWrapped.Salt != c.EnvWrapped.Salt ||
			existing.EnvWrapped.Nonce != c.EnvWrapped.Nonce ||
			existing.EnvWrapped.Ciphertext != c.EnvWrapped.Ciphertext ||
			existing.EnvWrapped.Generation != c.EnvWrapped.Generation {
			return false
		}
	}
	if (existing.BearerWrapped == nil) != (c.BearerWrapped == nil) {
		return false
	}
	if existing.BearerWrapped != nil && c.BearerWrapped != nil {
		if existing.BearerWrapped.AdminEphemPub != c.BearerWrapped.AdminEphemPub ||
			existing.BearerWrapped.Salt != c.BearerWrapped.Salt ||
			existing.BearerWrapped.Nonce != c.BearerWrapped.Nonce ||
			existing.BearerWrapped.Ciphertext != c.BearerWrapped.Ciphertext ||
			existing.BearerWrapped.NewGeneration != c.BearerWrapped.NewGeneration {
			return false
		}
	}
	return true
}

func stringSlicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// writeRecordSidecar writes a signed capability record next to its
// bundle so `dop exec` (which never opens the vault) can verify the
// admin signature.
func writeRecordSidecar(paths *config.Paths, rec capability.Record) error {
	dir := filepath.Join(paths.Vault, "capabilities")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	p := filepath.Join(dir, rec.LookupID+".record")
	blob, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	blob = append(blob, '\n')
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// writeSopsConfig writes a .sops.yaml file in the vault dir with the
// current admin recipient list.
func writeSopsConfig(vaultDir string, recipients []string) error {
	// Match any *.yaml in this dir. Newer sops (3.13+) refuses to encrypt
	// with --age explicit when .sops.yaml exists but has no matching rule
	// for the input path — and the daemon stages plaintext through
	// `.dop-encrypt-*.yaml` tempfiles that don't match `vault\.yaml$`.
	// This is dop's private vault dir; there's nothing else to encrypt
	// here, so a permissive regex is safe.
	body := fmt.Sprintf("creation_rules:\n  - path_regex: '\\.yaml$'\n    age: %s\n", strings.Join(recipients, ","))
	return os.WriteFile(filepath.Join(vaultDir, ".sops.yaml"), []byte(body), 0o644)
}

// --- Record ↔ vault.Capability conversion ---
// vault.Capability is the YAML view; capability.Record is the signing-enabled type.

func capability2VaultCapability(r capability.Record) vault.Capability {
	c := vault.Capability{
		Subject:    r.Subject,
		Grants:     r.Grants,
		CreatedAt:  r.CreatedAt,
		ExpiresAt:  r.ExpiresAt,
		Generation: r.Generation,
		LookupID:   r.LookupID,
		BundleHash: r.BundleHash,
		IssuedBy:   r.IssuedBy,
		Status:     r.Status,
		Signature:  r.Signature,
	}
	if r.Binding != nil {
		c.Binding = &vault.Binding{
			Kind:      r.Binding.Kind,
			PinExpiry: r.Binding.PinExpiry,
			Pubkey:    r.Binding.Pubkey,
			KeyType:   r.Binding.KeyType,
			ClaimedAt: r.Binding.ClaimedAt,
		}
	}
	if r.EnvWrapped != nil {
		c.EnvWrapped = &vault.WrappedEnv{
			AdminEphemPub: r.EnvWrapped.AdminEphemPub,
			Salt:          r.EnvWrapped.Salt,
			Nonce:         r.EnvWrapped.Nonce,
			Ciphertext:    r.EnvWrapped.Ciphertext,
			SealedAt:      r.EnvWrapped.SealedAt,
			Generation:    r.EnvWrapped.Generation,
		}
	}
	if r.BearerWrapped != nil {
		c.BearerWrapped = &vault.WrappedBearer{
			AdminEphemPub: r.BearerWrapped.AdminEphemPub,
			Salt:          r.BearerWrapped.Salt,
			Nonce:         r.BearerWrapped.Nonce,
			Ciphertext:    r.BearerWrapped.Ciphertext,
			SealedAt:      r.BearerWrapped.SealedAt,
			NewGeneration: r.BearerWrapped.NewGeneration,
		}
	}
	return c
}

func vaultCapability2Record(c vault.Capability, capIDHex string) capability.Record {
	r := capability.Record{
		CapabilityID: capIDHex,
		Subject:      c.Subject,
		Grants:       c.Grants,
		CreatedAt:    c.CreatedAt,
		ExpiresAt:    c.ExpiresAt,
		Generation:   c.Generation,
		LookupID:     c.LookupID,
		BundleHash:   c.BundleHash,
		IssuedBy:     c.IssuedBy,
		Status:       c.Status,
		Signature:    c.Signature,
	}
	if c.Binding != nil {
		r.Binding = &capability.RecordBinding{
			Kind:      c.Binding.Kind,
			PinExpiry: c.Binding.PinExpiry,
			Pubkey:    c.Binding.Pubkey,
			KeyType:   c.Binding.KeyType,
			ClaimedAt: c.Binding.ClaimedAt,
		}
	}
	if c.EnvWrapped != nil {
		r.EnvWrapped = &capability.WrappedEnv{
			AdminEphemPub: c.EnvWrapped.AdminEphemPub,
			Salt:          c.EnvWrapped.Salt,
			Nonce:         c.EnvWrapped.Nonce,
			Ciphertext:    c.EnvWrapped.Ciphertext,
			SealedAt:      c.EnvWrapped.SealedAt,
			Generation:    c.EnvWrapped.Generation,
		}
	}
	if c.BearerWrapped != nil {
		r.BearerWrapped = &capability.WrappedBearer{
			AdminEphemPub: c.BearerWrapped.AdminEphemPub,
			Salt:          c.BearerWrapped.Salt,
			Nonce:         c.BearerWrapped.Nonce,
			Ciphertext:    c.BearerWrapped.Ciphertext,
			SealedAt:      c.BearerWrapped.SealedAt,
			NewGeneration: c.BearerWrapped.NewGeneration,
		}
	}
	return r
}

// signRecordViaDaemon asks the daemon to ed25519-sign the record's
// canonical payload. Mutates rec.IssuedBy + rec.Signature.
func signRecordViaDaemon(client *admin.Client, rec *capability.Record) error {
	// Set IssuedBy from the session so it lands in the signed payload.
	st, err := client.Status()
	if err != nil {
		return err
	}
	rec.IssuedBy = st.AdminPubkey
	rec.Signature = ""
	payload, err := rec.SigningPayload()
	if err != nil {
		return err
	}
	sig, err := client.Sign(payload)
	if err != nil {
		return err
	}
	rec.Signature = hexEncode(sig)
	return nil
}

// hasAllTags returns true when every tag in `want` is present in `have`
// (case-insensitive). Empty `want` always matches.
func hasAllTags(have, want []string) bool {
	if len(want) == 0 {
		return true
	}
	for _, w := range want {
		if !containsFold(have, w) {
			return false
		}
	}
	return true
}

// detectPrefixCollisions returns a map of prefix → grant-IDs when two
// or more selected grants would write to the same `<PREFIX>_TOKEN`.
func detectPrefixCollisions(v *vault.Vault, grants []string) map[string][]string {
	byPrefix := map[string][]string{}
	for _, gid := range grants {
		g, ok := v.Grants[gid]
		if !ok {
			continue
		}
		p := g.EffectivePrefix()
		byPrefix[p] = append(byPrefix[p], gid)
	}
	out := map[string][]string{}
	for p, ids := range byPrefix {
		if len(ids) > 1 {
			out[p] = ids
		}
	}
	return out
}

// resolveGrantsToEnv walks the vault and materializes the env bundle
// that a bearer with these grants would receive at exec time.
//
// v1.13.0-rc13 — the bundle is now kind-aware:
//   - ${PREFIX}_KIND is always emitted so the agent can self-describe
//   - well-known metadata keys get promoted to canonical env names
//     (base_url → _BASE_URL, cli_cmd → _CMD, mcp_url → _MCP_URL, etc.)
//   - leftover metadata keys still emit under their raw-sanitized name
//     so the escape hatch (free-form metadata) keeps working
func resolveGrantsToEnv(v *vault.Vault, grants []string) map[string]string {
	out := map[string]string{}
	for _, gid := range grants {
		g, ok := v.Grants[gid]
		if !ok {
			continue
		}
		// v1.13.0-rc4 — normalize-aware integration lookup so legacy
		// grants that reference "Boiler Pensieve" still resolve against
		// the stored "boiler-pensieve" integration (and vice versa).
		integKey, ok := v.FindIntegrationKey(g.Integration)
		if !ok {
			continue
		}
		integ := v.Integrations[integKey]
		tok, ok := integ.Tokens[g.Token]
		if !ok {
			continue
		}
		// v1.8: EffectivePrefix defaults to <INTEGRATION>_<TOKEN> so grants
		// within the same integration don't collide on `<INTEGRATION>_TOKEN`.
		prefix := g.EffectivePrefix()
		out[prefix+"_TOKEN"] = tok.Value
		out[prefix+"_KIND"] = vault.IntegrationKindOf(integ)

		// Promoted metadata keys: canonical uppercase env names per kind.
		// Keys the operator ALSO put in metadata under these well-known
		// names get consumed here and not re-emitted below.
		promoted := promotedMetadataKeys()
		for rawKey, envSuffix := range promoted {
			if mv, ok := integ.Metadata[rawKey]; ok && mv != "" {
				out[prefix+"_"+envSuffix] = mv
			}
		}
		// Everything else in metadata falls through as-is (sanitized),
		// so free-form keys continue to work.
		for mk, mv := range integ.Metadata {
			if _, isPromoted := promoted[mk]; isPromoted {
				continue
			}
			out[prefix+"_"+vault.SanitizeEnvKey(mk)] = mv
		}
	}
	return out
}

// promotedMetadataKeys maps raw metadata keys (as stored on
// Integration.Metadata) to the canonical env suffix they're promoted
// to at resolve time. Centralized here so TUI/CLI prompts and the env
// renderer stay in sync.
func promotedMetadataKeys() map[string]string {
	return map[string]string{
		// api
		"base_url":      "BASE_URL",
		"endpoints_url": "ENDPOINTS_URL",
		"auth_header":   "AUTH_HEADER",
		// cli
		"cli_cmd":       "CMD",
		"cli_args_hint": "ARGS_HINT",
		// mcp
		"mcp_url": "MCP_URL",
		"mcp_cmd": "MCP_CMD",
	}
}

// v1.12 — sealEnvWrapped resolves env from record.Grants using the
// live vault, seals it to the agent's P-256 pubkey (from
// record.Binding), and returns a *capability.WrappedEnv ready to
// attach to the record. Caller re-signs the record afterwards.
//
// Errors surface loudly — this path is admin-driven and can't
// silently misfire. The one soft edge is "no P-256 pubkey on
// binding" which returns a plain error so callers can distinguish
// "nothing to reseal, agent is legacy" from "seal actually failed".
func sealEnvWrapped(v *vault.Vault, rec *capability.Record) (*capability.WrappedEnv, error) {
	if rec.Binding == nil || rec.Binding.Pubkey == "" {
		return nil, errNoAgentPubkey
	}
	kt := rec.Binding.KeyType
	if kt == "" {
		kt = vault.KeyTypeEd25519
	}
	if kt != vault.KeyTypeP256 {
		return nil, fmt.Errorf("token bound to %s key (not p256) — run `dop agent migrate <lookup>` on the agent first", kt)
	}
	pubBytes, err := hex.DecodeString(rec.Binding.Pubkey)
	if err != nil {
		return nil, fmt.Errorf("binding pubkey not hex: %w", err)
	}
	if len(pubBytes) != 65 || pubBytes[0] != 0x04 {
		return nil, fmt.Errorf("binding pubkey wrong format: want 65B uncompressed X9.62, got %dB", len(pubBytes))
	}
	env := resolveGrantsToEnv(v, rec.Grants)
	// The plaintext is JSON so that a v1.13 change to the env shape
	// (e.g. per-grant provenance) is backward compatible with v1.12
	// openers — they just JSON-decode into a plain map[string]string.
	blob, err := json.Marshal(struct {
		Env map[string]string `json:"env"`
	}{Env: env})
	if err != nil {
		return nil, fmt.Errorf("marshal env: %w", err)
	}
	// AAD binds the ciphertext to this specific record + generation so
	// a stale envelope can't be spliced onto a fresh record. Every byte
	// under aad must be reproducible by the agent at open time from the
	// (verified) record fields.
	aad := envSealAAD(rec.LookupID, rec.Generation)
	sealed, err := envseal.Seal(pubBytes, blob, aad)
	if err != nil {
		return nil, fmt.Errorf("envseal: %w", err)
	}
	m := sealed.ToHex()
	return &capability.WrappedEnv{
		AdminEphemPub: m["admin_ephem_pub"],
		Salt:          m["salt"],
		Nonce:         m["nonce"],
		Ciphertext:    m["ciphertext"],
		SealedAt:      time.Now().UTC().Truncate(time.Second),
		Generation:    rec.Generation,
	}, nil
}

// envSealAAD returns the deterministic byte string bound under the
// AEAD auth tag when sealing/opening EnvWrapped. Its contents must
// be reproducible by the agent from record fields alone.
func envSealAAD(lookupID string, generation uint64) []byte {
	return []byte(fmt.Sprintf("dop-envwrap-v1|lookup=%s|gen=%d", lookupID, generation))
}

// errNoAgentPubkey is returned by sealEnvWrapped when the record's
// binding has no pubkey yet (unclaimed PIN bearer). Not a hard
// failure — callers reseal after claim completes.
var errNoAgentPubkey = errors.New("agent pubkey not on binding yet (unclaimed PIN bearer)")

// runTokenReseal regenerates record.EnvWrapped from the current
// vault grants, using the agent's P-256 pubkey. This is what makes
// grant edits reach a bound agent without a re-claim: the admin
// mutates grants (or vault.yaml integrations), runs reseal, and the
// agent's next `dop exec` picks up the fresh env via ECDH.
//
// Only meaningful for bearers bound to a P-256 SE key. Ed25519
// bearers get a clear "migrate first" error.
func runTokenReseal(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: dop token reseal <lookup-id-prefix|subject>")
		return 2
	}
	needle := args[0]

	paths, _ := config.Resolve()
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token reseal: %v\n", err)
		return 1
	}
	v, vaultPath, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token reseal: %v\n", err)
		return 1
	}
	var (
		match   vault.Capability
		matchID string
		hits    []string
	)
	for id, c := range v.Capabilities {
		if strings.HasPrefix(id, needle) || strings.HasPrefix(c.LookupID, needle) || strings.EqualFold(c.Subject, needle) {
			hits = append(hits, id)
			match = c
			matchID = id
		}
	}
	if len(hits) == 0 {
		fmt.Fprintf(os.Stderr, "dop token reseal: no token matches %q\n", needle)
		return 1
	}
	if len(hits) > 1 {
		fmt.Fprintf(os.Stderr, "dop token reseal: %d tokens match %q — narrow with more prefix chars\n", len(hits), needle)
		return 1
	}
	rec := vaultCapability2Record(match, matchID)
	wrapped, err := sealEnvWrapped(v, &rec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token reseal: %v\n", err)
		return 1
	}
	rec.EnvWrapped = wrapped
	if err := signRecordViaDaemon(client, &rec); err != nil {
		fmt.Fprintf(os.Stderr, "dop token reseal: sign: %v\n", err)
		return 1
	}
	v.Capabilities[matchID] = capability2VaultCapability(rec)
	if err := writeRecordSidecar(paths, rec); err != nil {
		fmt.Fprintf(os.Stderr, "dop token reseal: write sidecar: %v\n", err)
		return 1
	}
	if err := saveVaultViaDaemon(client, paths, vaultPath, v); err != nil {
		fmt.Fprintf(os.Stderr, "dop token reseal: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "dop token reseal: sealed env for %s (gen %d)\n", match.Subject, rec.Generation)
	return 0
}

// runTokenAddGrant adds a grant to an existing bearer's grant set,
// bumps the generation, and re-seals the wrapped env so the agent's
// next `dop exec` sees the new env WITHOUT a re-claim.
//
// v1.12 direct-availability: only meaningful for P-256-bound bearers
// (ECDH re-encrypt requires the agent's SE pubkey). Ed25519 bearers
// return a clear "migrate first, or revoke+reissue" error.
func runTokenAddGrant(args []string) int {
	return runTokenGrantMutation(args, "add")
}

// runTokenRemoveGrant removes a grant from an existing bearer's grant
// set. Symmetric to add-grant.
func runTokenRemoveGrant(args []string) int {
	return runTokenGrantMutation(args, "remove")
}

// runTokenGrantMutation is the shared body of add-grant / remove-grant.
// mode is "add" or "remove".
func runTokenGrantMutation(args []string, mode string) int {
	// v1.13.0-rc12 — split flags from positional. Allow
	// --passphrase-stdin anywhere; the two positionals must remain
	// <lookup|subject> <grant-id>.
	fs := flag.NewFlagSet("token "+mode+"-grant", flag.ExitOnError)
	passphraseStdin := fs.Bool("passphrase-stdin", false, "read the approval passphrase from stdin (used when the grant is protected)")
	_ = fs.Parse(args)
	rest := fs.Args()
	if len(rest) != 2 {
		fmt.Fprintf(os.Stderr, "usage: dop token %s-grant [--passphrase-stdin] <lookup|subject> <grant-id>\n", mode)
		return 2
	}
	needle := rest[0]
	grantID := rest[1]

	paths, _ := config.Resolve()
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token %s-grant: %v\n", mode, err)
		return 1
	}
	v, vaultPath, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token %s-grant: %v\n", mode, err)
		return 1
	}

	// Match the target token.
	var matchID string
	var hits int
	for id, c := range v.Capabilities {
		if c.Status != capability.RecordStatusActive {
			continue
		}
		if strings.HasPrefix(id, needle) || strings.HasPrefix(c.LookupID, needle) || strings.EqualFold(c.Subject, needle) {
			hits++
			matchID = id
		}
	}
	if hits == 0 {
		fmt.Fprintf(os.Stderr, "dop token %s-grant: no active token matches %q\n", mode, needle)
		return 1
	}
	if hits > 1 {
		fmt.Fprintf(os.Stderr, "dop token %s-grant: %d active tokens match %q — narrow with more prefix chars\n", mode, hits, needle)
		return 1
	}
	match := v.Capabilities[matchID]

	// Direct-availability requires a P-256 SE key on the agent's side —
	// nothing to encrypt the fresh env to on ed25519 bearers. Error
	// clearly so operators know their options.
	if match.Binding == nil || match.Binding.Pubkey == "" {
		fmt.Fprintf(os.Stderr,
			"dop token %s-grant: this bearer is not yet claimed (no bound pubkey) — reserve grant edits until after `dop claim`\n",
			mode)
		return 1
	}
	kt := match.Binding.KeyType
	if kt == "" {
		kt = vault.KeyTypeEd25519
	}
	if kt != vault.KeyTypeP256 {
		fmt.Fprintf(os.Stderr,
			"dop token %s-grant: bearer is bound to %s key — direct grant edits require P-256\n"+
				"  Options:\n"+
				"    1) run `dop agent migrate %s` on the agent's machine (upgrades to P-256, keeps bearer)\n"+
				"    2) revoke this bearer and issue a fresh one with the wider/narrower grant set\n",
			mode, kt, match.LookupID)
		return 1
	}

	// Validate the grant argument.
	var targetGrant vault.Grant
	if mode == "add" {
		g, ok := v.Grants[grantID]
		if !ok {
			fmt.Fprintf(os.Stderr, "dop token add-grant: no grant %q in vault (see `dop grant list`)\n", grantID)
			return 1
		}
		targetGrant = g
		for _, g := range match.Grants {
			if g == grantID {
				fmt.Fprintf(os.Stderr, "dop token add-grant: bearer already has grant %q\n", grantID)
				return 1
			}
		}
	} else { // remove
		found := false
		for _, g := range match.Grants {
			if g == grantID {
				found = true
				break
			}
		}
		if !found {
			fmt.Fprintf(os.Stderr, "dop token remove-grant: bearer doesn't have grant %q\n", grantID)
			return 1
		}
		targetGrant = v.Grants[grantID]
	}

	// v1.13.0-rc12 — protected grant → owner + passphrase gate.
	// Applies to both add (giving the bearer access) and remove
	// (changing who sees what, which should still be an audited move).
	if targetGrant.Protected {
		if err := requireProtectionOwner(client, "grant "+grantID, targetGrant.Protected, targetGrant.Owner); err != nil {
			fmt.Fprintf(os.Stderr, "dop token %s-grant: %v\n", mode, err)
			return 1
		}
		if err := promptProtectionPassphrase(paths, fmt.Sprintf("approval passphrase (%s protected grant %s): ", mode, grantID), *passphraseStdin); err != nil {
			fmt.Fprintf(os.Stderr, "dop token %s-grant: %v\n", mode, err)
			return 1
		}
	}

	// Apply the mutation.
	newGrants := make([]string, 0, len(match.Grants)+1)
	if mode == "add" {
		newGrants = append(newGrants, match.Grants...)
		newGrants = append(newGrants, grantID)
	} else {
		for _, g := range match.Grants {
			if g == grantID {
				continue
			}
			newGrants = append(newGrants, g)
		}
	}
	match.Grants = newGrants
	// Bumping generation ensures a) cached agents notice the change via
	// the min-generation floor, b) the AEAD AAD on the resealed env
	// differs from prior seals (defense against replay of a partial mid-
	// mutation state).
	match.Generation = v.BumpGeneration(match.Subject)

	// Reseal EnvWrapped to reflect the new grants (env resolved fresh
	// from the current vault → bearer's env changes take effect on the
	// agent's next dop exec, no re-claim required).
	rec := vaultCapability2Record(match, matchID)
	wrapped, err := sealEnvWrapped(v, &rec)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token %s-grant: reseal: %v\n", mode, err)
		return 1
	}
	rec.EnvWrapped = wrapped

	if err := signRecordViaDaemon(client, &rec); err != nil {
		fmt.Fprintf(os.Stderr, "dop token %s-grant: sign: %v\n", mode, err)
		return 1
	}
	v.Capabilities[matchID] = capability2VaultCapability(rec)
	if err := writeRecordSidecar(paths, rec); err != nil {
		fmt.Fprintf(os.Stderr, "dop token %s-grant: write sidecar: %v\n", mode, err)
		return 1
	}
	if err := saveVaultViaDaemon(client, paths, vaultPath, v); err != nil {
		fmt.Fprintf(os.Stderr, "dop token %s-grant: %v\n", mode, err)
		return 1
	}

	verb := "added"
	prep := "to"
	if mode == "remove" {
		verb = "removed"
		prep = "from"
	}
	fmt.Fprintf(os.Stderr,
		"dop token %s-grant: %s %s %s %s (gen bumped to %d, env resealed — agent's next `dop exec` picks it up)\n",
		mode, verb, grantID, prep, match.Subject, rec.Generation)
	return 0
}

// runTokenRotate rotates the bearer for an existing P-256-bound
// capability, in place. It writes a fresh bundle + record at a NEW
// lookup id (derived from the new bearer), then marks the OLD record
// `status = rotated` and attaches a BearerWrapped envelope that
// tells the agent (via ECDH to their SE pubkey) both the new bearer
// and the new lookup id. The agent's next `dop exec` decrypts,
// re-tags its SE key, and switches to the new bearer transparently.
//
// The agent's P-256 pubkey is preserved across rotation — same
// physical key, same admin trust chain, just a new bearer + new
// file location. Ed25519 bearers cannot rotate (no ECDH) — clear
// error tells the operator to `dop agent migrate` first.
func runTokenRotate(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: dop token rotate <lookup|subject>")
		return 2
	}
	needle := args[0]

	paths, _ := config.Resolve()
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token rotate: %v\n", err)
		return 1
	}
	v, vaultPath, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token rotate: %v\n", err)
		return 1
	}

	// Match the target token.
	var oldCapID string
	var hits int
	for id, c := range v.Capabilities {
		if c.Status != capability.RecordStatusActive {
			continue
		}
		if strings.HasPrefix(id, needle) || strings.HasPrefix(c.LookupID, needle) || strings.EqualFold(c.Subject, needle) {
			hits++
			oldCapID = id
		}
	}
	if hits == 0 {
		fmt.Fprintf(os.Stderr, "dop token rotate: no active token matches %q\n", needle)
		return 1
	}
	if hits > 1 {
		fmt.Fprintf(os.Stderr, "dop token rotate: %d active tokens match %q — narrow with more prefix chars\n", hits, needle)
		return 1
	}
	old := v.Capabilities[oldCapID]

	if old.Binding == nil || old.Binding.Pubkey == "" {
		fmt.Fprintln(os.Stderr, "dop token rotate: bearer is not yet claimed — rotate only makes sense post-claim")
		return 1
	}
	kt := old.Binding.KeyType
	if kt == "" {
		kt = vault.KeyTypeEd25519
	}
	if kt != vault.KeyTypeP256 {
		fmt.Fprintf(os.Stderr,
			"dop token rotate: bearer bound to %s — rotation requires P-256 (needs ECDH to wrap the new bearer).\n"+
				"  Options:\n"+
				"    1) run `dop agent migrate %s` on the agent (upgrades to P-256)\n"+
				"    2) revoke + issue a new bearer manually (loses transparent rotation)\n",
			kt, old.LookupID)
		return 1
	}

	agentPub, err := hex.DecodeString(old.Binding.Pubkey)
	if err != nil || len(agentPub) != 65 || agentPub[0] != 0x04 {
		fmt.Fprintf(os.Stderr, "dop token rotate: bad binding pubkey (want 65B X9.62): %v\n", err)
		return 1
	}

	// Generate the new bearer and derive its lookup id.
	newBearer, err := capability.NewBearer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token rotate: new bearer: %v\n", err)
		return 1
	}
	vaultCtx, _ := hex.DecodeString(v.VaultContext)
	newLookupID := capability.LookupID(vaultCtx, newBearer)
	if newLookupID == old.LookupID {
		fmt.Fprintln(os.Stderr, "dop token rotate: new lookup id collided with old (128-bit unlucky) — retry")
		return 1
	}

	// Fresh generation for the new record.
	newGen := v.BumpGeneration(old.Subject)

	// Write the new bundle at the new lookup id (encrypted with the
	// new bearer). The envelope's env can be minimal — the record's
	// EnvWrapped is authoritative for v1.12+ P-256 bearers — but we
	// populate it with the current resolved env for backward-compat
	// with any future v1.11 verifier that might read it.
	envBundle := resolveGrantsToEnv(v, old.Grants)
	newCapIDRaw, err := capability.NewCapabilityID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token rotate: new capID: %v\n", err)
		return 1
	}
	newCapIDHex := hex.EncodeToString(newCapIDRaw[:])
	newBundlePath := filepath.Join(paths.Vault, "capabilities", newLookupID+".bundle")
	if err := os.MkdirAll(filepath.Dir(newBundlePath), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "dop token rotate: mkdir: %v\n", err)
		return 1
	}
	f, err := os.Create(newBundlePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token rotate: create bundle: %v\n", err)
		return 1
	}
	newBundleBytes, err := capability.Write(f, capability.WriteOpts{
		CapabilityID: newCapIDRaw,
		Bearer:       newBearer,
		Generation:   newGen,
		ExpiresAt:    old.ExpiresAt,
		Subject:      old.Subject,
		Env:          envBundle,
		Binding: &capability.EnvelopeBinding{
			Kind:    vault.BindingKindPubkey,
			Pubkey:  old.Binding.Pubkey,
			KeyType: vault.KeyTypeP256,
		},
	})
	f.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token rotate: write bundle: %v\n", err)
		return 1
	}
	newBundleHash := capability.HashBundle(newBundleBytes)

	// Build the new record (already-bound, no PIN — inherits pubkey).
	newRec := capability.Record{
		CapabilityID: newCapIDHex,
		Subject:      old.Subject,
		Grants:       append([]string(nil), old.Grants...),
		CreatedAt:    time.Now().UTC().Truncate(time.Second),
		ExpiresAt:    old.ExpiresAt,
		Generation:   newGen,
		LookupID:     newLookupID,
		BundleHash:   newBundleHash,
		Status:       capability.RecordStatusActive,
		Binding: &capability.RecordBinding{
			Kind:      vault.BindingKindPubkey,
			Pubkey:    old.Binding.Pubkey,
			KeyType:   vault.KeyTypeP256,
			ClaimedAt: time.Now().UTC().Truncate(time.Second),
		},
	}
	// Fresh EnvWrapped for the new record.
	wrapped, err := sealEnvWrapped(v, &newRec)
	if err != nil {
		_ = os.Remove(newBundlePath)
		fmt.Fprintf(os.Stderr, "dop token rotate: seal new record env: %v\n", err)
		return 1
	}
	newRec.EnvWrapped = wrapped
	if err := signRecordViaDaemon(client, &newRec); err != nil {
		_ = os.Remove(newBundlePath)
		fmt.Fprintf(os.Stderr, "dop token rotate: sign new record: %v\n", err)
		return 1
	}

	// Wrap the new bearer + new lookup id for the agent.
	payload, err := json.Marshal(struct {
		Bearer   string `json:"bearer"`
		LookupID string `json:"lookup_id"`
	}{Bearer: newBearer, LookupID: newLookupID})
	if err != nil {
		_ = os.Remove(newBundlePath)
		fmt.Fprintf(os.Stderr, "dop token rotate: marshal payload: %v\n", err)
		return 1
	}
	// AAD binds the wrapped payload to the OLD record's identity
	// (lookup + new_generation). Prevents splicing across rotations.
	aad := []byte(fmt.Sprintf("dop-bearerwrap-v1|old_lookup=%s|new_gen=%d", old.LookupID, newGen))
	sealed, err := envseal.Seal(agentPub, payload, aad)
	if err != nil {
		_ = os.Remove(newBundlePath)
		fmt.Fprintf(os.Stderr, "dop token rotate: seal bearer payload: %v\n", err)
		return 1
	}
	m := sealed.ToHex()

	// Mutate the OLD record: status=rotated + attach BearerWrapped.
	// Note: we bump the OLD record's generation too so a stale copy
	// can't be confused with the mutation.
	oldRec := vaultCapability2Record(old, oldCapID)
	oldRec.Status = capability.RecordStatusRotated
	oldRec.Generation = newGen
	oldRec.BearerWrapped = &capability.WrappedBearer{
		AdminEphemPub: m["admin_ephem_pub"],
		Salt:          m["salt"],
		Nonce:         m["nonce"],
		Ciphertext:    m["ciphertext"],
		SealedAt:      time.Now().UTC().Truncate(time.Second),
		NewGeneration: newGen,
	}
	if err := signRecordViaDaemon(client, &oldRec); err != nil {
		_ = os.Remove(newBundlePath)
		fmt.Fprintf(os.Stderr, "dop token rotate: sign old record: %v\n", err)
		return 1
	}

	// Both records back into vault.Capabilities.
	if v.Capabilities == nil {
		v.Capabilities = map[string]vault.Capability{}
	}
	v.Capabilities[oldCapID] = capability2VaultCapability(oldRec)
	v.Capabilities[newCapIDHex] = capability2VaultCapability(newRec)

	if err := saveVaultViaDaemon(client, paths, vaultPath, v); err != nil {
		_ = os.Remove(newBundlePath)
		fmt.Fprintf(os.Stderr, "dop token rotate: save vault: %v (rolled back new bundle)\n", err)
		return 1
	}
	// Sidecar writes — old changes shape, new is fresh.
	if err := writeRecordSidecar(paths, oldRec); err != nil {
		fmt.Fprintf(os.Stderr, "dop token rotate: write old sidecar: %v\n", err)
		return 1
	}
	if err := writeRecordSidecar(paths, newRec); err != nil {
		fmt.Fprintf(os.Stderr, "dop token rotate: write new sidecar: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stderr,
		"dop token rotate: rotated %s\n"+
			"  old lookup: %s (status=rotated; BearerWrapped attached)\n"+
			"  new lookup: %s (status=active; gen %d)\n"+
			"  → agent's next `dop exec` decrypts BearerWrapped, migrates SE key, switches\n",
		old.Subject, old.LookupID[:12], newLookupID[:12], newGen)
	return 0
}

// splitFlagsAndPositionals separates a raw argv slice so that flags can
// appear anywhere on the command line, not only before positionals (Go's
// stdlib flag parser stops at the first non-flag arg).
//
// Handles all forms the stdlib parser accepts:
//   -flag, --flag                (bool or absent-value)
//   -flag=v, --flag=v            (attached value)
//   -flag v, --flag v            (space-separated, for non-bool flags)
//
// It needs the FlagSet to tell bool flags apart from value flags — bool
// flags don't consume the next arg. Unknown flags are passed through
// as-is; flag.Parse will surface the error.
//
// `--` ends flag parsing (matches stdlib behaviour): everything after it
// is treated as positional. This lets callers like `dop exec` pass a
// child command whose args happen to start with `-`.
func splitFlagsAndPositionals(fs *flag.FlagSet, args []string) (flagArgs, posArgs []string) {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			posArgs = append(posArgs, args[i+1:]...)
			return
		}
		if !strings.HasPrefix(a, "-") || a == "-" {
			posArgs = append(posArgs, a)
			continue
		}
		flagArgs = append(flagArgs, a)
		if strings.Contains(a, "=") {
			continue
		}
		name := strings.TrimLeft(a, "-")
		f := fs.Lookup(name)
		if f == nil {
			continue
		}
		if bf, ok := f.Value.(interface{ IsBoolFlag() bool }); ok && bf.IsBoolFlag() {
			continue
		}
		if i+1 < len(args) {
			flagArgs = append(flagArgs, args[i+1])
			i++
		}
	}
	return
}

// tokenNeverSentinel returns the "never expires" timestamp used by
// --expires=never. Year 9999 is picked so it round-trips through Unix
// seconds without overflow and stays clearly distinguishable from any
// real expiry.
func tokenNeverSentinel() time.Time {
	return time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
}

// tokenExpiryDisplay renders an ExpiresAt for humans/logs. Returns
// "never" for tokens issued with --expires=never (year 9999), and
// RFC3339 otherwise.
func tokenExpiryDisplay(t time.Time) string {
	if t.Year() >= 9999 {
		return "never"
	}
	return t.Format(time.RFC3339)
}

// parseDurationLoose extends time.ParseDuration to accept "d" for days
// and "w" for weeks. Anything time.ParseDuration handles natively still
// works.
func parseDurationLoose(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if strings.HasSuffix(s, "d") {
		var n float64
		if _, err := fmt.Sscanf(s[:len(s)-1], "%f", &n); err != nil {
			return 0, err
		}
		return time.Duration(n * float64(24*time.Hour)), nil
	}
	if strings.HasSuffix(s, "w") {
		var n float64
		if _, err := fmt.Sscanf(s[:len(s)-1], "%f", &n); err != nil {
			return 0, err
		}
		return time.Duration(n * float64(7*24*time.Hour)), nil
	}
	return time.ParseDuration(s)
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Admin is a local alias to keep tokencmd.go's import list small.
type Admin = vault.Admin

// io.Discard used elsewhere.
var _ io.Writer = io.Discard
