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
	"github.com/fray/dop/internal/trust"
	"github.com/fray/dop/internal/vault"
)

func runToken(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: dop token <issue|list|revoke|repin> ...")
		return 2
	}
	switch args[0] {
	case "issue":
		return runTokenIssue(args[1:])
	case "list":
		return runTokenList(args[1:])
	case "revoke":
		return runTokenRevoke(args[1:])
	case "repin":
		return runTokenRepin(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "dop token: unknown subcommand %q\n", args[0])
		return 2
	}
}

func runTokenIssue(args []string) int {
	fs := flag.NewFlagSet("token issue", flag.ExitOnError)
	grantsCSV := fs.String("grants", "", "comma-separated grant IDs (required)")
	name := fs.String("name", "", "human-readable subject/label")
	expires := fs.String("expires", "72h", "duration until expiry (default 72h)")
	note := fs.String("note", "", "free-text note (not used in v1.0)")
	bindPubkey := fs.String("bind-pubkey", "", "pre-bind the bearer to this ed25519 pubkey (hex)")
	noBind := fs.Bool("no-bind", false, "issue an unbound bearer (bearer alone grants access)")
	pinTTL := fs.String("pin-ttl", "5m", "PIN validity window when --bind is default")
	_ = fs.Parse(args)
	_ = note

	if strings.TrimSpace(*grantsCSV) == "" {
		fmt.Fprintln(os.Stderr, "dop token issue: --grants is required")
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
	expDur, err := parseDurationLoose(*expires)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token issue: --expires: %v\n", err)
		return 2
	}
	if expDur <= 0 {
		fmt.Fprintln(os.Stderr, "dop token issue: --expires must be positive")
		return 2
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

	// Validate grants exist.
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
	expiresAt := time.Now().Add(expDur).UTC().Truncate(time.Second)
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
			"expires_at": expiresAt.Format(time.RFC3339),
		},
	})
	fmt.Fprintf(os.Stderr, "dop token issue: issued %s (grants: %v, expires: %s)\n", subject, grants, expiresAt.Format(time.RFC3339))
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
	for _, id := range names {
		c := v.Capabilities[id]
		fmt.Printf("- %s  subject=%s  grants=%v  gen=%d  status=%s  expires=%s\n",
			id[:12], c.Subject, c.Grants, c.Generation, c.Status,
			c.ExpiresAt.Format(time.RFC3339))
	}
	return 0
}

func runTokenRevoke(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: dop token revoke <name>")
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

	// Match by subject; fail if ambiguous.
	matched := ""
	for id, c := range v.Capabilities {
		if c.Subject == query && c.Status == capability.RecordStatusActive {
			if matched != "" {
				fmt.Fprintf(os.Stderr, "dop token revoke: subject %q matches multiple active capabilities; be more specific\n", query)
				return 1
			}
			matched = id
		}
	}
	if matched == "" {
		fmt.Fprintf(os.Stderr, "dop token revoke: no active capability with subject %q\n", query)
		return 1
	}
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
	pinTTL := fs.String("pin-ttl", "5m", "PIN validity window")
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
	return trust.Write(paths, v)
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
	for capID, c := range v.Capabilities {
		p := filepath.Join(dir, c.LookupID+".record")
		if c.Status != capability.RecordStatusActive {
			// Non-active — kill the sidecar (bundle is deleted by revoke
			// path; leave it be if still present so we don't double-delete
			// mid-operation).
			_ = os.Remove(p)
			continue
		}
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
		if c.Status == capability.RecordStatusActive {
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
	body := fmt.Sprintf("creation_rules:\n  - path_regex: 'vault\\.yaml$'\n    age: %s\n", strings.Join(recipients, ","))
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
			ClaimedAt: r.Binding.ClaimedAt,
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
			ClaimedAt: c.Binding.ClaimedAt,
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

// resolveGrantsToEnv walks the vault and materializes the env bundle
// that a bearer with these grants would receive at exec time.
func resolveGrantsToEnv(v *vault.Vault, grants []string) map[string]string {
	out := map[string]string{}
	for _, gid := range grants {
		g, ok := v.Grants[gid]
		if !ok {
			continue
		}
		integ, ok := v.Integrations[g.Integration]
		if !ok {
			continue
		}
		tok, ok := integ.Tokens[g.Token]
		if !ok {
			continue
		}
		prefix := g.EnvPrefix
		if prefix == "" {
			prefix = strings.ToUpper(g.Integration)
		}
		out[prefix+"_TOKEN"] = tok.Value
		for mk, mv := range integ.Metadata {
			out[prefix+"_"+strings.ToUpper(mk)] = mv
		}
	}
	return out
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
