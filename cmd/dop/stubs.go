// Stubs / minimal implementations for team + doctor + exec. Phase 4
// fleshes out `exec`; Phase 5 adds --security to doctor.

package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/admininvite"
	"github.com/fray/dop/internal/approval"
	"github.com/fray/dop/internal/audit"
	"github.com/fray/dop/internal/capability"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/pendingclaim"
	"github.com/fray/dop/internal/trust"
	"github.com/fray/dop/internal/tunnel"
	"github.com/fray/dop/internal/vault"
)

// --- dop team ---

func runTeam(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: dop team <add-key|remove|list|invite>")
		return 2
	}
	switch args[0] {
	case "add-key":
		return runTeamAddKey(args[1:])
	case "remove":
		return runTeamRemove(args[1:])
	case "list":
		return runTeamList(args[1:])
	case "invite":
		return runTeamInvite(args[1:])
	case "cancel-invite":
		// rc7m — delete a pending admin invite (invite file + identity
		// blob for shared-identity, and the response file if present).
		// Pushes a cleanup commit. The hint has been in the invite-
		// timeout output since v1.9 but the command was never actually
		// wired up until rc7m.
		return runTeamCancelInvite(args[1:])
	case "approve-invite":
		// rc7o — complete a pending invite after the teammate has
		// responded. Replaces the inline polling loop in pre-rc7o
		// runTeamInvite. `dop team invite` now exits immediately after
		// staging; this is the fire-and-forget completion step.
		return runTeamApproveInvite(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "dop team: unknown subcommand %q\n", args[0])
		return 2
	}
}

// runTeamCancelInvite deletes the pending invite files for the given
// invite id and pushes the cleanup commit.
func runTeamCancelInvite(args []string) int {
	fs := flag.NewFlagSet("team cancel-invite", flag.ExitOnError)
	_ = fs.Parse(args)
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "usage: dop team cancel-invite <invite-id>")
		fmt.Fprintln(os.Stderr, "  invite id is the hex prefix shown in `dop team list` pending output,")
		fmt.Fprintln(os.Stderr, "  or the full id from a prior `dop team invite` run.")
		return 2
	}
	id := rest[0]

	paths, err := config.Resolve()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop team cancel-invite: %v\n", err)
		return 1
	}
	// Resolve an id prefix (12 hex chars is enough) to the full id so
	// operators don't need to type the whole thing.
	full, err := resolveInviteID(paths, id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop team cancel-invite: %v\n", err)
		return 1
	}
	// Also wipe the identity blob when it exists (shared-identity invites).
	blob := admininvite.IdentityBlobPath(paths, full)
	if _, err := os.Stat(blob); err == nil {
		_ = os.Remove(blob)
	}
	if err := admininvite.Delete(paths, full); err != nil {
		fmt.Fprintf(os.Stderr, "dop team cancel-invite: delete: %v\n", err)
		return 1
	}
	if err := gitAddCommitPush(paths.Vault, "pending-admin-invites",
		fmt.Sprintf("dop: cancel admin invite %s", full[:8])); err != nil {
		fmt.Fprintf(os.Stderr, "dop team cancel-invite: push: %v — run `dop push` manually\n", err)
		return 1
	}
	audit.Append(paths, audit.Event{Kind: audit.EventInviteCancel, Extra: map[string]string{"invite_id": full}})
	fmt.Fprintf(os.Stderr, "dop team cancel-invite: deleted invite %s\n", full[:8])
	return 0
}

// resolveInviteID accepts a short prefix (>= 8 hex) and returns the
// full invite id. Errors on no match / multi-match.
func resolveInviteID(paths *config.Paths, prefix string) (string, error) {
	prefix = strings.TrimSpace(prefix)
	if len(prefix) < 8 {
		return "", fmt.Errorf("invite id must be at least 8 hex characters")
	}
	all, err := admininvite.ListInvites(paths)
	if err != nil {
		return "", err
	}
	var hits []string
	for _, inv := range all {
		if strings.HasPrefix(inv.InviteID, prefix) {
			hits = append(hits, inv.InviteID)
		}
	}
	switch len(hits) {
	case 0:
		return "", fmt.Errorf("no matching pending invite for %q", prefix)
	case 1:
		return hits[0], nil
	default:
		return "", fmt.Errorf("%d pending invites match %q — use more characters", len(hits), prefix)
	}
}

// runTeamRemove drops a member from the admins list and prints the
// upstream-token rotation checklist so the operator knows what to
// rotate at the source services.
func runTeamRemove(args []string) int {
	fs := flag.NewFlagSet("team remove", flag.ExitOnError)
	name := fs.String("name", "", "admin name to remove (required)")
	force := fs.Bool("force", false, "actually remove (default is dry-run)")
	_ = fs.Parse(args)

	if *name == "" {
		fmt.Fprintln(os.Stderr, "dop team remove: --name required")
		return 2
	}
	paths, _ := config.Resolve()
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop team remove: %v\n", err)
		return 1
	}
	v, vp, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop team remove: %v\n", err)
		return 1
	}
	victimEntry, ok := v.Admins[*name]
	if !ok {
		fmt.Fprintf(os.Stderr, "dop team remove: no admin named %q\n", *name)
		return 1
	}
	// v1.6.3 — safety checks. Neither of these can be defeated by
	// `--force`: they'd brick the vault outright.
	if len(v.Admins) <= 1 {
		fmt.Fprintln(os.Stderr, "dop team remove: refusing — this is the only admin. Vault would become unrecoverable.")
		return 1
	}
	st, serr := client.Status()
	if serr != nil {
		fmt.Fprintf(os.Stderr, "dop team remove: refusing — cannot verify current admin identity (session status: %v)\n", serr)
		return 1
	}
	if strings.EqualFold(victimEntry.Ed25519Pubkey, st.AdminPubkey) {
		fmt.Fprintln(os.Stderr, "dop team remove: refusing to remove yourself.")
		fmt.Fprintln(os.Stderr, "  Ask another admin to run `dop team remove --name <you> --force` from their machine.")
		return 1
	}

	// Always print the checklist — this is the whole point.
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "⚠  Removing admin %q. Rotate the following upstream tokens NOW:\n\n", *name)
	fmt.Fprintln(os.Stderr, "   Any cached copy of the vault they cloned before removal is still")
	fmt.Fprintln(os.Stderr, "   decryptable with their old age key. Every token below must be")
	fmt.Fprintln(os.Stderr, "   rotated at the upstream service AND updated via `dop integration add`.")
	fmt.Fprintln(os.Stderr)
	for iname, integ := range v.Integrations {
		for tname, tok := range integ.Tokens {
			fmt.Fprintf(os.Stderr, "   - %s.tokens.%s  (%s)\n", iname, tname, tok.ScopeNote)
		}
	}
	fmt.Fprintln(os.Stderr)
	if !*force {
		fmt.Fprintln(os.Stderr, "dop team remove: dry run. Re-run with --force AFTER you have rotated the upstream tokens.")
		return 0
	}

	// Force-remove. v1.6.4: also revoke every capability signed by the
	// removed admin's ed25519 pubkey and delete their bundle/record
	// sidecars. Without this, records signed by the removed admin
	// remain trusted (via admins.trust) until the admin explicitly
	// revokes them, which is the opposite of what removal should mean.
	victimPub := strings.ToLower(victimEntry.Ed25519Pubkey)
	revoked := 0
	if victimPub != "" {
		for capID, c := range v.Capabilities {
			if !strings.EqualFold(c.IssuedBy, victimPub) {
				continue
			}
			if c.Status != capability.RecordStatusActive {
				continue
			}
			c.Status = capability.RecordStatusRevoked
			c.Generation = v.BumpGeneration(c.Subject)
			v.Capabilities[capID] = c
			// Delete on-disk artifacts.
			bp := filepath.Join(paths.Vault, "capabilities", c.LookupID+".bundle")
			_ = os.Remove(bp)
			rp := filepath.Join(paths.Vault, "capabilities", c.LookupID+".record")
			_ = os.Remove(rp)
			audit.Append(paths, audit.Event{
				Kind:     audit.EventRevoke,
				Subject:  c.Subject,
				LookupID: c.LookupID,
				Extra:    map[string]string{"reason": "admin_removed", "admin": *name},
			})
			revoked++
		}
	}
	delete(v.Admins, *name)
	// v1.10.4 — signal saveVaultViaDaemon that this SHRINK is intentional.
	// The guard checks this env var and skips the "would lock out N admins"
	// refusal, letting the legitimate remove path through.
	os.Setenv("DOP_ALLOW_ADMIN_SHRINK", "1")
	defer os.Unsetenv("DOP_ALLOW_ADMIN_SHRINK")
	if err := saveVaultViaDaemon(client, paths, vp, v); err != nil {
		fmt.Fprintf(os.Stderr, "dop team remove: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "dop team remove: %s removed; revoked %d capability(ies) they had issued\n", *name, revoked)
	return 0
}

func runTeamAddKey(args []string) int {
	fs := flag.NewFlagSet("team add-key", flag.ExitOnError)
	name := fs.String("name", "", "human-readable admin label")
	pubkey := fs.String("pubkey", "", "age recipient (age1...)")
	ed25519pk := fs.String("ed25519", "", "admin ed25519 pubkey (optional; for signature verification)")
	note := fs.String("note", "", "note")
	_ = fs.Parse(args)

	if *name == "" || *pubkey == "" {
		fmt.Fprintln(os.Stderr, "dop team add-key: --name and --pubkey required")
		return 2
	}
	if !strings.HasPrefix(*pubkey, "age1") {
		fmt.Fprintln(os.Stderr, "dop team add-key: --pubkey must start with age1")
		return 2
	}
	paths, _ := config.Resolve()
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop team add-key: %v\n", err)
		return 1
	}
	v, vp, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop team add-key: %v\n", err)
		return 1
	}
	if v.Admins == nil {
		v.Admins = map[string]vault.Admin{}
	}
	v.Admins[*name] = vault.Admin{
		AgeRecipient:  *pubkey,
		Ed25519Pubkey: *ed25519pk,
		AddedAt:       time.Now().UTC().Truncate(time.Second),
		Note:          *note,
	}
	if err := saveVaultViaDaemon(client, paths, vp, v); err != nil {
		fmt.Fprintf(os.Stderr, "dop team add-key: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "dop team add-key: %s added as admin\n", *name)
	return 0
}

func runTeamList(args []string) int {
	paths, _ := config.Resolve()
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop team list: %v\n", err)
		return 1
	}
	v, _, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop team list: %v\n", err)
		return 1
	}
	if len(v.Admins) == 0 {
		fmt.Println("(no admins)")
		return 0
	}
	names := make([]string, 0, len(v.Admins))
	for n := range v.Admins {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		a := v.Admins[n]
		note := a.Note
		if note == "" {
			note = "-"
		}
		fmt.Printf("- %s  age=%s  ed25519=%s  note=%s\n", n, a.AgeRecipient, a.Ed25519Pubkey, note)
	}
	return 0
}

// --- dop doctor + --security ---

func runDoctor(args []string) int {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	securityMode := fs.Bool("security", false, "include security-focused warnings")
	_ = fs.Parse(args)

	paths, _ := config.Resolve()
	fmt.Println("dop doctor:")

	anyFail := false
	line := func(status, name, detail string) {
		fmt.Printf("  %s %s — %s\n", status, name, detail)
		if status == "✗" {
			anyFail = true
		}
	}

	// --- basic ---
	if _, err := exec.LookPath("sops"); err != nil {
		line("✗", "binary:sops", "not on $PATH — brew install sops")
	} else {
		line("✓", "binary:sops", "on $PATH")
	}
	if _, err := exec.LookPath("git"); err != nil {
		line("✗", "binary:git", "not on $PATH")
	} else {
		line("✓", "binary:git", "on $PATH")
	}
	adminOK := admin.KeyFileExists(paths)
	if adminOK {
		line("✓", "install:type", "admin (has keys/admin.age.enc)")
	} else {
		line("!", "install:type", "agent (no admin key — mutations refused)")
	}
	vpath := vaultFilePath(paths)
	if _, err := os.Stat(vpath); err == nil {
		line("✓", "vault:attached", vpath)
	} else {
		line("!", "vault:attached", "no vault at "+vpath)
	}
	c := admin.NewClient(admin.SockPath(paths))
	if c.SessionActive() {
		st, _ := c.Status()
		if st != nil {
			line("✓", "admin:session", fmt.Sprintf("unlocked (idle_ttl_left=%s, abs_ttl_left=%s)",
				remainingTTL(st.IdleTTLSeconds, st.LastActivityUnix),
				remainingTTL(st.AbsTTLSeconds, st.StartedAtUnix)))
		} else {
			line("!", "admin:session", "unlocked but status unreachable")
		}
	} else {
		line("⋯", "admin:session", "locked")
	}

	// --- v1.7 doctor: additional runtime + on-disk health checks ---
	// (always-on; the --security section below adds paranoia-mode)
	if _, err := exec.LookPath("cloudflared"); err != nil {
		line("!", "binary:cloudflared", "not on $PATH — web approval falls back to LAN")
	} else {
		line("✓", "binary:cloudflared", "on $PATH")
	}
	if approval.Configured(paths) {
		line("✓", "admin:approval-passphrase", "configured")
	} else if adminOK {
		line("✗", "admin:approval-passphrase", "not set — run `dop admin set-approval`")
	}
	trustPath := trust.Path(paths)
	if trusted, err := trust.Load(paths); err == nil && len(trusted) > 0 {
		line("✓", "vault:trust", fmt.Sprintf("%s (%d admin(s) trusted)", trustPath, len(trusted)))
		if c.SessionActive() {
			if st, _ := c.Status(); st != nil {
				if !trusted[strings.ToLower(st.AdminPubkey)] && !trusted[st.AdminPubkey] {
					line("!", "vault:trust-self", "current admin's pubkey is NOT in admins.trust — agents will reject your records")
				}
			}
		}
	} else if adminOK {
		line("!", "vault:trust", "no admins.trust yet — issue at least one token to seed it")
	}
	dopCheckSidecarConsistency(paths, line)
	dopCheckAuditLog(paths, line)
	dopCheckGenCache(paths, line)
	dopCheckPendingClaims(paths, line)
	dopCheckGrantPrefixCollisions(c, paths, line)
	dopCheckPendingInvites(paths, line)

	// v1.11 — agent-key backend summary + codesign posture.
	dopCheckAgentKeys(paths, line)
	dopCheckCodesign(line)

	// --- security ---
	if *securityMode {
		fmt.Println("\n  --- security ---")

		// Warn if admin session TTL env is unusually long.
		if v := os.Getenv("DOP_ADMIN_MAX_TTL"); v != "" {
			if d, err := time.ParseDuration(v); err == nil && d > 2*time.Hour {
				line("!", "sec:admin-ttl", fmt.Sprintf("DOP_ADMIN_MAX_TTL=%s is > 2h — reduce for admin machines", d))
			}
		}

		// Bundle file perms.
		capDir := filepath.Join(paths.Vault, "capabilities")
		if entries, err := os.ReadDir(capDir); err == nil {
			bad := 0
			for _, e := range entries {
				info, err := e.Info()
				if err != nil {
					continue
				}
				if info.Mode().Perm()&0o077 != 0 {
					bad++
				}
			}
			if bad > 0 {
				line("!", "sec:bundle-perms", fmt.Sprintf("%d bundle files have world/group-readable perms", bad))
			} else {
				line("✓", "sec:bundle-perms", "all bundles restrictive-perms")
			}
		}

		// Warn about DOP_TOKEN in shell history (best-effort — .zsh_history is common on macOS).
		if h := os.Getenv("HOME"); h != "" {
			for _, hf := range []string{".zsh_history", ".bash_history"} {
				p := filepath.Join(h, hf)
				if b, err := os.ReadFile(p); err == nil {
					if strings.Contains(string(b), "DOP_TOKEN=") {
						line("!", "sec:history", fmt.Sprintf("%s contains 'DOP_TOKEN=' — rotate any bearers referenced there", p))
					}
				}
			}
		}

		// vault.yaml permissions.
		if fi, err := os.Stat(vpath); err == nil {
			if fi.Mode().Perm()&0o044 != 0 {
				line("!", "sec:vault-perms", fmt.Sprintf("%s is group/world-readable", vpath))
			}
		}

		// Agent-install: warn if there's a keys/ directory that shouldn't be there.
		if !adminOK && exists(paths.KeysDir) {
			line("!", "sec:agent-keys", "agent install has a keys/ directory — verify it's empty")
		}
	}

	if anyFail {
		return 1
	}
	return 0
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// dopCheckSidecarConsistency warns about orphan bundles or records.
// Every active capability MUST have both a `.bundle` and a `.record` next
// to each other. Mismatches indicate a crash during issue/claim.
func dopCheckSidecarConsistency(paths *config.Paths, line func(status, name, detail string)) {
	dir := filepath.Join(paths.Vault, "capabilities")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	bundles := map[string]bool{}
	records := map[string]bool{}
	for _, e := range entries {
		n := e.Name()
		switch {
		case strings.HasSuffix(n, ".bundle"):
			bundles[strings.TrimSuffix(n, ".bundle")] = true
		case strings.HasSuffix(n, ".record"):
			records[strings.TrimSuffix(n, ".record")] = true
		}
	}
	orphanBundles := 0
	for k := range bundles {
		if !records[k] {
			orphanBundles++
		}
	}
	orphanRecords := 0
	for k := range records {
		if !bundles[k] {
			orphanRecords++
		}
	}
	switch {
	case orphanBundles == 0 && orphanRecords == 0:
		line("✓", "vault:sidecars", fmt.Sprintf("%d capabilities with matched bundle+record", len(bundles)))
	case orphanBundles > 0:
		line("!", "vault:sidecars", fmt.Sprintf("%d bundle(s) without a signed record — exec will reject them", orphanBundles))
	case orphanRecords > 0:
		line("!", "vault:sidecars", fmt.Sprintf("%d record(s) without a bundle — leftover from crashed operations", orphanRecords))
	}
}

// dopCheckAuditLog reports on log presence + size + freshness.
func dopCheckAuditLog(paths *config.Paths, line func(status, name, detail string)) {
	p := audit.Path(paths)
	fi, err := os.Stat(p)
	if err != nil {
		line("⋯", "audit:log", "no audit log yet (fine for a fresh install)")
		return
	}
	// Sample last line for parse health + freshness.
	f, err := os.Open(p)
	if err != nil {
		line("!", "audit:log", "log exists but can't be read: "+err.Error())
		return
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024), 64*1024)
	var last []byte
	count := 0
	badLines := 0
	for scanner.Scan() {
		last = append(last[:0], scanner.Bytes()...)
		count++
		var e audit.Event
		if json.Unmarshal(last, &e) != nil {
			badLines++
		}
	}
	sizeKB := float64(fi.Size()) / 1024.0
	freshness := "no events"
	if len(last) > 0 {
		var e audit.Event
		if json.Unmarshal(last, &e) == nil && !e.TS.IsZero() {
			freshness = time.Since(e.TS).Round(time.Second).String() + " ago"
		}
	}
	msg := fmt.Sprintf("%.1f KB, %d events, last %s", sizeKB, count, freshness)
	if badLines > 0 {
		msg += fmt.Sprintf(" (%d malformed lines)", badLines)
		line("!", "audit:log", msg)
	} else {
		line("✓", "audit:log", msg)
	}
}

// dopCheckGenCache surfaces parse errors and any missing-file races.
func dopCheckGenCache(paths *config.Paths, line func(status, name, detail string)) {
	dir := filepath.Join(paths.Root, "gen-cache")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return // no cache yet is fine
	}
	corrupt := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			corrupt++
			continue
		}
		var v uint64
		n, _ := fmt.Sscanf(strings.TrimSpace(string(b)), "%d", &v)
		if n != 1 {
			corrupt++
		}
	}
	total := len(entries)
	if corrupt > 0 {
		line("!", "cache:generation", fmt.Sprintf("%d/%d entries corrupt (will fall back to 0)", corrupt, total))
	} else if total > 0 {
		line("✓", "cache:generation", fmt.Sprintf("%d entry(ies)", total))
	}
}

// dopCheckPendingClaims warns about stale pending claims.
func dopCheckPendingClaims(paths *config.Paths, line func(status, name, detail string)) {
	all, err := pendingclaim.List(paths)
	if err != nil || len(all) == 0 {
		return
	}
	now := time.Now()
	live, stale := 0, 0
	for _, r := range all {
		if r.Expired(now) {
			stale++
		} else {
			live++
		}
	}
	msg := fmt.Sprintf("%d live", live)
	if stale > 0 {
		msg += fmt.Sprintf(", %d stale (should have been cleaned up)", stale)
		line("!", "pending:claims", msg)
	} else if live > 0 {
		line("⋯", "pending:claims", msg)
	}
}

// dopCheckGrantPrefixCollisions (v1.8) warns when any project contains
// two or more grants sharing an env prefix. Not fatal — `dop token
// issue` refuses at commit time — but flags a vault-config smell that
// will bite a future `--project P` bundle.
func dopCheckGrantPrefixCollisions(client *admin.Client, paths *config.Paths, line func(status, name, detail string)) {
	if !client.SessionActive() {
		return
	}
	// Load vault best-effort.
	vpath := vaultFilePath(paths)
	if _, err := os.Stat(vpath); err != nil {
		return
	}
	raw, err := os.ReadFile(vpath)
	if err != nil {
		return
	}
	var v vault.Vault
	if bytes.Contains(raw, []byte("\nsops:")) || bytes.HasPrefix(raw, []byte("sops:")) {
		plain, derr := client.DecryptVault(vpath)
		if derr != nil {
			return
		}
		if err := yamlUnmarshalVault(plain, &v); err != nil {
			return
		}
	} else {
		if err := yamlUnmarshalVault(raw, &v); err != nil {
			return
		}
	}

	// project → prefix → []grant-ids
	nested := map[string]map[string][]string{}
	add := func(proj, prefix, gid string) {
		if _, ok := nested[proj]; !ok {
			nested[proj] = map[string][]string{}
		}
		nested[proj][prefix] = append(nested[proj][prefix], gid)
	}
	for gid, g := range v.Grants {
		prefix := g.EffectivePrefix()
		if len(g.Projects) == 0 {
			add("(ungrouped)", prefix, gid)
		}
		for _, p := range g.Projects {
			add(p, prefix, gid)
		}
	}
	warned := 0
	for proj, byPrefix := range nested {
		for prefix, ids := range byPrefix {
			if len(ids) < 2 {
				continue
			}
			sort.Strings(ids)
			line("!", "vault:prefix-collision",
				fmt.Sprintf("project %q: %s_TOKEN used by %s (bundling any two will silently overwrite)",
					proj, prefix, strings.Join(ids, ", ")))
			warned++
		}
	}
	if warned == 0 && len(v.Grants) > 0 {
		line("✓", "vault:prefix-collision", "no env-prefix collisions within any project")
	}
}

// yamlUnmarshalVault is a tiny wrapper so we don't repeat the yaml import
// dance across doctor helpers.
func yamlUnmarshalVault(b []byte, v *vault.Vault) error {
	parsed, err := vault.ParsePlain(b)
	if err != nil {
		return err
	}
	*v = *parsed
	return nil
}

// Tie in tunnel package so it's not unused.
var _ = tunnel.Available

// dopCheckPendingInvites (v1.9) surfaces open admin invites — either
// waiting for a response or awaiting the operator's approval.
func dopCheckPendingInvites(paths *config.Paths, line func(status, name, detail string)) {
	all, err := admininvite.ListInvites(paths)
	if err != nil || len(all) == 0 {
		return
	}
	now := time.Now()
	live, expired := 0, 0
	for _, inv := range all {
		if inv.Expired(now) {
			expired++
		} else {
			live++
		}
	}
	msg := fmt.Sprintf("%d live", live)
	if expired > 0 {
		msg += fmt.Sprintf(", %d expired (delete with `dop team cancel-invite`)", expired)
		line("!", "vault:pending-invites", msg)
	} else if live > 0 {
		line("⋯", "vault:pending-invites", msg)
	}
}

func remainingTTL(ttlSec int64, refUnix int64) string {
	remaining := time.Until(time.Unix(refUnix, 0).Add(time.Duration(ttlSec) * time.Second))
	if remaining < 0 {
		remaining = 0
	}
	return remaining.Round(time.Second).String()
}

// hexEncodeBytes returns the lowercase hex of b. Used by tokencmd.
func hexEncodeBytes(b []byte) string { return hex.EncodeToString(b) }

// dopCheckCodesign inspects the currently-running dop binary and
// reports whether it's code-signed well enough to talk to the
// Secure Enclave. Adhoc / linker-signed binaries fail SE keygen
// with errSecMissingEntitlement (-34018).
func dopCheckCodesign(line func(status, name, detail string)) {
	if runtime.GOOS != "darwin" {
		return
	}
	self, err := os.Executable()
	if err != nil {
		return
	}
	cmd := exec.Command("codesign", "--display", "--verbose=2", self)
	var out bytes.Buffer
	cmd.Stderr = &out
	cmd.Stdout = &out
	_ = cmd.Run()
	s := out.String()
	switch {
	case strings.Contains(s, "not signed"):
		line("✗", "codesign:self", "binary is unsigned — Secure Enclave keygen will fail; agent keys fall back to legacy file")
	case strings.Contains(s, "adhoc") || strings.Contains(s, "Signature=adhoc"):
		line("!", "codesign:self", "adhoc-signed (linker default) — Secure Enclave keygen will FAIL. Install an officially-signed release for SE-backed agent keys.")
	case strings.Contains(s, "TeamIdentifier=not set"):
		line("!", "codesign:self", "signed but no team identifier — SE access may not work. Reinstall a properly signed release.")
	case strings.Contains(s, "Apple Development:"):
		// Apple Development cert can hardened-runtime-sign but still
		// gets errSecMissingEntitlement (-34018) from SE without an
		// App Store provisioning profile. Distributable SE access
		// needs Developer ID Application.
		line("!", "codesign:self", "signed with Apple Development cert — SE keygen still returns -34018 without a provisioning profile. Distributable SE access needs a Developer ID Application cert.")
	case strings.Contains(s, "Developer ID Application:"):
		line("✓", "codesign:self", "signed with Developer ID Application + hardened runtime — SE access should work")
	default:
		line("✓", "codesign:self", "signed, SE access should work")
	}
}

// dopCheckAgentKeys is a v1.11 doctor check: enumerates all agent keys
// on this machine and flags legacy ed25519 file storage (extractable →
// migration recommended). Also reports pending grace-delete counts.
func dopCheckAgentKeys(paths *config.Paths, line func(status, name, detail string)) {
	entries, err := collectAgentKeys(paths)
	if err != nil {
		line("!", "agent:keys", fmt.Sprintf("couldn't enumerate: %v", err))
		return
	}
	if len(entries) == 0 {
		line("⋯", "agent:keys", "none on this machine")
		return
	}
	seCount, fileEd, fileP256, pending := 0, 0, 0, 0
	for _, e := range entries {
		if e.Backend == "keychain-darwin" {
			seCount++
		} else if e.KeyType == "p256" {
			fileP256++
		} else {
			fileEd++
		}
		if e.PendingDelete {
			pending++
		}
	}
	if seCount > 0 && fileEd == 0 && fileP256 == 0 {
		line("✓", "agent:keys", fmt.Sprintf("all %d hardened in Secure Enclave", seCount))
	} else if fileEd > 0 {
		line("!", "agent:keys",
			fmt.Sprintf("%d Secure Enclave · %d ed25519 file (LEGACY, extractable — run `dop agent migrate <lookup>` to harden) · %d p256 file",
				seCount, fileEd, fileP256))
	} else if seCount == 0 && fileP256 > 0 {
		// v1.13.0-rc17 — louder flag when NO keys reached the Secure
		// Enclave. ClaudeMini field report: a cheerful "✓ 0 Secure
		// Enclave · 2 p256 file" obscures the fact that every key is
		// extractable. On signed builds this would be ✓ with ≥ 1 SE
		// key; a zero-SE count on Darwin means the binary isn't
		// Developer-ID-signed.
		line("!", "agent:keys",
			fmt.Sprintf("%d p256 file (EXTRACTABLE — 0 Secure Enclave on this install). Unsigned build → file-backed fallback. Install an officially-signed release to upgrade.", fileP256))
	} else {
		line("✓", "agent:keys",
			fmt.Sprintf("%d Secure Enclave · %d p256 file", seCount, fileP256))
	}
	if pending > 0 {
		line("⋯", "agent:keys-pending", fmt.Sprintf("%d legacy key(s) in 12h grace-delete window — will be removed automatically", pending))
	}
}
