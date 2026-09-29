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
	default:
		fmt.Fprintf(os.Stderr, "dop team: unknown subcommand %q\n", args[0])
		return 2
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
