// Stubs / minimal implementations for team + doctor + exec. Phase 4
// fleshes out `exec`; Phase 5 adds --security to doctor.

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/audit"
	"github.com/fray/dop/internal/capability"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

// --- dop team ---

func runTeam(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: dop team <add-key|remove|list>")
		return 2
	}
	switch args[0] {
	case "add-key":
		return runTeamAddKey(args[1:])
	case "remove":
		return runTeamRemove(args[1:])
	case "list":
		return runTeamList(args[1:])
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
	if _, ok := v.Admins[*name]; !ok {
		fmt.Fprintf(os.Stderr, "dop team remove: no admin named %q\n", *name)
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
	victim := v.Admins[*name]
	victimPub := strings.ToLower(victim.Ed25519Pubkey)
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

func remainingTTL(ttlSec int64, refUnix int64) string {
	remaining := time.Until(time.Unix(refUnix, 0).Add(time.Duration(ttlSec) * time.Second))
	if remaining < 0 {
		remaining = 0
	}
	return remaining.Round(time.Second).String()
}

// hexEncodeBytes returns the lowercase hex of b. Used by tokencmd.
func hexEncodeBytes(b []byte) string { return hex.EncodeToString(b) }
