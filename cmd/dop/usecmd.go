// `dop use <subject>` — v1.14.0-rc1. Shortcut flow for admin's own
// bearers. Prints an `export DOP_TOKEN=…` line to stdout that the
// operator eval's into their shell, or writes to a token file with
// `--token-file`.
//
// Design (see _rules/_plans/shell_use.md):
//   - Admin session MUST be unlocked. The daemon holds the age
//     identity needed to decrypt the stashed bearer; without an
//     unlock, we have no way to retrieve it.
//   - The capability for <subject> MUST have been issued with
//     `--portable`. If it wasn't, we can't retrieve the bearer
//     (DOP intentionally doesn't store bearer values otherwise) —
//     refuse with a clear hint.
//   - Protected bearers (rc12) are additionally owner-gated: refuse
//     when the session's admin pubkey isn't the capability owner.
//   - Audit event `use_attached` fires on every successful attach,
//     carrying the subject + whether a disk file was written.
//     NEVER the bearer value.

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/audit"
	"github.com/fray/dop/internal/capability"
	"github.com/fray/dop/internal/cli/printguard"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

// defaultTokenFileTTL is how long a `--token-file` is considered
// valid from its mtime. Short — the file is a persistence escape
// hatch, not a long-term store.
const defaultTokenFileTTL = 24 * time.Hour

func runUse(args []string) int {
	fs := flag.NewFlagSet("use", flag.ExitOnError)
	tokenFile := fs.String("token-file", "", "write the bearer to this file (JSON {token, subject, expires_at}) with mode 0600, instead of printing to stdout. Operator sets DOP_TOKEN_FILE=<path>.")
	// rc6h — --print-export retired. Pre-rc5 it was a three-tier gate
	// (non-tty refuse / flag opt-in / approval on non-tty+flag). rc5
	// Option A collapsed that to "approval always, no tty distinction"
	// and the flag was retained as a documented-but-dead no-op. The
	// stale help text misled agents into setting the flag defensively,
	// which did nothing — remove the flag entirely to end the confusion.
	// Legacy callers still pass it: parse silently + warn once to stderr.
	legacyPrintExport := fs.Bool("print-export", false, "DEPRECATED (rc6h): no-op, accepted for backward-compat. The approval popup fires on every print; the flag never changed that.")
	// --passphrase-stdin reserved for future use (phase 2 might add
	// an approval-passphrase gate; today the admin session unlock is
	// the gate). Parsed but ignored so scripts can predeclare it.
	_ = fs.Bool("passphrase-stdin", false, "reserved — currently a no-op; the admin daemon unlock is the authorization gate")
	_ = fs.Parse(args)
	if *legacyPrintExport {
		fmt.Fprintln(os.Stderr, "dop use: --print-export is deprecated and has no effect (removed in rc6h).")
	}

	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "usage: dop use [--token-file FILE] <subject>")
		fmt.Fprintln(os.Stderr, "  Attaches an admin-stashed bearer to the current shell.")
		fmt.Fprintln(os.Stderr, "  Default: prints `export DOP_TOKEN=…` to stdout for `eval \"$(…)\"`.")
		fmt.Fprintln(os.Stderr, "  Issue the bearer with:")
		fmt.Fprintln(os.Stderr, "    dop token issue --name <subject> --grants … --portable")
		return 2
	}
	subject := rest[0]

	paths, _ := config.Resolve()
	// rc6f — operator-friendly unlock: if the admin session is locked
	// AND we're not inside the TUI, pop a native passphrase dialog
	// instead of erroring out. Headless / scripted environments fall
	// back to the normal "run dop admin login" error.
	client, err := requireAdminSessionOrUnlock(paths, "use "+subject)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop use: %v\n", err)
		return 1
	}
	v, _, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop use: %v\n", err)
		return 1
	}

	// Find the active capability for this subject. Mirrors the repin
	// resolution pattern: exact subject match + status=active.
	capIDHex, crec, err := findActiveCapBySubject(v, subject)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop use: %v\n", err)
		return 1
	}

	// Refuse if the capability wasn't stashed. Explicit hint rather
	// than a vague "nothing to unwrap" since this is the most common
	// first-encounter error.
	if crec.PortableWrapped == "" {
		fmt.Fprintf(os.Stderr,
			"dop use: capability %q has no portable stash — the bearer value is not retrievable.\n"+
				"  Re-issue it with --portable, OR use the one-shot bearer printed at issue time:\n"+
				"    dop token issue --name %s --grants … --portable\n",
			subject, subject)
		return 1
	}

	// Protection gate — same owner check as rc12. Caller must be the
	// capability's owning admin if it's protected.
	if err := checkCapabilityProtection(client, crec); err != nil {
		fmt.Fprintf(os.Stderr, "dop use: %v\n", err)
		return 1
	}

	// Unwrap via daemon.
	bearerBytes, err := client.UnwrapPortable(crec.PortableWrapped)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop use: unwrap: %v\n", err)
		return 1
	}
	bearer := string(bearerBytes)
	if bearer == "" {
		fmt.Fprintln(os.Stderr, "dop use: unwrap returned empty bearer — stash may be corrupted")
		return 1
	}

	// Compute audit actor (short pubkey) for the event.
	st, _ := client.Status()
	actor := ""
	if st != nil && len(st.AdminPubkey) >= 8 {
		actor = st.AdminPubkey[:8]
	}

	// Default: stdout eval line. Optional: write to token file.
	disk := false
	if *tokenFile != "" {
		if err := writeTokenFile(*tokenFile, bearer, subject); err != nil {
			fmt.Fprintf(os.Stderr, "dop use: write token file: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "dop use: wrote %s (mode 0600, TTL %s)\n", *tokenFile, defaultTokenFileTTL)
		fmt.Fprintf(os.Stderr, "  Point the agent at it: export DOP_TOKEN_FILE=%s\n", *tokenFile)
		disk = true
	} else {
		// rc5 Option A: every print requires operator approval regardless
		// of tty/non-tty. printguard handles the dialog + fallbacks.
		if err := printguard.Guard(printguard.Request{
			Kind:    printguard.KindUse,
			Subject: subject,
			Out:     os.Stdout,
			Paths:   paths,
			Client:  client,
		}); err != nil {
			return 1
		}
		fmt.Printf("export DOP_TOKEN=%s\n", bearer)
	}

	audit.Append(paths, audit.Event{
		Kind:     audit.EventUseAttached,
		Subject:  subject,
		LookupID: crec.LookupID,
		Actor:    actor,
		Extra: map[string]string{
			"capability_id": capIDHex,
			"disk":          boolStrUse(disk),
		},
	})
	return 0
}

func boolStrUse(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// findActiveCapBySubject looks for exactly one ACTIVE capability
// whose Subject matches `subject`. Multiple-matches is an error:
// the admin needs to pick explicitly.
func findActiveCapBySubject(v *vault.Vault, subject string) (string, vault.Capability, error) {
	var (
		foundID string
		found   vault.Capability
		matches int
	)
	for id, c := range v.Capabilities {
		if c.Subject == subject && c.Status == capability.RecordStatusActive {
			foundID = id
			found = c
			matches++
		}
	}
	if matches == 0 {
		return "", vault.Capability{}, fmt.Errorf("no active capability with subject %q", subject)
	}
	if matches > 1 {
		return "", vault.Capability{}, fmt.Errorf("subject %q matches multiple active capabilities — revoke the duplicates or disambiguate by cap-id", subject)
	}
	return foundID, found, nil
}

// checkCapabilityProtection enforces the rc12 owner lock for
// protected bearers (via the grants they carry). We look at the
// grants referenced by the capability — if any is protected and the
// session isn't the owner, refuse. Mirrors requireProtectionOwner
// but for bearer-level attach rather than mutation.
func checkCapabilityProtection(client *admin.Client, crec vault.Capability) error {
	// For now, protection is only checked on the integrations/grants
	// referenced by the bearer at use-attach time. This is a
	// conservative lift of the owner gate; `dop use` doesn't mutate
	// anything, but we still prefer not to hand a bearer to an admin
	// who doesn't own the protected grants it carries.
	//
	// Keep this cheap: load vault once (already loaded by caller),
	// but the caller doesn't pass it in — resolve via daemon again
	// is fine for a non-hot path.
	paths, _ := config.Resolve()
	v, _, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		return fmt.Errorf("load vault for protection check: %w", err)
	}
	st, err := client.Status()
	if err != nil {
		return fmt.Errorf("session status: %w", err)
	}
	for _, gid := range crec.Grants {
		g, ok := v.Grants[gid]
		if !ok {
			continue
		}
		if !g.Protected {
			continue
		}
		if !strings.EqualFold(g.Owner, st.AdminPubkey) {
			return fmt.Errorf("bearer carries protected grant %q owned by another admin — only the owner can `dop use` it", gid)
		}
	}
	return nil
}

// writeTokenFile stores a bearer at the given path in a JSON
// envelope with an issued_at timestamp. Mode 0600. Overwrites if
// present. Callers (and other DOP commands reading DOP_TOKEN_FILE)
// should refuse to use a file older than defaultTokenFileTTL from
// its stored issued_at.
func writeTokenFile(path, bearer, subject string) error {
	payload := map[string]string{
		"token":      bearer,
		"subject":    subject,
		"issued_at":  time.Now().UTC().Format(time.RFC3339),
		"expires_at": time.Now().Add(defaultTokenFileTTL).UTC().Format(time.RFC3339),
	}
	data, _ := json.MarshalIndent(payload, "", "  ")
	data = append(data, '\n')
	// Create with mode 0600 (readable only by the owner).
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	// Chmod again in case OpenFile didn't fully honor it (umask).
	_ = os.Chmod(path, 0o600)
	return nil
}

// Compile-time sanity: these are the only error types we construct.
var (
	_ = errors.New
	_ = fmt.Errorf
)
