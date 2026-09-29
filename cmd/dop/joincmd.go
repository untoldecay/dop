// `dop admin join <VAULT-URL> <PIN>` — v1.9 admin bootstrap, M2 side.
//
// On a machine without an admin key yet (or with one but never
// attached to this vault), clones the vault, verifies the PIN against
// the open invite, signs a response with its ed25519 key, pushes,
// then polls until it appears in the vault's admins list.

package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/admininvite"
	"github.com/fray/dop/internal/approval"
	"github.com/fray/dop/internal/audit"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/trust"
)

func runAdminJoin(args []string) int {
	fs := flag.NewFlagSet("admin join", flag.ExitOnError)
	pfromStdin := fs.Bool("passphrase-stdin", false, "read passphrase(s) from stdin (testing only)")
	timeoutStr := fs.String("timeout", "30m", "how long to wait for M1 to approve")
	_ = fs.Parse(args)

	if fs.NArg() != 2 {
		fmt.Fprintln(os.Stderr, "usage: dop admin join <VAULT-URL> <PIN>")
		return 2
	}
	vaultURL := fs.Arg(0)
	pin := fs.Arg(1)
	waitTimeout, err := time.ParseDuration(*timeoutStr)
	if err != nil || waitTimeout <= 0 {
		fmt.Fprintf(os.Stderr, "dop admin join: bad --timeout: %v\n", err)
		return 2
	}

	paths, _ := config.Resolve()
	if err := paths.EnsureDirs(); err != nil {
		fmt.Fprintf(os.Stderr, "dop admin join: %v\n", err)
		return 1
	}

	// Clone the vault first so we can read the invite metadata and
	// know which flavor (X per-device / Y shared identity) the operator
	// picked.
	if _, err := os.Stat(filepath.Join(paths.Vault, ".git")); err != nil {
		fmt.Fprintf(os.Stderr, "dop admin join: cloning vault into %s…\n", paths.Vault)
		if rc := attachRepo(vaultURL, paths.Vault, false); rc != 0 {
			return rc
		}
	} else {
		fmt.Fprintln(os.Stderr, "dop admin join: vault already attached — pulling.")
		if err := runGit(io.Discard, paths.Vault, "pull", "--ff-only"); err != nil {
			fmt.Fprintf(os.Stderr, "dop admin join: pull: %v\n", err)
			return 1
		}
	}

	inv, err := admininvite.FindByPIN(paths, pin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop admin join: %v\n", err)
		return 1
	}
	if inv == nil {
		fmt.Fprintln(os.Stderr, "dop admin join: no matching invite found — did the original admin run `dop team invite` and push?")
		return 1
	}
	if inv.Expired(time.Now()) {
		fmt.Fprintln(os.Stderr, "dop admin join: this invite has expired — ask for a fresh one")
		return 1
	}
	fmt.Fprintf(os.Stderr, "  ✓ invite matched: %q (id %s)\n", inv.Name, inv.InviteID[:8])

	// Flavor Y — shared identity: install M1's keys directly, no new
	// admin entry to negotiate.
	if inv.ShareIdentity {
		return runAdminJoinShared(paths, inv, pin, *pfromStdin)
	}

	// Flavor X — per-device identity (existing path).
	var pass string
	if !admin.KeyFileExists(paths) {
		fmt.Fprintln(os.Stderr, "dop admin join: no admin key on this machine — creating one now.")
		created, rc := adminInitInline(paths, *pfromStdin)
		if rc != 0 {
			return rc
		}
		pass = created
	} else {
		fmt.Fprintln(os.Stderr, "dop admin join: existing admin key detected — using it.")
		p, err := readPassphrase("Admin passphrase (to unwrap keys): ", *pfromStdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dop admin join: %v\n", err)
			return 1
		}
		pass = p
	}

	keys, err := admin.LoadAndUnwrap(paths, pass)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop admin join: %v\n", err)
		return 1
	}
	edPub := keys.Ed25519.Public().(ed25519.PublicKey)
	pubHex := hex.EncodeToString(edPub)
	ageRecipient := keys.Age.Recipient().String()

	// Step 5: sign + write the response.
	host, _ := os.Hostname()
	resp := admininvite.Response{
		InviteID:      inv.InviteID,
		Ed25519Pubkey: pubHex,
		AgeRecipient:  ageRecipient,
		Host:          host,
		RespondedAt:   time.Now().UTC().Truncate(time.Second),
	}
	if err := resp.Sign(keys.Ed25519); err != nil {
		fmt.Fprintf(os.Stderr, "dop admin join: sign: %v\n", err)
		return 1
	}
	if err := admininvite.WriteResponse(paths, resp); err != nil {
		fmt.Fprintf(os.Stderr, "dop admin join: write response: %v\n", err)
		return 1
	}
	if err := gitAddCommitPush(paths.Vault,
		filepath.Join("pending-admin-invites", inv.InviteID+".response.json"),
		fmt.Sprintf("dop: admin invite response %s (%s)", inv.InviteID[:8], host)); err != nil {
		fmt.Fprintf(os.Stderr, "dop admin join: push response: %v\n", err)
		return 1
	}
	audit.Append(paths, audit.Event{
		Kind:    audit.EventInviteResponse,
		Subject: inv.Name,
		Actor:   pubHex,
		Extra:   map[string]string{"invite_id": inv.InviteID, "host": host},
	})
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  ✓ response pushed. Waiting for original admin to approve…")

	// Step 6: poll until we appear in admins.trust.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	deadline := time.Now().Add(waitTimeout)
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()

	for {
		select {
		case <-sigCh:
			fmt.Fprintln(os.Stderr, "\ndop admin join: cancelled by signal")
			return 1
		case <-tick.C:
		}
		if time.Now().After(deadline) {
			fmt.Fprintln(os.Stderr, "\ndop admin join: timed out — no approval received.")
			return 1
		}
		_ = runGit(io.Discard, paths.Vault, "pull", "--ff-only")
		trusted, err := trust.Load(paths)
		if err != nil {
			continue
		}
		if trusted[strings.ToLower(pubHex)] || trusted[pubHex] {
			break
		}
	}

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  ✓ approved — this machine is now an admin.")
	fmt.Fprintln(os.Stderr, "    next: `dop admin login` to start an interactive session,")
	fmt.Fprintln(os.Stderr, "          `dop admin status` to verify.")
	return 0
}

// adminInitInline runs the same interactive admin-init flow that
// `dop admin init` uses, so `dop admin join` on a fresh machine can
// bootstrap without a separate command call.
func adminInitInline(paths *config.Paths, pfromStdin bool) (string, int) {
	pass1, err := readPassphrase("Choose a passphrase for your admin key (≥ 8 chars): ", pfromStdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop admin join: %v\n", err)
		return "", 1
	}
	if len(pass1) < 8 {
		fmt.Fprintln(os.Stderr, "dop admin join: passphrase must be at least 8 characters")
		return "", 1
	}
	if !pfromStdin {
		pass2, err := readPassphrase("Confirm passphrase: ", false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dop admin join: %v\n", err)
			return "", 1
		}
		if pass1 != pass2 {
			fmt.Fprintln(os.Stderr, "dop admin join: passphrases do not match")
			return "", 1
		}
	}
	keys, err := admin.Generate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop admin join: %v\n", err)
		return "", 1
	}
	wrapped, err := admin.Wrap(keys, pass1)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop admin join: %v\n", err)
		return "", 1
	}
	if err := admin.WriteFile(admin.KeyFile(paths), wrapped); err != nil {
		fmt.Fprintf(os.Stderr, "dop admin join: %v\n", err)
		return "", 1
	}
	appPass1, err := readPassphrase("Choose an approval passphrase (≥ 10 chars): ", pfromStdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop admin join: %v\n", err)
		return "", 1
	}
	if len(appPass1) < 10 {
		fmt.Fprintln(os.Stderr, "dop admin join: approval passphrase must be at least 10 characters")
		return "", 1
	}
	if !pfromStdin {
		appPass2, err := readPassphrase("Confirm approval passphrase: ", false)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dop admin join: %v\n", err)
			return "", 1
		}
		if appPass1 != appPass2 {
			fmt.Fprintln(os.Stderr, "dop admin join: approval passphrases do not match")
			return "", 1
		}
	}
	if err := approval.Set(paths, appPass1); err != nil {
		fmt.Fprintf(os.Stderr, "dop admin join: store approval passphrase: %v\n", err)
		return "", 1
	}
	fmt.Fprintln(os.Stderr, "  ✓ admin key generated")
	return pass1, 0
}

// runAdminJoinShared handles Flavor Y — the invite carries an
// encrypted identity blob. M2 refuses to run if it already has an
// admin key (would silently overwrite), then decrypts the blob with
// the PIN, installs M1's wrapped key + approval hash, verifies the
// operator knows M1's admin passphrase (`LoadAndUnwrap`), cleans up
// the blob, and pushes. No response file, no waiting for M1.
func runAdminJoinShared(paths *config.Paths, inv *admininvite.Invite, pin string, pfromStdin bool) int {
	if admin.KeyFileExists(paths) {
		fmt.Fprintln(os.Stderr, "dop admin join: shared-identity invite refuses to overwrite the existing admin key on this machine.")
		fmt.Fprintln(os.Stderr, "  run `dop admin reset` first if you really want to replace it.")
		return 1
	}
	blob, err := os.ReadFile(admininvite.IdentityBlobPath(paths, inv.InviteID))
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop admin join: shared-identity blob missing: %v\n", err)
		return 1
	}
	adminKey, approvalHash, err := admininvite.DecryptIdentityBlob(pin, inv.InviteID, blob)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop admin join: %v\n", err)
		return 1
	}
	// Install to local disk.
	if err := admin.WriteFile(admin.KeyFile(paths), adminKey); err != nil {
		fmt.Fprintf(os.Stderr, "dop admin join: write admin key: %v\n", err)
		return 1
	}
	approvalPath := filepath.Join(paths.KeysDir, "approval.hash")
	if err := os.WriteFile(approvalPath, approvalHash, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "dop admin join: write approval hash: %v\n", err)
		return 1
	}
	// Verify the operator can actually unwrap (guards against a corrupt
	// blob or a bad PIN that decrypted to junk).
	fmt.Fprintln(os.Stderr, "  ✓ identity installed. Verifying by unwrapping…")
	pass, err := readPassphrase("Admin passphrase (same one used on the inviting machine): ", pfromStdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop admin join: %v\n", err)
		return 1
	}
	if _, err := admin.LoadAndUnwrap(paths, pass); err != nil {
		fmt.Fprintf(os.Stderr, "dop admin join: unwrap failed: %v\n", err)
		fmt.Fprintln(os.Stderr, "  (make sure you're typing the SAME passphrase as on the inviting machine.)")
		fmt.Fprintln(os.Stderr, "  the installed key file remains — retry `dop admin login`, or `dop admin reset` and re-run join.")
		return 1
	}
	fmt.Fprintln(os.Stderr, "  ✓ unwrap OK — this machine is now the SAME admin as the inviting machine.")

	// Clean up the blob + invite so M1's polling loop can exit.
	if err := admininvite.Delete(paths, inv.InviteID); err != nil {
		fmt.Fprintf(os.Stderr, "dop admin join: cleanup: %v (non-fatal)\n", err)
	}
	_ = os.Remove(admininvite.IdentityBlobPath(paths, inv.InviteID))
	_ = runGit(io.Discard, paths.Vault, "add", "-A", "pending-admin-invites")
	_ = runGit(io.Discard, paths.Vault, "commit", "-m",
		fmt.Sprintf("dop: consume shared-identity invite %s", inv.InviteID[:8]),
		"--allow-empty")
	_ = runGit(io.Discard, paths.Vault, "push")

	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "  ✓ done. `dop admin login` will accept the same passphrase you used on the inviting machine.")
	return 0
}

var _ = errors.New // keep tidy
