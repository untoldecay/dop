// `dop team invite --name <label>` — v1.9 admin bootstrap invitation.
//
// Called on the ORIGINAL admin machine (M1). Generates a PIN, stages
// a pending-admin-invite in the vault repo, commits + pushes, and
// then polls the vault waiting for the joining machine (M2) to reply.
// When M2's response arrives, prompts M1 for the approval passphrase,
// runs the existing team-add-key path, and pushes the completed vault.

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/admininvite"
	"github.com/fray/dop/internal/approval"
	"github.com/fray/dop/internal/audit"
	"github.com/fray/dop/internal/capability"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

// vaultOriginURL returns the git origin URL of the vault repo, or ""
// if the vault has no origin (rare — a fresh local-only setup) or git
// fails for some other reason. Callers should treat "" as "fall back
// to the old 'same one you cloned from' hint".
func vaultOriginURL(vaultDir string) string {
	cmd := exec.Command("git", "-C", vaultDir, "remote", "get-url", "origin")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func runTeamInvite(args []string) int {
	fs := flag.NewFlagSet("team invite", flag.ExitOnError)
	name := fs.String("name", "", "human-readable label for the new admin device (required)")
	kind := fs.String("kind", "device", "\"device\" (another machine of yours) or \"team_member\"")
	pfromStdin := fs.Bool("passphrase-stdin", false, "read passphrase(s) from stdin (testing only)")
	timeoutStr := fs.String("timeout", "30m", "how long to wait for the response before giving up")
	pinTTL := fs.String("pin-ttl", "30m", "invite validity window")
	shareIdentity := fs.Bool("share-identity", false, "give the joining machine THIS machine's admin identity (Flavor Y — single revocation surface across devices)")
	_ = fs.Parse(args)

	if strings.TrimSpace(*name) == "" {
		fmt.Fprintln(os.Stderr, "dop team invite: --name required")
		return 2
	}
	waitTimeout, err := time.ParseDuration(*timeoutStr)
	if err != nil || waitTimeout <= 0 {
		fmt.Fprintf(os.Stderr, "dop team invite: bad --timeout: %v\n", err)
		return 2
	}
	pinDur, err := time.ParseDuration(*pinTTL)
	if err != nil || pinDur <= 0 {
		fmt.Fprintf(os.Stderr, "dop team invite: bad --pin-ttl: %v\n", err)
		return 2
	}

	paths, _ := config.Resolve()
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop team invite: %v\n", err)
		return 1
	}
	if !approval.Configured(paths) {
		fmt.Fprintln(os.Stderr, "dop team invite: no approval passphrase configured — run `dop admin set-approval` first")
		return 1
	}

	// Optimistic pull so the invite lands on the latest tip.
	_ = gitQuiet(paths.Vault, "pull", "--ff-only")

	inviteID, err := admininvite.NewInviteID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop team invite: %v\n", err)
		return 1
	}
	pin, err := capability.NewPIN()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop team invite: %v\n", err)
		return 1
	}
	st, err := client.Status()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop team invite: %v\n", err)
		return 1
	}
	now := time.Now().UTC().Truncate(time.Second)
	inv := admininvite.Invite{
		InviteID:      inviteID,
		Name:          *name,
		PinHash:       admininvite.HashPIN(inviteID, pin),
		CreatedAt:     now,
		ExpiresAt:     now.Add(pinDur),
		CreatedByPub:  st.AdminPubkey,
		Kind:          *kind,
		ShareIdentity: *shareIdentity,
	}
	if err := admininvite.WriteInvite(paths, inv); err != nil {
		fmt.Fprintf(os.Stderr, "dop team invite: write invite: %v\n", err)
		return 1
	}
	// v1.9.3 — Flavor Y: also stage the encrypted identity blob so M2
	// can install M1's admin keys directly (no new admin entry).
	if *shareIdentity {
		if rc := writeShareBlob(paths, inviteID, pin, *pfromStdin); rc != 0 {
			return rc
		}
	}
	commitPath := filepath.Join("pending-admin-invites", inviteID+".invite.json")
	if *shareIdentity {
		commitPath = filepath.Join("pending-admin-invites")
	}
	if err := gitAddCommitPush(paths.Vault, commitPath,
		fmt.Sprintf("dop: open admin invite %s (%s)", inviteID[:8], *name)); err != nil {
		fmt.Fprintf(os.Stderr, "dop team invite: push invite: %v — run `dop push` manually\n", err)
		return 1
	}
	audit.Append(paths, audit.Event{
		Kind:    audit.EventInvite,
		Subject: *name,
		Extra:   map[string]string{"invite_id": inviteID, "kind": *kind},
	})

	// rc7o — show the human details + the approve-later hint, then exit.
	// No more polling loop. Operator runs `dop team approve-invite <id>`
	// (or picks the invite in the TUI Team → Pending tab and presses `a`)
	// when the teammate has joined.
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Admin invite for", *name)
	fmt.Fprintf(os.Stderr, "  invite_id:  %s\n", inviteID)
	fmt.Fprintf(os.Stderr, "  PIN:        %s   (valid %s)\n", pin, pinDur)
	vaultURL := vaultOriginURL(paths.Vault)
	if vaultURL != "" {
		fmt.Fprintf(os.Stderr, "  vault URL:  %s\n", vaultURL)
		fmt.Fprintln(os.Stderr, "  on the new machine run:")
		fmt.Fprintf(os.Stderr, "    dop admin join %s %s\n", vaultURL, pin)
	} else {
		fmt.Fprintln(os.Stderr, "  vault URL:  (no git origin — copy the URL you cloned this vault from)")
		fmt.Fprintln(os.Stderr, "  on the new machine run:")
		fmt.Fprintf(os.Stderr, "    dop admin join <VAULT-URL> %s\n", pin)
	}
	fmt.Fprintln(os.Stderr)
	if *shareIdentity {
		fmt.Fprintf(os.Stderr, "  Shared-identity invite — nothing to approve on this side; the join completes\n")
		fmt.Fprintf(os.Stderr, "  on the teammate's machine automatically. Check later via `dop team list`.\n")
	} else {
		fmt.Fprintf(os.Stderr, "  Approve-later: when %s finishes `dop admin join`, run:\n", *name)
		fmt.Fprintf(os.Stderr, "    dop team approve-invite %s\n", inviteID[:8])
		fmt.Fprintf(os.Stderr, "  or open the TUI Team → Pending tab and press `a` on the row.\n")
	}
	fmt.Fprintln(os.Stderr)
	// Keep the invite in the vault; the operator can `dop team cancel-invite`
	// if they want to drop it before the teammate completes.
	_ = waitTimeout // kept for backward-compat with pre-rc7o scripts passing --timeout
	return 0
}

// runTeamApproveInvite — rc7o. Complete a pending admin invite by
// reading the teammate's response, verifying the signature, prompting
// for the approval passphrase, running the add-admin logic, and
// pushing. Replaces the inline polling loop in rc6/pre-rc7o
// runTeamInvite.
func runTeamApproveInvite(args []string) int {
	fs := flag.NewFlagSet("team approve-invite", flag.ExitOnError)
	pfromStdin := fs.Bool("passphrase-stdin", false, "read approval passphrase from stdin (TUI uses this)")
	_ = fs.Parse(args)
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "usage: dop team approve-invite <invite-id>")
		fmt.Fprintln(os.Stderr, "  invite id is the hex prefix shown by `dop team invite` output,")
		fmt.Fprintln(os.Stderr, "  or any of the ids in `dop team list` pending output.")
		return 2
	}
	id := rest[0]

	paths, err := config.Resolve()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop team approve-invite: %v\n", err)
		return 1
	}
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop team approve-invite: %v\n", err)
		return 1
	}

	// Pull so the teammate's response + any other admin's changes are visible.
	_ = gitQuiet(paths.Vault, "pull", "--ff-only")

	full, err := resolveInviteID(paths, id)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop team approve-invite: %v\n", err)
		return 1
	}
	inv, err := admininvite.ReadInvite(paths, full)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop team approve-invite: %v\n", err)
		return 1
	}

	// Shared-identity has no response file — the teammate consumes
	// the invite by deleting it on their side. If the invite still
	// exists, they haven't completed. If it's gone, this command is
	// a no-op (there's nothing to approve).
	if inv.ShareIdentity {
		fmt.Fprintf(os.Stderr, "dop team approve-invite: shared-identity invite — nothing to approve on this side;\n")
		fmt.Fprintln(os.Stderr, "  the teammate's `dop admin join` completes the join automatically.")
		fmt.Fprintln(os.Stderr, "  check `dop team list` for the admin entry.")
		return 0
	}

	resp, err := admininvite.ReadResponse(paths, full)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop team approve-invite: no response yet from %s — try again when they've run `dop admin join`.\n", inv.Name)
		return 1
	}
	if err := resp.Verify(); err != nil {
		fmt.Fprintf(os.Stderr, "dop team approve-invite: response signature invalid: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stderr, "  ✓ response from %s at host %s\n", inv.Name, resp.Host)
	fmt.Fprintf(os.Stderr, "    pubkey  %s\n", resp.Ed25519Pubkey)
	fmt.Fprintf(os.Stderr, "    age     %s\n", resp.AgeRecipient)

	pass, err := readPassphrase("Approval passphrase (to confirm add): ", *pfromStdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop team approve-invite: %v\n", err)
		return 1
	}
	ok, err := approval.Verify(paths, pass)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop team approve-invite: %v\n", err)
		return 1
	}
	if !ok {
		fmt.Fprintln(os.Stderr, "dop team approve-invite: incorrect passphrase — leaving invite open, try again")
		return 1
	}

	if rc := completeInvite(client, paths, *inv, resp); rc != 0 {
		return rc
	}
	fmt.Fprintln(os.Stderr, "  ✓ approved — pushed. joining machine will pick it up on its next pull.")
	return 0
}

// completeInvite runs the "add the new admin + cleanup + push" path.
func completeInvite(client *admin.Client, paths *config.Paths,
	inv admininvite.Invite, resp *admininvite.Response) int {
	// Load vault, add the new admin, save (which re-encrypts for all
	// recipients + writes admins.trust).
	v, vp, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop team invite: load vault: %v\n", err)
		return 1
	}
	if v.Admins == nil {
		v.Admins = map[string]Admin{}
	}
	// If a different admin entry already exists under this hostname
	// use a numeric suffix so we don't overwrite (mirrors save-vault).
	key := inv.Name
	for i := 2; ; i++ {
		existing, ok := v.Admins[key]
		if !ok || strings.EqualFold(existing.Ed25519Pubkey, resp.Ed25519Pubkey) {
			break
		}
		key = fmt.Sprintf("%s-%d", inv.Name, i)
	}
	v.Admins[key] = Admin{
		AgeRecipient:  resp.AgeRecipient,
		Ed25519Pubkey: resp.Ed25519Pubkey,
		AddedAt:       time.Now().UTC().Truncate(time.Second),
		Note:          "joined via invite " + inv.InviteID[:8],
	}
	if err := saveVaultViaDaemon(client, paths, vp, v); err != nil {
		fmt.Fprintf(os.Stderr, "dop team invite: save vault: %v\n", err)
		return 1
	}
	// Wipe the invite files.
	if err := admininvite.Delete(paths, inv.InviteID); err != nil {
		fmt.Fprintf(os.Stderr, "dop team invite: cleanup: %v (non-fatal)\n", err)
	}
	if err := gitAddCommitPush(paths.Vault, ".",
		fmt.Sprintf("dop: complete admin invite %s (%s)", inv.InviteID[:8], inv.Name)); err != nil {
		fmt.Fprintf(os.Stderr, "dop team invite: git push: %v — run `dop push` manually\n", err)
		return 1
	}
	audit.Append(paths, audit.Event{
		Kind:    audit.EventInviteComplete,
		Subject: inv.Name,
		Actor:   resp.Ed25519Pubkey,
		Extra:   map[string]string{"invite_id": inv.InviteID, "host": resp.Host},
	})
	return 0
}

// gitQuiet runs a git command with stdio muted.
func gitQuiet(dir string, args ...string) error {
	return runGit(io.Discard, dir, args...)
}

// gitAddCommitPush stages + commits + pushes. Empty commit is allowed
// so the push still fires when only deletions happened.
func gitAddCommitPush(dir, addPath, msg string) error {
	if err := runGit(io.Discard, dir, "add", "-A", addPath); err != nil {
		return err
	}
	if err := runGit(io.Discard, dir, "commit", "-m", msg, "--allow-empty"); err != nil {
		return err
	}
	return runGit(io.Discard, dir, "push")
}

// writeShareBlob (v1.9.3) — reads the wrapped admin key + approval hash
// from disk, encrypts them with a PIN-derived argon2id key, and writes
// the ciphertext to <invite_id>.identity-blob inside the vault so M2
// can install M1's identity directly.
func writeShareBlob(paths *config.Paths, inviteID, pin string, pfromStdin bool) int {
	_ = pfromStdin
	adminKeyPath := admin.KeyFile(paths)
	adminKeyBytes, err := os.ReadFile(adminKeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop team invite: read admin key: %v\n", err)
		return 1
	}
	approvalPath := filepath.Join(paths.KeysDir, "approval.hash")
	approvalBytes, err := os.ReadFile(approvalPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop team invite: read approval hash: %v\n", err)
		return 1
	}
	blob, err := admininvite.EncryptIdentityBlob(pin, inviteID, adminKeyBytes, approvalBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop team invite: encrypt identity blob: %v\n", err)
		return 1
	}
	p := admininvite.IdentityBlobPath(paths, inviteID)
	if err := os.WriteFile(p, blob, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "dop team invite: write identity blob: %v\n", err)
		return 1
	}
	return 0
}

// vault package alias just to keep the imports honest.
var _ = vault.SchemaVersion
var _ = errors.New
