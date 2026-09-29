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
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/admininvite"
	"github.com/fray/dop/internal/approval"
	"github.com/fray/dop/internal/audit"
	"github.com/fray/dop/internal/capability"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

func runTeamInvite(args []string) int {
	fs := flag.NewFlagSet("team invite", flag.ExitOnError)
	name := fs.String("name", "", "human-readable label for the new admin device (required)")
	kind := fs.String("kind", "device", "\"device\" (another machine of yours) or \"team_member\"")
	pfromStdin := fs.Bool("passphrase-stdin", false, "read approval passphrase from stdin (testing only)")
	timeoutStr := fs.String("timeout", "30m", "how long to wait for the response before giving up")
	pinTTL := fs.String("pin-ttl", "30m", "invite validity window")
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
		InviteID:     inviteID,
		Name:         *name,
		PinHash:      admininvite.HashPIN(inviteID, pin),
		CreatedAt:    now,
		ExpiresAt:    now.Add(pinDur),
		CreatedByPub: st.AdminPubkey,
		Kind:         *kind,
	}
	if err := admininvite.WriteInvite(paths, inv); err != nil {
		fmt.Fprintf(os.Stderr, "dop team invite: write invite: %v\n", err)
		return 1
	}
	if err := gitAddCommitPush(paths.Vault, filepath.Join("pending-admin-invites", inviteID+".invite.json"),
		fmt.Sprintf("dop: open admin invite %s (%s)", inviteID[:8], *name)); err != nil {
		fmt.Fprintf(os.Stderr, "dop team invite: push invite: %v — run `dop push` manually\n", err)
		return 1
	}
	audit.Append(paths, audit.Event{
		Kind:    audit.EventInvite,
		Subject: *name,
		Extra:   map[string]string{"invite_id": inviteID, "kind": *kind},
	})

	// Show the human details.
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Admin invite for", *name)
	fmt.Fprintf(os.Stderr, "  PIN:        %s   (valid %s)\n", pin, pinDur)
	fmt.Fprintln(os.Stderr, "  vault URL: same one you cloned this vault from")
	fmt.Fprintln(os.Stderr, "  on the new machine run:")
	fmt.Fprintf(os.Stderr, "    dop admin join <VAULT-URL> %s\n", pin)
	fmt.Fprintln(os.Stderr)

	// Poll for M2's response.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	deadline := time.Now().Add(waitTimeout)
	tick := time.NewTicker(3 * time.Second)
	defer tick.Stop()

	fmt.Fprintln(os.Stderr, "  ⋯ waiting for response…")

	for {
		select {
		case <-sigCh:
			// Best-effort cleanup: leave the invite in the vault so M2
			// can still complete if they've partially started; but
			// user knows they aborted.
			fmt.Fprintln(os.Stderr, "\ndop team invite: cancelled (invite left in vault; delete with `dop team cancel-invite`)")
			return 1
		case <-tick.C:
		}
		if time.Now().After(deadline) {
			fmt.Fprintln(os.Stderr, "\ndop team invite: timed out — no response received.")
			_ = admininvite.Delete(paths, inviteID)
			_ = gitAddCommitPush(paths.Vault, "pending-admin-invites",
				fmt.Sprintf("dop: expire admin invite %s", inviteID[:8]))
			return 1
		}

		if err := gitQuiet(paths.Vault, "pull", "--ff-only"); err != nil {
			continue // transient
		}
		resp, err := admininvite.ReadResponse(paths, inviteID)
		if err != nil {
			continue // not there yet
		}
		if err := resp.Verify(); err != nil {
			fmt.Fprintf(os.Stderr, "\ndop team invite: response signature invalid: %v\n", err)
			continue
		}

		// M2 responded. Confirm + prompt for approval passphrase.
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "  ✓ %s responded from host %s\n", *name, resp.Host)
		fmt.Fprintf(os.Stderr, "    pubkey  %s\n", resp.Ed25519Pubkey)
		fmt.Fprintf(os.Stderr, "    age     %s\n", resp.AgeRecipient)

		pass, err := readPassphrase("Approval passphrase (to confirm add): ", *pfromStdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dop team invite: %v\n", err)
			return 1
		}
		ok, err := approval.Verify(paths, pass)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dop team invite: %v\n", err)
			return 1
		}
		if !ok {
			fmt.Fprintln(os.Stderr, "dop team invite: incorrect passphrase — leaving invite open, try again")
			continue
		}

		// Passphrase good — add the admin.
		if rc := completeInvite(client, paths, inv, resp); rc != 0 {
			return rc
		}
		fmt.Fprintln(os.Stderr, "  ✓ approved — pushed. joining machine will pick it up on its next pull.")
		return 0
	}
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

// vault package alias just to keep the imports honest.
var _ = vault.SchemaVersion
var _ = errors.New
