// `dop approve-remote` — admin-side counterpart of `dop claim --remote`.
// Ingests a pending remote-claim staged in the vault repo, verifies
// the agent's signature, prompts for the approval passphrase, then
// swaps the new bundle in + writes an updated signed record sidecar.

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fray/dop/internal/approval"
	"github.com/fray/dop/internal/audit"
	"github.com/fray/dop/internal/capability"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/remoteclaim"
	"github.com/fray/dop/internal/vault"
)

func runApproveRemote(args []string) int {
	fs := flag.NewFlagSet("approve-remote", flag.ExitOnError)
	subject := fs.String("subject", "", "subject of the remote claim to approve (required unless --list)")
	list := fs.Bool("list", false, "list pending remote claims and exit")
	pfromStdin := fs.Bool("passphrase-stdin", false, "read approval passphrase from stdin")
	_ = fs.Parse(args)

	paths, _ := config.Resolve()

	if *list {
		return runApproveRemoteList(paths)
	}
	if *subject == "" {
		fmt.Fprintln(os.Stderr, "usage: dop approve-remote --subject S  |  --list")
		return 2
	}
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop approve-remote: %v\n", err)
		return 1
	}
	if !approval.Configured(paths) {
		fmt.Fprintln(os.Stderr, "dop approve-remote: no approval passphrase set — run `dop admin set-approval`")
		return 1
	}

	all, err := remoteclaim.List(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop approve-remote: %v\n", err)
		return 1
	}
	var match *remoteclaim.Request
	for _, r := range all {
		if r.Subject == *subject {
			if match != nil {
				fmt.Fprintf(os.Stderr, "dop approve-remote: multiple remote claims for %q — narrow with `--list`\n", *subject)
				return 1
			}
			match = r
		}
	}
	if match == nil {
		fmt.Fprintf(os.Stderr, "dop approve-remote: no pending remote claim for subject %q\n", *subject)
		return 1
	}
	if time.Now().After(match.ExpiresAt) {
		fmt.Fprintf(os.Stderr, "dop approve-remote: this claim expired at %s\n", match.ExpiresAt.Format(time.RFC3339))
		return 1
	}
	if err := match.Verify(); err != nil {
		fmt.Fprintf(os.Stderr, "dop approve-remote: %v (agent did not correctly sign the request)\n", err)
		return 1
	}

	// Present the claim so the admin can confirm identity out-of-band.
	fmt.Fprintln(os.Stderr, "Remote claim:")
	fmt.Fprintf(os.Stderr, "  subject:      %s\n", match.Subject)
	fmt.Fprintf(os.Stderr, "  host:         %s\n", match.Host)
	fmt.Fprintf(os.Stderr, "  pubkey:       %s\n", match.Pubkey)
	fmt.Fprintf(os.Stderr, "  requested at: %s\n", match.RequestedAt.Format(time.RFC3339))
	fmt.Fprintf(os.Stderr, "  new gen:      %d\n", match.NewGeneration)

	// Passphrase gate.
	pass, err := readPassphrase("Approval passphrase: ", *pfromStdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop approve-remote: %v\n", err)
		return 1
	}
	ok, err := approval.Verify(paths, pass)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop approve-remote: %v\n", err)
		return 1
	}
	if !ok {
		fmt.Fprintln(os.Stderr, "dop approve-remote: incorrect passphrase")
		audit.Append(paths, audit.Event{
			Kind:     audit.EventClaimDenied,
			Subject:  match.Subject,
			LookupID: match.LookupID,
			Extra:    map[string]string{"reason": "remote_bad_passphrase"},
		})
		return 1
	}

	// Load vault, locate the capability record.
	v, vaultPath, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop approve-remote: %v\n", err)
		return 1
	}
	crec, ok := v.Capabilities[match.CapabilityID]
	if !ok {
		fmt.Fprintln(os.Stderr, "dop approve-remote: capability record missing from vault")
		return 1
	}
	if crec.Status != capability.RecordStatusActive {
		fmt.Fprintf(os.Stderr, "dop approve-remote: capability is %s, not active\n", crec.Status)
		return 1
	}
	if crec.Binding == nil || crec.Binding.Kind != vault.BindingKindPIN {
		fmt.Fprintln(os.Stderr, "dop approve-remote: capability is not PIN-bound")
		return 1
	}
	if crec.Binding.Pubkey != "" {
		fmt.Fprintln(os.Stderr, "dop approve-remote: capability already claimed")
		return 1
	}

	// Verify the staged bundle exists and its hash matches what the
	// agent claimed.
	_, stagedBundle, err := remoteclaim.ReadOne(paths, match.LookupID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop approve-remote: read staged bundle: %v\n", err)
		return 1
	}
	if capability.HashBundle(stagedBundle) != match.NewBundleHash {
		fmt.Fprintln(os.Stderr, "dop approve-remote: staged bundle hash does not match request — refusing")
		return 1
	}

	// Sync generation counter up to the agent's chosen new gen.
	if v.Generations == nil {
		v.Generations = map[string]uint64{}
	}
	if match.NewGeneration > v.Generations[crec.Subject] {
		v.Generations[crec.Subject] = match.NewGeneration
	} else {
		fmt.Fprintf(os.Stderr,
			"dop approve-remote: staged gen %d is not ahead of vault gen %d — refusing\n",
			match.NewGeneration, v.Generations[crec.Subject])
		return 1
	}

	claimedAt := time.Now().UTC().Truncate(time.Second)
	crec.Generation = match.NewGeneration
	crec.BundleHash = match.NewBundleHash
	crec.Binding = &vault.Binding{
		Kind:      vault.BindingKindPIN,
		Pubkey:    match.Pubkey,
		ClaimedAt: claimedAt,
	}
	rec := vaultCapability2Record(crec, match.CapabilityID)
	if err := signRecordViaDaemon(client, &rec); err != nil {
		fmt.Fprintf(os.Stderr, "dop approve-remote: sign: %v\n", err)
		return 1
	}
	putCapability(v, match.CapabilityID, rec)

	// Swap the bundle into place.
	finalBundle := filepath.Join(paths.Vault, "capabilities", match.LookupID+".bundle")
	if err := os.WriteFile(finalBundle, stagedBundle, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "dop approve-remote: swap bundle: %v\n", err)
		return 1
	}
	if err := writeRecordSidecar(paths, rec); err != nil {
		fmt.Fprintf(os.Stderr, "dop approve-remote: write sidecar: %v\n", err)
		return 1
	}
	if err := saveVaultViaDaemon(client, paths, vaultPath, v); err != nil {
		fmt.Fprintf(os.Stderr, "dop approve-remote: save vault: %v\n", err)
		return 1
	}

	// Clean pending files + push.
	if err := remoteclaim.Delete(paths, match.LookupID); err != nil {
		fmt.Fprintf(os.Stderr, "dop approve-remote: cleanup: %v (non-fatal)\n", err)
	}
	if err := gitCommitPushApproveRemote(paths, match.LookupID); err != nil {
		fmt.Fprintf(os.Stderr, "dop approve-remote: git push failed (%v) — run `dop push` manually\n", err)
	}

	audit.Append(paths, audit.Event{
		Kind:     audit.EventClaim,
		Subject:  match.Subject,
		LookupID: match.LookupID,
		Actor:    match.Pubkey,
		Extra:    map[string]string{"remote": "true", "host": match.Host, "generation": fmt.Sprintf("%d", match.NewGeneration)},
	})

	fmt.Fprintf(os.Stderr, "dop approve-remote: approved %s (agent %s can now `dop pull` + exec)\n",
		match.Subject, match.Host)
	_ = hex.EncodeToString // keep import
	return 0
}

func runApproveRemoteList(paths *config.Paths) int {
	all, err := remoteclaim.List(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop approve-remote --list: %v\n", err)
		return 1
	}
	if len(all) == 0 {
		fmt.Println("(no pending remote claims)")
		return 0
	}
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "SUBJECT\tHOST\tPUBKEY\tREQUESTED\tSTATE")
	now := time.Now()
	for _, r := range all {
		state := "pending"
		if now.After(r.ExpiresAt) {
			state = "expired"
		}
		fmt.Fprintf(w, "%s\t%s\t%s…\t%s\t%s\n",
			r.Subject, r.Host, shortPub(r.Pubkey),
			r.RequestedAt.Format(time.RFC3339), state)
	}
	_ = w.Flush()
	return 0
}

func shortPub(p string) string {
	if len(p) > 12 {
		return p[:12]
	}
	return p
}

// gitCommitPushApproveRemote commits the bundle overwrite + record
// change + pending-cleanup and pushes. Errors are surfaced to stderr
// so a wedged operation is diagnosable.
func gitCommitPushApproveRemote(paths *config.Paths, lookupID string) error {
	dir := paths.Vault
	if err := runGit(os.Stderr, dir, "add", "-A", "."); err != nil {
		return fmt.Errorf("git add: %w", err)
	}
	msg := fmt.Sprintf("dop: approve remote claim %s", lookupID[:12])
	// Allow-empty is defensive: if syncSidecars produced no diff on this
	// specific path, we still want a commit for provenance.
	if err := runGit(os.Stderr, dir, "commit", "-m", msg, "--allow-empty"); err != nil {
		return fmt.Errorf("git commit: %w", err)
	}
	return runGit(os.Stderr, dir, "push")
}

// keep the strings import used implicitly
var _ = strings.ToLower
