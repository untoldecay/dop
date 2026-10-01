// `dop approve <SAS>` / `dop reject <SAS>` / `dop pending` — v1.5.
//
// Approve/reject work on pending-claim files written by an in-flight
// `dop claim`. Approving sets the file's state → the polling claim
// wakes up and finalizes.
//
// `dop pending` lists all currently pending claims (useful when you
// see a notification but forgot the SAS).

package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/fray/dop/internal/approval"
	"github.com/fray/dop/internal/audit"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/pendingclaim"
)

func runApprove(args []string) int {
	fs := flag.NewFlagSet("approve", flag.ExitOnError)
	pfromStdin := fs.Bool("passphrase-stdin", false, "read approval passphrase from stdin")
	flagArgs, posArgs := splitFlagsAndPositionals(fs, args)
	_ = fs.Parse(flagArgs)
	if len(posArgs) != 1 {
		fmt.Fprintln(os.Stderr, "usage: dop approve <SAS>")
		return 2
	}
	// Approval gate: verify the approval passphrase interactively BEFORE
	// touching the pending file. A malicious agent running as the same
	// user cannot type the passphrase into the parent's TTY.
	paths, err := config.Resolve()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop approve: %v\n", err)
		return 1
	}
	if !approval.Configured(paths) {
		fmt.Fprintln(os.Stderr, "dop approve: no approval passphrase set — run `dop admin set-approval`")
		return 1
	}
	// v1.6.3 — locate the pending claim BEFORE prompting so we can
	// share the rate limiter with the web endpoint. A same-uid attacker
	// spinning `dop approve --passphrase-stdin` in a loop trips this.
	sasArg := posArgs[0]
	pending, err := pendingclaim.FindBySAS(paths, sasArg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop approve: %v\n", err)
		return 1
	}
	if pending == nil {
		fmt.Fprintf(os.Stderr, "dop approve: no pending claim matches SAS %q\n", sasArg)
		return 1
	}
	if pending.FailureCount >= pendingclaim.MaxFailures {
		fmt.Fprintf(os.Stderr, "dop approve: this claim has already burned its %d passphrase attempts\n", pendingclaim.MaxFailures)
		return 1
	}
	pass, err := readPassphrase("Approval passphrase: ", *pfromStdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop approve: %v\n", err)
		return 1
	}
	ok, err := approval.Verify(paths, pass)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop approve: %v\n", err)
		return 1
	}
	if !ok {
		newCount, autoReject, berr := pendingclaim.BumpFailure(paths, pending.LookupID)
		if berr != nil {
			fmt.Fprintf(os.Stderr, "dop approve: bump failure counter: %v\n", berr)
		}
		remaining := pendingclaim.MaxFailures - newCount
		if autoReject || remaining <= 0 {
			fmt.Fprintf(os.Stderr, "dop approve: incorrect passphrase — claim aborted after %d attempts\n", pendingclaim.MaxFailures)
			return 1
		}
		fmt.Fprintf(os.Stderr, "dop approve: incorrect passphrase (%d attempt(s) left)\n", remaining)
		return 1
	}
	return decideClaim(sasArg, pendingclaim.StateApproved)
}

func runReject(args []string) int {
	fs := flag.NewFlagSet("reject", flag.ExitOnError)
	flagArgs, posArgs := splitFlagsAndPositionals(fs, args)
	_ = fs.Parse(flagArgs)
	if len(posArgs) != 1 {
		fmt.Fprintln(os.Stderr, "usage: dop reject <SAS>")
		return 2
	}
	// Reject does NOT require the passphrase — rejecting is safe:
	// worst case a malicious rejection annoys the user, and same-user
	// rejection would just force a retry. Approve, by contrast, is the
	// dangerous direction.
	return decideClaim(posArgs[0], pendingclaim.StateRejected)
}

// decideClaim is the shared body of approve + reject.
func decideClaim(sas, state string) int {
	verb := "approve"
	if state == pendingclaim.StateRejected {
		verb = "reject"
	}

	paths, err := config.Resolve()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop %s: %v\n", verb, err)
		return 1
	}
	rec, err := pendingclaim.FindBySAS(paths, sas)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop %s: %v\n", verb, err)
		return 1
	}
	if rec == nil {
		fmt.Fprintf(os.Stderr, "dop %s: no pending claim matches SAS %q\n", verb, sas)
		return 1
	}
	if rec.Expired(time.Now()) {
		fmt.Fprintf(os.Stderr, "dop %s: this claim has already expired\n", verb)
		return 1
	}
	if rec.State != pendingclaim.StatePending {
		fmt.Fprintf(os.Stderr, "dop %s: claim already %s\n", verb, rec.State)
		return 1
	}
	if err := pendingclaim.SetState(paths, rec.LookupID, state); err != nil {
		fmt.Fprintf(os.Stderr, "dop %s: %v\n", verb, err)
		return 1
	}
	kind := audit.EventClaimApproved
	if state == pendingclaim.StateRejected {
		kind = audit.EventClaimDenied
	}
	extra := map[string]string{"sas": pendingclaim.NormalizeSAS(rec.SAS)}
	if kind == audit.EventClaimDenied {
		extra["reason"] = "rejected"
	}
	audit.Append(paths, audit.Event{
		Kind:     kind,
		Subject:  rec.Subject,
		LookupID: rec.LookupID,
		Extra:    extra,
	})
	fmt.Fprintf(os.Stderr, "dop %s: %s → %s\n", verb, rec.Subject, state)
	return 0
}

func runPending(args []string) int {
	fs := flag.NewFlagSet("pending", flag.ExitOnError)
	_ = fs.Parse(args)
	paths, err := config.Resolve()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop pending: %v\n", err)
		return 1
	}
	all, err := pendingclaim.List(paths)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			fmt.Println("(no pending claims)")
			return 0
		}
		fmt.Fprintf(os.Stderr, "dop pending: %v\n", err)
		return 1
	}
	// Sort by started_at desc for a "most-recent-first" feel.
	if len(all) == 0 {
		fmt.Println("(no pending claims)")
		return 0
	}
	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "SAS\tSUBJECT\tSTATE\tTTL LEFT\tPUBKEY")
	now := time.Now()
	for _, r := range all {
		ttl := r.ExpiresAt.Sub(now).Truncate(time.Second)
		ttlStr := ttl.String()
		if ttl < 0 {
			ttlStr = "expired"
		}
		pub := r.Pubkey
		if len(pub) > 12 {
			pub = pub[:12] + "…"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			r.SAS, r.Subject, r.State, ttlStr, pub)
	}
	_ = w.Flush()
	// Trailing hint that composes safely — no leading spaces users could parse.
	_ = strings.TrimSpace
	return 0
}
