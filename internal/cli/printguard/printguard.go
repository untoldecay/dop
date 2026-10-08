// Package printguard enforces the approval-always policy for secret-print
// surfaces (`dop use`, `dop token issue`, `dop env`, `dop claim` export).
//
// Threat model: an LLM-driven shell running `! dop <secret-print-cmd>`
// captures stdout into a chat transcript on disk — even when stdout
// looks like a tty from the operator's perspective.
//
// Rc5 Option A: every print requires operator approval regardless of
// tty state. Two bypasses:
//
//   - DOP_FROM_TUI=1 — set by the TUI on every shell-out. The TUI is
//     the interactive operator surface; its captured output goes back
//     to the TUI render path, not to a transcript.
//   - DOP_APPROVAL_PASSPHRASE — scripted/CI pre-approval. Same auth
//     strength as the popup (verifies via approval.Verify).
//   - ClaimApproved (KindClaim only) — the admin approved this claim
//     seconds ago in the same process; its export line skips a second
//     prompt.
//
// Decision flow:
//   - Local approval: admin daemon's native dialog (osascript on darwin).
//     Timeout configurable via userprefs (15/30/60s).
//   - Tunnel+phone fallback (rc5b): fires on local timeout, daemon
//     unreachable, OR platform unsupported. Prints URL + QR to stderr;
//     admin approves on phone with the same approval passphrase.
//
// rc6h — removed PrintFlag from the Request struct. The pre-rc5 three-
// tier model (non-tty refuse / --print-* opt-in / approval on non-tty)
// kept the flag as a gate; Option A collapsed the model so the flag
// became a no-op kept for backward-compat. Stale help text misled
// callers into setting the flag defensively, which did nothing. Flags
// are now accepted at the CLI layer with a one-line deprecation warning
// and never reach this package.
package printguard

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"golang.org/x/term"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/approval"
	"github.com/fray/dop/internal/audit"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/printapproval"
	"github.com/fray/dop/internal/sessiontrust"
	"github.com/fray/dop/internal/userprefs"
)

// Kind tags the audit event + the dialog title. Short, operator-facing.
type Kind string

const (
	KindUse        Kind = "print_use"         // `dop use` export line
	KindTokenIssue Kind = "print_issue"       // `dop token issue` bearer + PIN
	KindEnv        Kind = "print_env"         // `dop env` scoped exports
	KindClaim      Kind = "print_claim"       // `dop claim` success export
)

// Request bundles everything the caller passes to Guard. All fields
// are populated by the caller based on CLI arg parsing.
type Request struct {
	// Kind is the print-surface tag. Required.
	Kind Kind
	// Subject identifies what's being printed (bearer subject, grant,
	// etc.). Surfaces in the dialog + audit event.
	Subject string
	// Out is the stream we're about to write the secret to. We check
	// its tty-ness for the shell-trust cache fast path; `os.Stdout`
	// in almost every real caller.
	Out io.Writer
	// Audit stores the paths needed for audit emission. Set to the
	// caller's resolved config.Paths.
	Paths *config.Paths
	// Client is the admin daemon client, used for the approval popup.
	// May be nil when the caller doesn't have one; Guard then
	// treats "daemon unreachable" and falls back / refuses.
	Client *admin.Client
	// ClaimApproved is set by `dop claim` once the admin approved this
	// claim in the same process (QR / phone or popup). Its export line
	// then needs no second prompt seconds later (dop-8g7). Only KindClaim
	// honours it; `claim --skip-approval` never sets it.
	ClaimApproved bool
	// LookupID goes on the claim-approval audit event.
	LookupID string
}

// ErrRefused signals the caller MUST NOT print the secret. Caller
// should return non-zero to the OS.
var ErrRefused = errors.New("printguard: print refused")

// Guard runs the three-tier policy on req. Returns nil when the caller
// is cleared to print, ErrRefused (or wrapped) otherwise.
//
// Side effects:
//   - Writes a human-readable refusal to stderr when refusing.
//   - Emits one audit event per approval request/decision.
//   - Does NOT write to req.Out itself; caller does the actual print.
func Guard(req Request) error {
	// Option A (rc5): approval required for every print invocation
	// regardless of tty/non-tty state. The old tty bypass was removed
	// because an LLM running `! dop use X` in the operator's own
	// terminal has a tty from DOP's point of view AND leaks the output
	// into the chat transcript. One rule everywhere.
	//
	// Two bypasses:
	//   1. DOP_FROM_TUI=1 — the TUI shells out to this CLI; the TUI is
	//      the operator's interactive surface, output goes back to the
	//      TUI render path, no LLM-capture risk.
	//   2. DOP_APPROVAL_PASSPHRASE — scripted/CI pre-approval via env
	//      (same auth strength as the popup).
	isTTY := isTerminal(req.Out)

	if os.Getenv("DOP_FROM_TUI") == "1" {
		return nil
	}
	channel := ""
	switch {
	case req.ClaimApproved && req.Kind == KindClaim:
		channel = "claim_approval"
	}
	if channel != "" {
		audit.Append(req.Paths, audit.Event{
			Kind:     audit.EventPrintApprovalGranted,
			Subject:  req.Subject,
			LookupID: req.LookupID,
			Extra:    map[string]string{"surface": string(req.Kind), "channel": channel},
		})
		return nil
	}
	// v1.14.0-rc6i — TrustContext cache. Replaces the rc6 shell-trust
	// cache. The CLI-side resolver (internal/sessiontrust) walks a
	// precedence stack (DOP_SESSION_ID → recognized harness adapter →
	// tty → getsid() → ppid) to produce a stable identifier for the
	// current execution context. The daemon stores grants keyed by
	// (ContextKind, ContextValue, Subject) with idle TTL.
	//
	// Gates (unchanged from rc6):
	//   - non-tty only — a visible-print surface in a real terminal
	//     always prompts (defense against drive-by `! dop use` from
	//     an LLM in the operator's own tty)
	//   - KindUse / KindEnv only — mutations stay per-invocation
	//   - daemon reachable
	evalPatternSurface := req.Kind == KindUse || req.Kind == KindEnv
	// rc7i — thread the operator's picked harness through to the
	// resolver via DOP_HARNESS. Operators who set this via Settings
	// get the right harness adapter without needing to export
	// DOP_INFER_HARNESS_SESSION=1 themselves.
	if prefs := userprefs.Load(req.Paths); prefs.Harness != "" {
		os.Setenv("DOP_HARNESS", userprefs.DOPHarnessEnvValue(prefs.Harness))
	}
	tctx := sessiontrust.Resolve()
	if !isTTY && evalPatternSurface && req.Client != nil {
		if trusted, _ := req.Client.TrustContextCheck(string(tctx.Kind), tctx.Value, req.Subject); trusted {
			audit.Append(req.Paths, audit.Event{
				Kind:    audit.EventPrintApprovalGranted,
				Subject: req.Subject,
				Extra: map[string]string{
					"surface":      string(req.Kind),
					"channel":      "trust_context",
					"context_kind": string(tctx.Kind),
				},
			})
			return nil
		}
	}
	// Env escape hatch (DOP_APPROVAL_PASSPHRASE): same auth strength
	// as typing into the popup — still verifies the real passphrase.
	// Not advertised in --help; purely a scripted-approval escape.
	if envPass := os.Getenv("DOP_APPROVAL_PASSPHRASE"); envPass != "" {
		audit.Append(req.Paths, audit.Event{
			Kind:    audit.EventPrintApprovalRequested,
			Subject: req.Subject,
			Extra:   map[string]string{"surface": string(req.Kind), "channel": "env"},
		})
		ok, verr := approval.Verify(req.Paths, envPass)
		if verr != nil {
			fmt.Fprintf(os.Stderr, "dop %s: approval verify (env): %v\n", req.Kind, verr)
			audit.Append(req.Paths, audit.Event{
				Kind:    audit.EventPrintApprovalDenied,
				Subject: req.Subject,
				Extra:   map[string]string{"surface": string(req.Kind), "reason": "verify_error", "channel": "env"},
			})
			return ErrRefused
		}
		if !ok {
			fmt.Fprintf(os.Stderr, "dop %s: approval denied (wrong passphrase in DOP_APPROVAL_PASSPHRASE).\n", req.Kind)
			audit.Append(req.Paths, audit.Event{
				Kind:    audit.EventPrintApprovalDenied,
				Subject: req.Subject,
				Extra:   map[string]string{"surface": string(req.Kind), "reason": "wrong_passphrase", "channel": "env"},
			})
			return ErrRefused
		}
		audit.Append(req.Paths, audit.Event{
			Kind:    audit.EventPrintApprovalGranted,
			Subject: req.Subject,
			Extra:   map[string]string{"surface": string(req.Kind), "channel": "env"},
		})
		return nil
	}
	// Approval via admin daemon's local popup. 60s dialog timeout.
	// Future (rc5b): on timeout OR unsupported-platform, upgrade to
	// tunnel+phone fallback instead of refusing outright.
	if req.Client == nil {
		fmt.Fprintln(os.Stderr, "dop "+string(req.Kind)+": approval required but no admin session reachable.")
		fmt.Fprintln(os.Stderr, "  Run `dop admin login`, then retry.")
		return ErrRefused
	}
	// Audit the request before the dialog opens so a hung dialog
	// still leaves a trail.
	audit.Append(req.Paths, audit.Event{
		Kind:    audit.EventPrintApprovalRequested,
		Subject: req.Subject,
		Extra: map[string]string{
			"surface": string(req.Kind),
		},
	})
	prompt := fmt.Sprintf("A dop process is about to print %q to stdout.\n\nSurface: %s\nSubject: %s\n\nType your approval passphrase to allow this one invocation.",
		req.Subject, req.Kind, req.Subject)
	// rc5b — timeout is operator-configurable (15/30/60s) via the TUI
	// settings view, stored in userprefs. Falls back to the 60s default
	// when prefs are absent or carry an invalid value.
	timeout := userprefs.Load(req.Paths).ApprovalTimeout()
	decision, reason, err := req.Client.ApprovalPopup(
		string(req.Kind),
		req.Subject,
		prompt,
		timeout,
	)
	// Decide whether to fall back to tunnel+phone.
	// - err from daemon RPC → unreachable, try fallback
	// - decision "timeout" → local popup timed out, try fallback
	// - decision "unsupported" → platform/env can't show dialog, try fallback
	// - decision "denied" / "approved" → final, no fallback
	fallback := false
	fallbackReason := ""
	switch {
	case err != nil:
		fallback = true
		fallbackReason = "daemon_unreachable"
	case decision == "timeout":
		fallback = true
		fallbackReason = "local_timeout"
	case decision == "unsupported":
		fallback = true
		fallbackReason = "unsupported"
	}
	if fallback {
		fmt.Fprintf(os.Stderr, "dop %s: local approval failed (%s) — falling back to tunnel+phone.\n", req.Kind, fallbackReason)
		audit.Append(req.Paths, audit.Event{
			Kind:    audit.EventPrintApprovalRequested,
			Subject: req.Subject,
			Extra:   map[string]string{"surface": string(req.Kind), "channel": "phone", "escalated_from": fallbackReason},
		})
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()
		d, derr := printapproval.Run(ctx, printapproval.Request{
			Paths:   req.Paths,
			Kind:    string(req.Kind),
			Subject: req.Subject,
			TTL:     5 * time.Minute,
		})
		if derr != nil {
			fmt.Fprintf(os.Stderr, "dop %s: tunnel fallback error: %v\n", req.Kind, derr)
			audit.Append(req.Paths, audit.Event{
				Kind:    audit.EventPrintApprovalDenied,
				Subject: req.Subject,
				Extra:   map[string]string{"surface": string(req.Kind), "channel": "phone", "reason": "fallback_error"},
			})
			return ErrRefused
		}
		switch d {
		case printapproval.DecisionApproved:
			audit.Append(req.Paths, audit.Event{
				Kind:    audit.EventPrintApprovalGranted,
				Subject: req.Subject,
				Extra:   map[string]string{"surface": string(req.Kind), "channel": "phone"},
			})
			// rc6i — mark this trust context so subsequent invocations
			// from the same session context skip the popup. Phone
			// approval counts as the "first" approval.
			if !isTTY && evalPatternSurface && req.Client != nil {
				_ = req.Client.TrustContextMark(string(tctx.Kind), tctx.Value, req.Subject)
			}
			return nil
		case printapproval.DecisionRejected:
			fmt.Fprintf(os.Stderr, "dop %s: approval denied via phone.\n", req.Kind)
			audit.Append(req.Paths, audit.Event{
				Kind:    audit.EventPrintApprovalDenied,
				Subject: req.Subject,
				Extra:   map[string]string{"surface": string(req.Kind), "channel": "phone", "reason": "rejected"},
			})
			return ErrRefused
		default: // expired
			fmt.Fprintf(os.Stderr, "dop %s: phone approval expired.\n", req.Kind)
			audit.Append(req.Paths, audit.Event{
				Kind:    audit.EventPrintApprovalDenied,
				Subject: req.Subject,
				Extra:   map[string]string{"surface": string(req.Kind), "channel": "phone", "reason": "expired"},
			})
			return ErrRefused
		}
	}
	switch decision {
	case "approved":
		audit.Append(req.Paths, audit.Event{
			Kind:    audit.EventPrintApprovalGranted,
			Subject: req.Subject,
			Extra:   map[string]string{"surface": string(req.Kind), "channel": "local"},
		})
		// rc6i — mark this trust context so subsequent invocations from
		// the same session context skip the popup within the idle TTL.
		if !isTTY && evalPatternSurface && req.Client != nil {
			_ = req.Client.TrustContextMark(string(tctx.Kind), tctx.Value, req.Subject)
		}
		return nil
	case "denied":
		fmt.Fprintf(os.Stderr, "dop %s: approval denied.\n", req.Kind)
		if reason != "" {
			fmt.Fprintf(os.Stderr, "  reason: %s\n", reason)
		}
		audit.Append(req.Paths, audit.Event{
			Kind:    audit.EventPrintApprovalDenied,
			Subject: req.Subject,
			Extra:   map[string]string{"surface": string(req.Kind), "reason": reason},
		})
		return ErrRefused
	default:
		fmt.Fprintf(os.Stderr, "dop %s: approval returned unexpected decision %q.\n", req.Kind, decision)
		return ErrRefused
	}
}

// isTerminal checks whether out is a tty. Only works for *os.File;
// anything else is treated as non-tty (safe default).
func isTerminal(out io.Writer) bool {
	f, ok := out.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

// shortCmd maps a Kind back to the operator-facing CLI incantation
// used in refusal hints.
func shortCmd(k Kind) string {
	switch k {
	case KindUse:
		return "use <subject>"
	case KindTokenIssue:
		return "token issue --name <subject> --grants …"
	case KindEnv:
		return "env"
	case KindClaim:
		return "claim <PIN>"
	default:
		return string(k)
	}
}
