// Package printguard enforces the three-tier policy for secret-print
// surfaces (`dop use`, `dop token issue`, `dop env`, `dop claim` export).
//
// Threat model: an LLM-driven shell running `! dop <secret-print-cmd>`
// captures stdout into a chat transcript on disk. The three tiers:
//
//  1. Tier 1 — refuse to print to a non-tty by default (the common
//     case for `!`-prefix captures).
//  2. Tier 2 — explicit `--print-*` flag opts into non-tty printing
//     (for genuine CI / script workflows that pipe stdout).
//  3. Tier 3 — when Tier 2 is set, additionally require operator
//     approval via the admin daemon's local popup (osascript on
//     darwin) OR the tunnel+phone fallback. Decision per-invocation,
//     no session window.
//
// At a tty, Tier 1 passes transparently; Tier 2 flag is ignored (user
// already sees the output); Tier 3 is skipped (no transcript leak path).
//
// Non-tty + no flag  → refuse with eval hint
// Non-tty + flag + approved → allow
// Non-tty + flag + denied  → refuse with reason
// Non-tty + flag + timeout → refuse with hint to retry
// Non-tty + flag + daemon unreachable → fall back to tunnel+phone (TODO rc4b)
package printguard

import (
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
// except PrintFlag are set by the caller based on CLI arg parsing.
type Request struct {
	// Kind is the print-surface tag. Required.
	Kind Kind
	// Subject identifies what's being printed (bearer subject, grant,
	// etc.). Surfaces in the dialog + audit event.
	Subject string
	// PrintFlag is the value of the surface's `--print-*` flag.
	// False → Tier 1 refusal when non-tty.
	// True  → Tier 2 opt-in; Tier 3 approval runs on non-tty.
	PrintFlag bool
	// Out is the stream we're about to write the secret to. We check
	// its tty-ness; `os.Stdout` in almost every real caller.
	Out io.Writer
	// Audit stores the paths needed for audit emission. Set to the
	// caller's resolved config.Paths.
	Paths *config.Paths
	// Client is the admin daemon client, used for Tier 3 approval.
	// May be nil when the caller doesn't have one; Guard then
	// treats "daemon unreachable" and falls back / refuses.
	Client *admin.Client
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
	isTTY := isTerminal(req.Out)
	// At a tty: no leak path, no approval needed. Caller prints.
	if isTTY {
		return nil
	}
	// v1.14.0-rc4b — TUI subprocess bypass. The TUI shells out to this
	// CLI binary with stdout piped back to the TUI render path. From the
	// child's perspective, stdout is a pipe (not a tty) — Tier 1 would
	// refuse and the TUI's handoff screen would be empty. But the TUI
	// IS the interactive operator surface; there's no LLM-capture leak
	// path when the human is literally driving the TUI. The TUI sets
	// DOP_FROM_TUI=1 on every shell-out, which we treat as tty-equivalent.
	//
	// Threat model: a shell operator could forge DOP_FROM_TUI=1 to bypass
	// the gate, but that's explicitly choosing to disable the protection
	// — same category as setting DOP_APPROVAL_PASSPHRASE in env.
	if os.Getenv("DOP_FROM_TUI") == "1" {
		return nil
	}
	// Env escape hatch (DOP_APPROVAL_PASSPHRASE): set in env means
	// "I pre-approve this print; verify my passphrase and proceed."
	// Bypasses both Tier 1 (print-flag check) AND Tier 3 (interactive
	// popup) in one go. Threat model: an attacker who can read env
	// already has DOP_TOKEN, so putting the approval passphrase in
	// env doesn't widen the surface — it just makes the same auth
	// invocation-silent. Used by E2E + scripted operator flows.
	// Not advertised in --help; purely an escape.
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
	// Non-tty + no flag → Tier 1 refusal.
	if !req.PrintFlag {
		fmt.Fprintln(os.Stderr, "dop "+string(req.Kind)+": refusing to print secret to a non-tty.")
		fmt.Fprintln(os.Stderr, "  Why: stdout is captured by the caller, which (for LLM-driven shells)")
		fmt.Fprintln(os.Stderr, "       means the secret value lands in a transcript on disk.")
		fmt.Fprintln(os.Stderr, "  Fix (safe at a tty): use eval, e.g.")
		fmt.Fprintln(os.Stderr, "        eval \"$(dop "+shortCmd(req.Kind)+")\"")
		fmt.Fprintln(os.Stderr, "       $() captures stdout silently; eval consumes it; nothing prints.")
		fmt.Fprintln(os.Stderr, "  Fix (opt-in): pass --print-export (or --print-bearer on `token issue`)")
		fmt.Fprintln(os.Stderr, "       to force printing. You'll be asked to approve via the DOP popup.")
		return ErrRefused
	}
	// Non-tty + flag → Tier 3 approval via daemon local-popup RPC.
	// (The env-escape path above already handled the "scripted-approval"
	// case before reaching here.)
	// 60s dialog timeout.
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
	decision, reason, err := req.Client.ApprovalPopup(
		string(req.Kind),
		req.Subject,
		prompt,
		60*time.Second,
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop %s: approval RPC failed: %v\n", req.Kind, err)
		audit.Append(req.Paths, audit.Event{
			Kind:    audit.EventPrintApprovalDenied,
			Subject: req.Subject,
			Extra:   map[string]string{"surface": string(req.Kind), "reason": "rpc_error"},
		})
		return ErrRefused
	}
	switch decision {
	case "approved":
		audit.Append(req.Paths, audit.Event{
			Kind:    audit.EventPrintApprovalGranted,
			Subject: req.Subject,
			Extra:   map[string]string{"surface": string(req.Kind), "channel": "local"},
		})
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
	case "timeout":
		fmt.Fprintf(os.Stderr, "dop %s: approval dialog timed out. Retry when you're ready to approve.\n", req.Kind)
		audit.Append(req.Paths, audit.Event{
			Kind:    audit.EventPrintApprovalDenied,
			Subject: req.Subject,
			Extra:   map[string]string{"surface": string(req.Kind), "reason": "timeout"},
		})
		return ErrRefused
	case "unsupported":
		// macOS where DOP_NO_POPUP=1, or non-darwin platform.
		// For rc4 we treat unsupported as a hard refuse — the
		// tunnel+phone fallback is a future improvement (rc4b).
		fmt.Fprintf(os.Stderr, "dop %s: native approval dialog is not available on this platform.\n", req.Kind)
		if reason != "" {
			fmt.Fprintf(os.Stderr, "  reason: %s\n", reason)
		}
		fmt.Fprintln(os.Stderr, "  Future: tunnel+phone fallback will unblock this path.")
		audit.Append(req.Paths, audit.Event{
			Kind:    audit.EventPrintApprovalDenied,
			Subject: req.Subject,
			Extra:   map[string]string{"surface": string(req.Kind), "reason": "unsupported:" + reason},
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
