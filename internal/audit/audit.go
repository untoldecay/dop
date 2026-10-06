// Package audit writes an append-only JSONL log of security-relevant
// DOP events. `dop watch` tails it; `dop doctor` can surface counts.
//
// One event per line. Writes rely on POSIX O_APPEND atomicity for
// writes ≤ PIPE_BUF (4096), which every event comfortably fits under —
// no explicit locking needed.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/fray/dop/internal/config"
)

// Event kinds. Keep short; `dop watch` colorizes by string.
const (
	EventIssue         = "issue"
	EventClaim         = "claim"
	EventClaimPending  = "claim_pending"
	EventClaimApproved = "claim_approved"
	EventClaimDenied   = "claim_denied"
	EventRepin         = "repin"
	EventPortable      = "portable" // portable stash stored or removed
	EventRevoke        = "revoke"
	EventRotate        = "rotate"        // claimed bearer rotated in place
	EventPrune         = "prune"         // old revoked/rotated records deleted (extra: count, lookup_ids)
	EventInviteCancel  = "invite_cancel" // pending admin invite deleted
	EventExec          = "exec"
	// v1.9.7 — `dop env` (like exec) surfaces plaintext values,
	// so it now enforces + audits the same binding gate.
	EventEnv         = "env"
	EventEnvDenied   = "env_denied"
	EventAdminLogin  = "admin_login"
	EventAdminLogout = "admin_logout"
	// v1.9 — admin-invite bootstrap.
	EventInvite         = "invite"          // M1 opens an invite
	EventInviteResponse = "invite_response" // M2 replies
	EventInviteComplete = "invite_complete" // M1 accepts, admin added
	// v1.11 — agent key operations.
	EventAgentMigrated = "agent_migrated" // ed25519 → P-256 re-enrollment
	// v1.13.0-rc12 — protected credentials (owner-locked integrations
	// + their grants). Any admin can see these events; they're the
	// trust-but-verify half of the Shape B design.
	EventProtectedCreate        = "protected_create"         // integration or grant marked protected
	EventProtectedTokenIssue    = "protected_token_issue"    // bearer issued containing a protected grant
	EventProtectedBypassAttempt = "protected_bypass_attempt" // daemon reverted a non-owner's protected mutation
	// v1.14.0-rc3 — owner-initiated unlock. Mirrors EventProtectedCreate
	// so the audit trail is symmetric: every protect transition logs,
	// in either direction. Fires only on actual true→false flips.
	EventProtectedUnlock = "protected_unlock"
	// v1.13.0-rc15 — endpoints doc probe at `integration add` time.
	// Opt-in via --probe-endpoints. One event per run (success OR
	// failure). Lets operators audit "did DOP make an outbound HTTP
	// call on my behalf, and what did it find?"
	EventIntegrationProbed = "integration_probed"
	// v1.13.0-rc16 — `dop integration set-token` mutations. Fires on
	// every value rotation + every scope-note edit. Carries flags
	// `rotated`/`scope_changed` (both bool-as-string) and the token
	// name; NEVER the new value.
	EventIntegrationTokenSet = "integration_token_set"
	// v1.14.0-rc1 — `dop use <subject>` attached a bearer to a shell.
	// Carries `subject`, `by` (admin pubkey short-form), `disk`
	// (bool-as-string: did it write to --token-file). NEVER the
	// bearer value.
	EventUseAttached = "use_attached"
	// v1.14.0-rc3 — `dop integration rename` emits a single event with
	// old_name + new_name + referrers (count of grants rewritten).
	// Fires once per rename; the rename itself is atomic at save time.
	EventIntegrationRenamed = "integration_renamed"
	// `dop integration rename-token` renamed a credential and rewrote the
	// grants that used it. Subject = integration; extra.from, extra.to,
	// extra.grants (count rewritten, as string).
	EventTokenRename = "token_rename"
	// v1.14.0-rc4 — Tier 3 approval events for secret-print surfaces.
	// Emitted by `internal/cli/printguard` around the approval dialog.
	// Requested fires before the dialog opens so a hung dialog still
	// leaves a trail. Granted / Denied fires after the decision; the
	// Extra["channel"] field is "local" (osascript popup) or "phone"
	// (tunnel fallback) once the fallback ships. Extra["surface"] is
	// the printguard.Kind ("print_use" / "print_issue" / "print_env" /
	// "print_claim"). Extra["reason"] carries "wrong_passphrase",
	// "timeout", "rpc_error", "unsupported:…" when denied.
	EventPrintApprovalRequested = "print_approval_requested"
	EventPrintApprovalGranted   = "print_approval_granted"
	EventPrintApprovalDenied    = "print_approval_denied"
)

// Event is one line in the log.
type Event struct {
	TS       time.Time         `json:"ts"`
	Kind     string            `json:"event"`
	Subject  string            `json:"subject,omitempty"`
	LookupID string            `json:"lookup_id,omitempty"`
	Host     string            `json:"host,omitempty"`
	Actor    string            `json:"actor,omitempty"` // admin pubkey (short) or "agent"
	Extra    map[string]string `json:"extra,omitempty"`
}

// Append writes one event to $Logs/audit.jsonl. Never returns an error
// to the caller — auditing must not block the primary flow. Failures
// are silently swallowed but leave a trace on stderr for `dop doctor`.
func Append(paths *config.Paths, e Event) {
	if e.TS.IsZero() {
		e.TS = time.Now().UTC().Truncate(time.Second)
	}
	if e.Host == "" {
		h, _ := os.Hostname()
		e.Host = h
	}
	if err := paths.EnsureDirs(); err != nil {
		return
	}
	path := filepath.Join(paths.Logs, "audit.jsonl")
	line, err := json.Marshal(e)
	if err != nil {
		return
	}
	line = append(line, '\n')
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop audit: open log: %v\n", err)
		return
	}
	if _, err := f.Write(line); err != nil {
		fmt.Fprintf(os.Stderr, "dop audit: write: %v\n", err)
	}
	f.Close()
	Notify(e)
}

// Path returns the audit-log file path (for `dop watch`, `dop doctor`).
func Path(paths *config.Paths) string {
	return filepath.Join(paths.Logs, "audit.jsonl")
}
