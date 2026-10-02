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
	EventRevoke        = "revoke"
	EventExec          = "exec"
	// v1.9.7 — `dop env` (like exec) surfaces plaintext values,
	// so it now enforces + audits the same binding gate.
	EventEnv       = "env"
	EventEnvDenied = "env_denied"
	EventAdminLogin    = "admin_login"
	EventAdminLogout   = "admin_logout"
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
	// v1.13.0-rc15 — endpoints doc probe at `integration add` time.
	// Opt-in via --probe-endpoints. One event per run (success OR
	// failure). Lets operators audit "did DOP make an outbound HTTP
	// call on my behalf, and what did it find?"
	EventIntegrationProbed = "integration_probed"
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
