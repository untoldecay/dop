# Feature Contract — Audit Log + Notifications

## Scope
- Append-only JSONL log of security-relevant events, its live tail (`dop watch`), and the macOS notification hook.

## Purpose
- Give the operator a real-time picture of who did what — issue, claim, revoke, exec — without shipping observability infrastructure.

## Invariants
- MUST log to `<Logs>/audit.jsonl` (one JSON object per line).
- MUST create the log directory (`<Logs>`) with mode 0700 when missing.
- MUST create the log file with mode 0600.
- MUST never block a primary flow on audit-log failure — writes are best-effort with stderr warnings.
- MUST include these fields per event: `ts (RFC3339 UTC), event, subject?, lookup_id?, host, actor?, extra?`.

## Mandatory Behaviors
- MUST emit one event per the recognized event kinds:
  - Core (pre-rc12): `issue`, `claim_pending`, `claim`, `claim_approved`, `claim_denied` (with reason), `repin`, `revoke`, `exec`, `admin_login`, `admin_logout`.
  - v1.9: `env`, `env_denied` (exec/env refusal on bad binding).
  - v1.9: `invite`, `invite_response`, `invite_complete` (two-admin bootstrap handshake).
  - v1.11: `agent_migrated` (ed25519 → P-256 re-enrollment).
  - v1.13.0-rc12: `protected_create`, `protected_token_issue`, `protected_bypass_attempt` (see contract 15).
  - v1.14.0-rc1: `use_attached` (`dop use` attached a bearer to a shell; see contract 19). Carries `subject`, `lookup_id`, `actor`, `extra.capability_id`, `extra.disk`. NEVER the bearer value.
  - v1.14.0-rc3: `protected_unlock` (owner-initiated unlock of a protected integration or grant; mirrors `protected_create`). Carries `subject`, `extra.kind` (`"integration"` or `"grant"`), `extra.prior_owner`.
  - v1.14.0-rc3: `integration_renamed` (`dop integration rename` rewrote an integration map key and every referring grant). Carries `subject` (new name), `extra.old_name`, `extra.new_name`, `extra.referrers` (count of grants rewritten, as string).
  - v1.14.0-rc3: `exec` events gain `extra.portable_owner = "yes"` when the owner-held portable bypass skipped the binding check. Same event kind, extra field.
  - v1.14.0-rc3 (rc5 Option A): `print_approval_requested`, `print_approval_granted`, `print_approval_denied`. Fired by `internal/cli/printguard` on every print surface (`dop use`/`dop token issue`/`dop env`/`dop claim --shell`). Carries `extra.surface` ∈ {`print_use`,`print_issue`,`print_env`,`print_claim`}, `extra.channel` ∈ {`local`,`phone`,`env`,`trust_context`,`shell_trust`}, `extra.reason` on denial (`wrong_passphrase`,`verify_error`,`rejected`,`expired`,`fallback_error`), `extra.escalated_from` on phone-fallback requests.
  - v1.14.0-rc15: `integration_probed` (opt-in endpoints probe at `integration add`; see contract 17). Carries `subject` (integration name), `extra.kind`, `extra.probed_url`, `extra.endpoint_count`.
  - v1.14.0-rc16: `integration_token_set` (`dop integration set-token` rotated a value or edited scope; see contract 18). Carries `subject` (integration name), `extra.token_name`, `extra.changed` ∈ {`value`,`scope`,`both`}.
- MUST include reason strings on denial: `pin_mismatch`, `pin_expired`, `rejected`, `approval_timeout`, `admin_removed`.
- MUST fire `audit.Notify` on Darwin for `claim_pending`, `claim`, `claim_denied`, `revoke`.
- MUST honor `DOP_NO_NOTIFY=1` (used by tests + headless CI).
- `dop watch` MUST support `--since D`, `--all`, `--filter K,K,K`, `--no-color`.
- `dop watch` MUST detect log rotation via inode change or truncation and reopen.
- `dop watch` MUST poll on ≥ 400 ms tick and stream new lines as they land.
- `dop watch` MUST auto-disable ANSI colors when stdout is not a TTY.

## Forbidden Behaviors
- MUST NOT log bearers, PINs, passphrase attempts, or upstream token values — only fingerprints and metadata.
- MUST NOT rely on macOS notifications as a security boundary (best-effort UX).
- MUST NOT keep an open file descriptor for the audit log longer than a single append — every `Append` opens + writes + closes.
- MUST NOT accept an event that omits the `event` kind string.

## Interfaces
- Inputs: `audit.Event{Kind, Subject, LookupID, Host, Actor, Extra}` from every mutation site.
- Outputs: appended JSONL line; osascript notification on Darwin.
- Events: emitted by all mutation paths; consumed by `dop watch` and future `dop doctor --security`.
- Dependencies: `os/exec` for osascript (Darwin only, build-tagged files).

## State & Data Rules
- MUST rely on POSIX `O_APPEND` atomicity for writes ≤ PIPE_BUF (every event fits).
- MUST NOT truncate or rotate the log automatically — operators manage log size.
- SHOULD write extras as flat `map[string]string` for grep-friendliness.

## Acceptance Criteria
- PASS if issue/claim/revoke each add exactly one line with the correct `event` field.
- PASS if `dop watch --filter claim` only surfaces `claim` events from the backfill.
- PASS if `DOP_NO_NOTIFY=1` suppresses osascript.
- FAIL if any event line lacks a `ts` or `event` field.

## Regression Checks
- `v1_watch_audit.sh` covers issue/claim/denied/revoke events + `dop watch` backfill + filter.
- `v1_sas_approval.sh` step [6] confirms pending/approved/denied land together.

## Open Questions
- Should the audit log gain a hash-chain per-line so a same-uid truncation is detectable via `dop doctor --security`?
