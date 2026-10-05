# Feature Contract — Trust Context Cache + Harness Adapters

## Scope
- Daemon-held approval cache keyed on an operator-approved execution context.
- CLI-side resolver that discovers the context from env + runtime signals.
- Harness picker surfaces (first-start wizard, Settings) that persist the operator's choice.

## Purpose
- Burst `dop use` / `dop env` calls in the same conversation share one approval popup.
- The resolver MUST pick a stable identifier so cache hits land correctly across LLM-driven shells.

## Invariants
- MUST key cache entries on `<ContextKind>:<ContextValue>:<Subject>` so values from different sources never collide.
- MUST namespace harness values per adapter (`claude:<id>`, `codex:<id>`, `opencode:<id>`).
- MUST expire grants after idle TTL (daemon-side). Logout clears all grants.
- MUST only serve the cache fast-path when `KindUse` or `KindEnv` AND stdout is NOT a tty.
- MUST NOT allow mutation surfaces (`token issue`, `claim --shell`, grant mutations) to hit the cache.
- MUST reject session-id values with control characters or > 256 bytes.

## Mandatory Behaviors
- MUST resolve the trust context in this precedence order:
  1. `DOP_SESSION_ID` (explicit, caller-provided)
  2. recognized harness env var when `DOP_HARNESS` or `userprefs.Harness` selects it
  3. controlling tty via fstat Rdev (NOT `os.File.Name()`)
  4. `getsid(0)` from `golang.org/x/sys/unix.Getsid`
  5. `getppid()` as compatibility floor
- MUST read harness mode from `DOP_HARNESS` env; legacy `DOP_INFER_HARNESS_SESSION=1` MUST alias to `DOP_HARNESS=any`.
- MUST support harness values: `claude-code`, `codex`, `opencode`, `any`, `none`, `manual`.
- MUST surface the context source via `dop trust context` without printing the raw value.
- MUST support `dop trust list` (grants + metadata) and `dop trust revoke [--all] [KIND VALUE SUBJECT]`.
- CLI entry points (`printguard`, `dop trust context`) MUST set `DOP_HARNESS` from `userprefs.Harness` before calling the resolver.
- First-start wizard in `dop admin init` + `dop admin join` MUST offer the harness picker as the final step; esc MUST skip (prefs stay empty).
- Settings view MUST include the harness picker using the standard list→picker pattern.

## Forbidden Behaviors
- MUST NOT key on `$TERM`, `isatty(stdin/stdout/stderr)`, or `$DISPLAY` for the resolver.
- MUST NOT promote arbitrary env vars to trust identity without a vetted adapter.
- MUST NOT persist grant data to disk — in-memory only, cleared on daemon exit.

## Interfaces
- Inputs: `DOP_SESSION_ID`, `DOP_HARNESS`, `DOP_INFER_HARNESS_SESSION`, `CLAUDE_CODE_SESSION_ID`, `CODEX_THREAD_ID`, `OPENCODE_SESSION_ID`, `userprefs.Harness`
- Outputs: `sessiontrust.Context{Kind, Value}`, grant records in daemon memory
- Events: `print_approval_granted` with `extra.channel="trust_context"` + `extra.context_kind` on cache hits
- Dependencies: `internal/sessiontrust`, `internal/admin/session.go::opTrustContext`, `cmd/dop/trustcmd.go`, `internal/userprefs`

## State & Data Rules
- MUST store `TrustGrant{ContextKind, ContextValue, Subject, CreatedAt, LastUsedAt, Source}`.
- MUST sweep expired grants on every op (idle TTL evaluated at check time; no background sweeper).
- MUST update `LastUsedAt` on each successful `check`.
- MUST serialize grant listings deterministically (sorted by kind then subject) for `dop trust list`.

## Acceptance Criteria
- PASS if second `eval "$(dop use CamShell)"` in the same Claude Code conversation skips the approval popup (with `DOP_HARNESS=claude-code` set via Settings).
- PASS if `dop trust context` prints the resolver's descriptive label without printing the raw session id value.
- PASS if `dop admin logout` immediately drops every cached grant (next `dop use` re-prompts).
- PASS if `DOP_HARNESS=none` skips the harness branch even when a recognized harness env var is set.
- FAIL if two different harness env vars holding the same UUID collide in the cache (namespace must prevent this).
- FAIL if the resolver returns `tty:/dev/stdin` or similar hardcoded Go-stdio label as the TTY value.

## Regression Checks
- Verify `go test ./internal/sessiontrust/...` covers all precedence paths including rejection of control chars + overlong values.
- Verify `dop trust list` after an approval popup shows exactly one row matching the operator's harness choice.
- Verify idle TTL purge: a grant whose `LastUsedAt + idleTTL < now` MUST be absent from `dop trust list` without any explicit revoke.
- Verify `GOOS=linux go build ./...` succeeds (resolver uses `unix.Getsid`, not `syscall.Getsid`).

## Open Questions
- Idle TTL is currently hardcoded (30min). Should it move to `userprefs`?
- Should the `DOP_INFER_HARNESS_SESSION` deprecation hard-remove in v1.15 or stay as doc-only no-op?
