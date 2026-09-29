# Audit & Notifications

**Date:** 2026-09-29
**Contracts:** [`10_audit_log.md`](../_requirements/contracts/10_audit_log.md), [`08_web_approval_flow.md`](../_requirements/contracts/08_web_approval_flow.md)

Live visibility into what DOP is doing, on both admin and agent hosts. `dop watch` is the primary console; macOS notifications catch you when you're away.

---

## Commands

### `dop watch`
`apps/dop/cmd/dop/watchcmd.go:15`

Tails the audit log with color-coded events. Reads `<Logs>/audit.jsonl` and follows for appends.

```bash
dop watch                                # follow with 24h backfill
dop watch --all                          # from the start of the log
dop watch --since 1h                     # only events from the last hour
dop watch --filter claim,claim_pending   # only these event kinds
dop watch --no-color                     # for pipes / dumb terminals
dop watch --follow=false                 # print backfill and exit
```

Detects log rotation (inode change or truncation) and reopens automatically.

Color palette:
- **green bold** — `claim` (success)
- **red bold** — `claim_denied`
- **cyan** — `issue`
- **yellow** — `repin`
- **red** — `revoke`
- **blue** — `admin_login` / `admin_logout`

Auto-disables color when stdout is not a TTY.

---

## Log file

Location: `<Logs>/audit.jsonl` (mode 0600 in a 0700 dir).  
Format: one JSON object per line.

```json
{"ts":"2026-09-29T22:11:04Z","event":"claim","subject":"research-agent","lookup_id":"b3d01fad...","host":"cam-mbp","actor":"0f39638e...","extra":{"generation":"2"}}
```

Fields:
- `ts` — RFC3339 UTC.
- `event` — event kind (see below).
- `subject` — capability subject (when relevant).
- `lookup_id` — 40-hex bundle identifier.
- `host` — `os.Hostname()`.
- `actor` — the agent's ed25519 pubkey (on claim events) or admin pubkey (on issue/revoke).
- `extra` — flat `map[string]string` for kind-specific context.

## Event kinds

| Kind | Emitted by |
|---|---|
| `issue` | `dop token issue` |
| `claim_pending` | `dop claim` at server-up |
| `claim` | `dop claim` on success |
| `claim_approved` | `dop approve` (CLI or web) |
| `claim_denied` | `dop claim` on failure (reason in extras) |
| `repin` | `dop token repin` |
| `revoke` | `dop token revoke` or `dop team remove --force` |
| `exec` | `dop exec` on success |
| `admin_login` / `admin_logout` | (reserved — currently not emitted) |

Denial reasons: `pin_mismatch`, `pin_expired`, `rejected`, `approval_timeout`, `admin_removed`.

## What the log does NOT contain

- No bearers, PINs, or passphrase attempts. Only fingerprints and reasons.
- No upstream token values.
- No env values that `dop exec` injects into children.

The exec event carries `env_keys` (count) but not the values or the key names — enough to spot activity, not enough to leak secrets.

---

## macOS notifications

`internal/audit/notify_darwin.go` fires an `osascript` banner for:
- `claim_pending` — "approval needed — SAS XX-XX-XX"
- `claim` — "agent bound — <subject> claimed a bearer"
- `claim_denied` — "claim denied — <subject>: <reason>"
- `revoke` — "revoked — <subject> was revoked"

Set `DOP_NO_NOTIFY=1` to disable (tests do this).

On Linux the `notify_other.go` build-tagged file makes `Notify` a no-op. A future `notify_linux.go` could shell to `notify-send`.

---

## Best practices

- Keep `dop watch` open in a corner terminal. Every `claim_pending` line is a signal that an agent is asking to bind.
- Use `--filter claim,revoke` to reduce noise once you're comfortable.
- Log rotation is manual (`> audit.jsonl` or `logrotate`). `dop watch` will follow through it.
- The audit log is append-only via `O_APPEND` but not tamper-proof — a same-uid attacker can still truncate. Merkle-lite hash chain is a v2 candidate.

---

## Dependencies

- `encoding/json`, `bufio`, `os/signal`, `syscall` (for follow-mode stat + inode).
- `osascript` on Darwin (system, no install).

---

## Next steps

- Merkle-lite chain: each line embeds the sha256 of the previous line, checked by `dop doctor --security`.
- Structured `exec` events (add pid, exit code, duration once we don't `syscall.Exec` inline).
- Linux `notify-send` port.
- Log-size warning in `dop doctor` when `audit.jsonl` exceeds a threshold.
