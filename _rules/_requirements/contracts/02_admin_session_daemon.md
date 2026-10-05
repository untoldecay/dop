# Feature Contract — Admin Session Daemon

## Scope
- The forked-off `dop admin __session-daemon` process, its unix socket, RPCs, and TTL semantics.

## Purpose
- Hold the unwrapped admin keys in one long-lived process so subsequent admin commands don't re-prompt the passphrase — sudo-style.

## Invariants
- MUST run as the same uid as the CLI that spawned it.
- MUST hold the wrapped keys in memory only after a successful `Unwrap`, never persist them unencrypted.
- MUST bind exactly one unix socket at `SockPath(paths)` per user session.
- MUST refuse any socket connection whose peer uid ≠ daemon uid.
- MUST expire the session when either the idle-TTL or the absolute-TTL is exceeded.

## Mandatory Behaviors
- MUST create the socket file mode 0600 inside a mode-0700 parent directory.
- MUST verify peer credentials via `LOCAL_PEERCRED` (Darwin) or `SO_PEERCRED` (Linux) on every connection.
- MUST bump the idle timer on every non-`status` RPC.
- MUST NOT extend the idle timer on `status` calls (avoids polling keeping the session alive forever).
- MUST shut down cleanly on `logout`, removing the socket file and zeroing key material.
- MUST expose these RPCs: `status`, `keep_alive`, `logout`, `sign`, `decrypt_vault`, `encrypt_vault`, `unwrap_portable` (rc1 — age-unwrap of stashed bearer; see contract 19), `shared_secret` (v1.12 — ECDH for direct-availability; see contract 04), `approval_popup` (rc5b — osascript dialog on daemon side), `shell_trust` (rc6; legacy, see `trust_context`), `trust_context` (rc6i — grant cache check/mark/list/revoke; see contract 20).
- MUST cap message size at 10 MB per frame.

## Forbidden Behaviors
- MUST NOT accept connections without a peer-cred check.
- MUST NOT log or return the unwrapped `age` secret or ed25519 private key over any RPC.
- MUST NOT persist keys to disk after `Unwrap`.
- MUST NOT allow multiple concurrent daemons on the same socket path.

## Interfaces
- Inputs: length-prefixed JSON (`ReadMessage`) — `{op: string, data: raw json}`.
- Outputs: `{ok: bool, error?: string, data?: raw json}`.
- Events: `admin_login`, `admin_logout` audit events; socket file lifecycle.
- Dependencies: `filippo.io/age` for scrypt-wrap of keys, `sops` binary for vault decrypt/encrypt.

## State & Data Rules
- MUST store `startedAt`, `lastActivity`, `idleTTL`, `absTTL` in the `Session` struct.
- MUST NOT persist any of these across restart — every daemon start is a fresh session.
- MUST derive `IdleTTL` from `$DOP_ADMIN_TTL` (default 15 min) and `AbsTTL` from `$DOP_ADMIN_MAX_TTL` (default 60 min).
- rc7l — `performAdminLogin` MUST set `DOP_ADMIN_TTL` from `userprefs.EffectiveAdminIdleTTL()` on the daemon fork when the pref is non-zero. Operators who pick "never" via Settings get a 100-year sentinel; pre-rc7l shell exports of `DOP_ADMIN_TTL` keep working when prefs are unset.

## Acceptance Criteria
- PASS if `SessionActive()` returns true only when the socket exists AND a status RPC succeeds.
- PASS if `logout` closes the socket and subsequent `SessionActive()` returns false.
- FAIL if a socket connection from a different uid gets a valid response instead of `peer uid mismatch`.
- FAIL if a status ping-loop extends the session beyond idle TTL.

## Regression Checks
- Verify `v1_admin_session.sh` covers login → keep-alive → idle expiry → logout.
- Verify `dop admin login` refuses when a socket is already active.
- Verify the socket path length stays under `SUN_PATH_MAX` on macOS (~104 bytes).

## Open Questions
- Should the daemon support explicit re-authentication (`dop admin reauth`) instead of requiring logout + login on passphrase rotation?
