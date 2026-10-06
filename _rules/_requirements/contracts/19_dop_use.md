# Feature Contract — `dop use <subject>`

## Scope
- The `dop use` top-level command, the `token issue --portable` flag, the `dop token portable --on|--off` toggle for existing bearers, the admin daemon `OpUnwrapPortable` RPC, the `use_attached` / `portable` audit events, and the TUI portable surfaces. Introduced in v1.14.0-rc1.

## Purpose
- Give admins a one-command way to attach their OWN bearer to any shell on any of their machines, without re-issuing or re-claiming. Keeps the "narrow bearer per task" scoping intent while removing the operational cost of per-shell credential handoff.

## Invariants
- A bearer is retrievable via `dop use` ONLY IF it carries a stash: issued with `--portable`, re-issued by `dop token portable --on`, or re-issued (repin) from a bearer that had one. Default `token issue` behavior is unchanged — the bearer leaves the admin and lives only with the agent that claims it.
- The admin-use stash (`vault.Capability.PortableWrapped`) is a base64 age-encrypted ciphertext. The plaintext is the raw bearer value.
- The stash MUST be wrapped to the ISSUING admin's age recipient. Other admins on the vault see the ciphertext but cannot decrypt it.
- `dop use` MUST require an unlocked admin session on the local machine. Without the daemon's age identity, the stash can't be decrypted.
- The bearer value MUST NEVER appear in audit logs, stderr, or any file other than `--token-file` or stdout.

## Mandatory Behaviors

### CLI — `dop use`
- Usage: `dop use [--token-file FILE] <subject>`
- MUST resolve `<subject>` to exactly one ACTIVE capability. Zero matches or multiple matches MUST exit 1 with a clear error.
- MUST refuse (exit 1) when the capability has an empty `PortableWrapped`, with a hint pointing at `--portable`.
- When the session is locked, MUST call `requireAdminSessionOrUnlock` which pops the native osascript dialog on darwin + GUI reachability (`launchctl managername == Aqua` AND `/dev/console` uid matches). On operator approve → session re-active → flow continues. On cancel / dialog unavailable / non-darwin → exit 1 pointing operator at `dop admin login`.
- MUST refuse (exit 1) when any grant carried by the bearer is protected and the current admin pubkey isn't the owner (rc12 gate reused).
- Default output: `export DOP_TOKEN=<bearer>\n` to stdout. Nothing else to stdout. Operator pattern: `eval "$(dop use <subject>)"`.
- MUST route the print through `printguard.Guard` (approval always, rc5 Option A). See contract 07. Second `dop use` call in the same trust-context session skips the popup via the trust-context cache (contract 20).
- v1.14.0-rc6h — `--print-export` is **DEPRECATED**. Parsed for backward-compat with pre-rc6h scripts; emits a one-line stderr deprecation warning when set. Has no effect on gating (printguard requires approval regardless of flag).
- With `--token-file FILE`: writes a JSON envelope `{token, subject, issued_at, expires_at}` to FILE with mode 0600, prints a short confirmation to stderr, nothing to stdout.
- The `--token-file` TTL (default 24h) is embedded in the file's `expires_at`. Readers (future `dop exec` extensions, etc.) MAY refuse an expired file.
- MUST emit `EventUseAttached` on success. Fields: `Subject`, `LookupID`, `Actor` (short admin pubkey), `Extra.capability_id`, `Extra.disk` (bool-as-string).

### `token issue --portable`
- MUST require an active admin session (needs `client.Status().AgeRecipient`).
- MUST age-wrap the freshly-minted bearer value to the session admin's age recipient via `admin.WrapToRecipient`.
- MUST store the base64 ciphertext on the capability's `PortableWrapped` field BEFORE calling `saveVaultViaDaemon`.
- MUST preserve `PortableWrapped` through every later record rewrite (revoke, repin, reseal, grant edits, rotate, cascade, claim, remote approve, agent migrate, `syncSidecars`): all go through `putCapability`, which carries the stash from the existing entry.
- MUST NOT change the bearer handoff printed to stderr — the normal "bearer (shown ONCE — copy now):" output still fires. The stash is additional, not a replacement.
- Setting `--portable` alongside `--protected` grants MUST still enforce the normal protection passphrase gate at issue time.

### `dop token portable --subject S (--on | --off) [--passphrase-stdin]`
- Exactly one of `--on` / `--off` (usage error, exit 2, otherwise). Subject MUST resolve to one active bearer.
- `--on` MUST re-issue (DOP never keeps the bearer it handed out, so it cannot wrap the existing one). Path by binding state, rules in contract 25:
  - claimed: rotated in place (`rotateBearer` with the session age recipient); the agent picks up the new bearer on its next exec; stdout `portable copy stored for <S>`; no bearer printed.
  - unclaimed PIN-bound or unbound: new bearer (+ new PIN, `defaultPinTTL`), old revoked in the same save (`reissueUnclaimed`); bearer + PIN printed once on stdout.
- `--on` MUST refuse an expired bearer and MUST ask the approval passphrase only when the bearer carries protected grants (`gateProtectedGrants`).
- `--off` MUST always ask the approval passphrase, clear `PortableWrapped` without re-signing (the stash is outside the signed record), keep the bearer working, print `portable copy removed for <S>`.
- Both MUST emit `portable` (`extra.portable` = `on` / `off`; `extra.replaces` on `on`).

### TUI
- Issue wizard MUST have a Portable step (`portablePresets`: no default / yes).
- Bearer detail MUST offer `Portable: make portable` when the stash is empty and `Portable: remove copy` when set (`listView.currentActions`), each behind a confirm that states the consequence (claimed: the agent keeps working; unclaimed: a new bearer and PIN are shown once) and a passphrase step when needed (`portNeedsPass`).
- The re-issue result MUST land on the shown-once screen (unclaimed) or `✓ Bearer is portable` (claimed), with `useGuidance` lines (contract 13): Claude Code harness gets the skill-install line (when missing) and `/dop-use <S> <task>`; every harness gets `eval "$(dop use <S>)"`.

### Admin daemon RPC
- `OpUnwrapPortable` MUST require session unlocked (same as `OpSign` / `OpDecryptVault`).
- MUST use the daemon's in-memory age identity (`s.keys.Age`), never leaving the process.
- MUST return plaintext as base64 (`UnwrapPortableResp.PlaintextB64`), mirroring the `DecryptVaultResp` convention.
- MUST NOT log plaintext anywhere.

## Forbidden Behaviors
- MUST NOT allow `dop use` to retrieve a bearer whose `PortableWrapped` is empty.
- MUST NOT allow a non-owner to retrieve a bearer that carries protected grants, even if they are a valid admin on the vault.
- MUST NOT print the bearer to stderr; stdout is reserved for the eval-able export line only.
- MUST NOT log the bearer value in audit events, log messages, error messages, or `--token-file` content outside the JSON `token` field.
- MUST NOT accept the bearer value on the command line via a flag — the `token-file` path is write-only; reading a bearer back into a shell happens via env var or env-var-pointing-at-a-file.
- MUST NOT auto-renew `--token-file` files past their `expires_at` without an explicit `dop use` re-invocation.
- MUST NOT wrap the bearer to any recipient other than the ISSUING admin's own age recipient.

## Interfaces
- Inputs: `--portable` boolean flag on `dop token issue`; `--subject`, `--on`, `--off`, `--passphrase-stdin` on `dop token portable`; `--token-file FILE` + `--print-export` + `--passphrase-stdin` (reserved) flags on `dop use`; `<subject>` positional on `dop use`.
- Outputs: stdout `export DOP_TOKEN=…` line OR a token-file JSON envelope; stderr informational text; audit event.
- Events: `EventUseAttached` with the fields enumerated above; `EventPortable` on the toggle.
- Dependencies: `internal/admin.Client.UnwrapPortable` + `.Status`, `internal/admin.WrapToRecipient` + `.UnwrapWithIdentity`, `internal/vault.Capability.PortableWrapped`, `internal/audit.Append`, `cmd/dop/protected.go` for the owner gate pattern.

## State & Data Rules
- `vault.Capability.PortableWrapped` MUST serialize via `yaml:"portable_wrapped,omitempty" json:"portable_wrapped,omitempty"` — pre-rc1 vaults round-trip unchanged.
- The stash lives ONLY on the capability record. There is no sidecar, no separate file, no admin-local keychain entry. Vault pull carries it; vault push publishes it (encrypted-at-rest alongside the whole SOPS payload).
- `PortableWrapped` is NOT part of the capability's signature (unlike `EnvWrapped`/`BearerWrapped` which are). It's admin-only; agents never see it; signing it would be noise.
- `syncSidecars` and every other rewrite MUST write records via `putCapability` (never a bare `capability2VaultCapability` on an existing id). Tested by `TestPutCapabilityKeepsPortableStash`.
- Token file format: `{"token", "subject", "issued_at", "expires_at"}` as pretty-printed JSON. Mode 0600 (chmod'd twice: once on open flags, once explicit after write, to defeat umask).

## Acceptance Criteria
- PASS if `testdata/e2e/v1_1400_dop_use.sh` passes (8 steps covering refusal without stash, happy path, env works, token-file, unknown subject, locked session, no bearer leak in audit).
- PASS if `go test ./internal/admin/` passes (round-trip + wrong-identity + bad-recipient coverage of `WrapToRecipient` / `UnwrapWithIdentity`).
- PASS if a vault that previously had no `PortableWrapped` fields round-trips through save unchanged (no spurious `portable_wrapped:` keys appear).
- PASS if `dop use <subject>` with `grep DOP_TOKEN` in output grants shell access to the bearer's env on `dop env`.
- PASS if the audit log line for `use_attached` doesn't contain the token value (`grep "$TOKEN" audit.jsonl` returns nothing).
- FAIL if any mutation of `syncSidecars` drops `PortableWrapped` from a capability it was previously set on.
- FAIL if `dop use` prints anything to stdout other than the single export line.
- FAIL if `token issue --portable` is accepted without an active admin session.

## Regression Checks
- Verify `cmd/dop/tokencmd.go::issueBearer` preserves `stored.PortableWrapped` after setting it (store the whole struct back; don't overwrite partially).
- Verify `go test ./cmd/dop -run 'TestTokenPortable|TestPutCapability'` passes.
- Verify `cmd/dop/usecmd.go::checkCapabilityProtection` applies the rc12 owner check on EVERY grant carried by the bearer, not just the first.
- Verify `internal/admin/session.go::opUnwrapPortable` fails cleanly when `s.keys == nil` (session locked).
- Verify no file outside `--token-file`'s target ever contains the plaintext bearer.

## Open Questions
- Should `dop use` also accept a `--eval` flag that outputs ONLY the token value (no `export` wrapper), for scripts that construct their own env? Not implemented; low priority.
- Should token-file readers verify `expires_at` server-side (via a daemon RPC)? Currently client-side only; good enough.
- Should the token-file auto-reap on `dop admin logout` (same mechanism as pending-claim reaper)? Deferred.
- Should the stash be removed when the bearer is revoked? Currently stays on the revoked capability record (harmless; the bearer no longer works). Could clean up during cascade.

## Exec plane interaction (v1.14.0-rc3)

- When the owning admin invokes `dop exec` with a portable bearer in `DOP_TOKEN`, exec MUST skip the agent-plane binding check. The three preconditions ALL hold: admin session active + vault capability has `PortableWrapped != ""` + capability `IssuedBy == session.AdminPubkey`. Any precondition miss falls through to standard `verifyBinding`.
- Signature verification, generation / expiry / status, and scope filtering all continue to apply. Only the binding (claim + agent-key) step is skipped.
- Exec audit event MUST carry `Extra["portable_owner"] = "yes"` when the bypass fires. Same event kind (`exec`), extra field — the trail stays self-describing without introducing `exec_portable`.
- A non-owner holding plaintext `DOP_TOKEN` manually cannot reach the bypass: vault lookup returns their-not-mine for `IssuedBy`, helper returns false, standard binding gate applies.

## Related contracts
- **03 (Vault Schema)** — adds `PortableWrapped` to the Capability shape.
- **04 (Capability Envelope)** — notes that `PortableWrapped` is distinct from `EnvWrapped`/`BearerWrapped` (admin-only vs agent-facing).
- **07 (Approval Gate)** — the approval passphrase is NOT consumed by `dop use` v1; the admin daemon unlock is the gate. If a future `--passphrase-stdin` phase lands, it becomes a second gate.
- **10 (Audit Log)** — adds `use_attached` and `portable` event kinds.
- **13 (Handoff Text Shape)** — the `useGuidance` block on done screens.
- **25 (Bearer Re-issue)** — `portable --on` re-issue path and stash carry-over.
- **15 (Protected Credentials)** — the owner check for protected bearers is reused by `dop use`.
