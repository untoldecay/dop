# Feature Contract — `dop use <subject>`

## Scope
- The `dop use` top-level command, the `token issue --portable` flag that stashes a bearer on the capability record, the admin daemon `OpUnwrapPortable` RPC, and the `use_attached` audit event. Introduced in v1.14.0-rc1.

## Purpose
- Give admins a one-command way to attach their OWN bearer to any shell on any of their machines, without re-issuing or re-claiming. Keeps the "narrow bearer per task" scoping intent while removing the operational cost of per-shell credential handoff.

## Invariants
- A bearer is retrievable via `dop use` ONLY IF it was issued with `--portable`. Default `token issue` behavior is unchanged — the bearer leaves the admin and lives only with the agent that claims it.
- The admin-use stash (`vault.Capability.PortableWrapped`) is a base64 age-encrypted ciphertext. The plaintext is the raw bearer value.
- The stash MUST be wrapped to the ISSUING admin's age recipient. Other admins on the vault see the ciphertext but cannot decrypt it.
- `dop use` MUST require an unlocked admin session on the local machine. Without the daemon's age identity, the stash can't be decrypted.
- The bearer value MUST NEVER appear in audit logs, stderr, or any file other than `--token-file` or stdout.

## Mandatory Behaviors

### CLI — `dop use`
- Usage: `dop use [--token-file FILE] <subject>`
- MUST resolve `<subject>` to exactly one ACTIVE capability. Zero matches or multiple matches MUST exit 1 with a clear error.
- MUST refuse (exit 1) when the capability has an empty `PortableWrapped`, with a hint pointing at `--portable`.
- MUST refuse (exit 1) when the session is locked, pointing operator at `dop admin login`.
- MUST refuse (exit 1) when any grant carried by the bearer is protected and the current admin pubkey isn't the owner (rc12 gate reused).
- Default output: `export DOP_TOKEN=<bearer>\n` to stdout. Nothing else to stdout. Operator pattern: `eval "$(dop use <subject>)"`.
- With `--token-file FILE`: writes a JSON envelope `{token, subject, issued_at, expires_at}` to FILE with mode 0600, prints a short confirmation to stderr, nothing to stdout.
- The `--token-file` TTL (default 24h) is embedded in the file's `expires_at`. Readers (future `dop exec` extensions, etc.) MAY refuse an expired file.
- MUST emit `EventUseAttached` on success. Fields: `Subject`, `LookupID`, `Actor` (short admin pubkey), `Extra.capability_id`, `Extra.disk` (bool-as-string).

### `token issue --portable`
- MUST require an active admin session (needs `client.Status().AgeRecipient`).
- MUST age-wrap the freshly-minted bearer value to the session admin's age recipient via `admin.WrapToRecipient`.
- MUST store the base64 ciphertext on the capability's `PortableWrapped` field BEFORE calling `saveVaultViaDaemon`.
- MUST preserve `PortableWrapped` through subsequent `syncSidecars` round-trips (which otherwise re-materialize `vault.Capability` from `capability.Record` and would drop the field).
- MUST NOT change the bearer handoff printed to stderr — the normal "bearer (shown ONCE — copy now):" output still fires. The stash is additional, not a replacement.
- Setting `--portable` alongside `--protected` grants MUST still enforce the normal protection passphrase gate at issue time.

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
- Inputs: `--portable` boolean flag on `dop token issue`; `--token-file FILE` + `--passphrase-stdin` (reserved) flags on `dop use`; `<subject>` positional on `dop use`.
- Outputs: stdout `export DOP_TOKEN=…` line OR a token-file JSON envelope; stderr informational text; audit event.
- Events: `EventUseAttached` with the fields enumerated above.
- Dependencies: `internal/admin.Client.UnwrapPortable` + `.Status`, `internal/admin.WrapToRecipient` + `.UnwrapWithIdentity`, `internal/vault.Capability.PortableWrapped`, `internal/audit.Append`, `cmd/dop/protected.go` for the owner gate pattern.

## State & Data Rules
- `vault.Capability.PortableWrapped` MUST serialize via `yaml:"portable_wrapped,omitempty" json:"portable_wrapped,omitempty"` — pre-rc1 vaults round-trip unchanged.
- The stash lives ONLY on the capability record. There is no sidecar, no separate file, no admin-local keychain entry. Vault pull carries it; vault push publishes it (encrypted-at-rest alongside the whole SOPS payload).
- `PortableWrapped` is NOT part of the capability's signature (unlike `EnvWrapped`/`BearerWrapped` which are). It's admin-only; agents never see it; signing it would be noise.
- `syncSidecars` MUST read the vault's current `PortableWrapped` before the `capability2VaultCapability(rec)` conversion and reapply it after. Tested implicitly by the round-trip e2e steps.
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
- Verify `cmd/dop/tokencmd.go::runTokenIssue` preserves `stored.PortableWrapped` after setting it (store the whole struct back; don't overwrite partially).
- Verify `cmd/dop/tokencmd.go::syncSidecars` saves + restores the stash across the `vaultCapability2Record` → `capability2VaultCapability` round-trip (preservedStash pattern).
- Verify `cmd/dop/usecmd.go::checkCapabilityProtection` applies the rc12 owner check on EVERY grant carried by the bearer, not just the first.
- Verify `internal/admin/session.go::opUnwrapPortable` fails cleanly when `s.keys == nil` (session locked).
- Verify no file outside `--token-file`'s target ever contains the plaintext bearer.

## Open Questions
- Should `dop use` also accept a `--eval` flag that outputs ONLY the token value (no `export` wrapper), for scripts that construct their own env? Not implemented; low priority.
- Should token-file readers verify `expires_at` server-side (via a daemon RPC)? Currently client-side only; good enough.
- Should the token-file auto-reap on `dop admin logout` (same mechanism as pending-claim reaper)? Deferred.
- Should the stash be removed when the bearer is revoked? Currently stays on the revoked capability record (harmless; the bearer no longer works). Could clean up during cascade.

## Related contracts
- **03 (Vault Schema)** — adds `PortableWrapped` to the Capability shape.
- **04 (Capability Envelope)** — notes that `PortableWrapped` is distinct from `EnvWrapped`/`BearerWrapped` (admin-only vs agent-facing).
- **07 (Approval Gate)** — the approval passphrase is NOT consumed by `dop use` v1; the admin daemon unlock is the gate. If a future `--passphrase-stdin` phase lands, it becomes a second gate.
- **10 (Audit Log)** — adds `use_attached` event kind.
- **15 (Protected Credentials)** — the owner check for protected bearers is reused by `dop use`.
