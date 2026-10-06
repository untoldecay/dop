# Feature Contract — Credential + Bearer Lifecycle

## Scope
- Credentials (upstream secrets inside an integration; `vault.Token`, CLI flag names still say `token`): `dop integration set-token`, `dop integration rename-token`, the TUI integration Credentials tab, `EventIntegrationTokenSet` and `EventTokenRename`. Introduced in v1.13.0-rc16.
- Bearers (what an agent holds): the `dop token` subcommand set and the rule that every bearer record rewrite keeps the portable stash.

## Vocabulary
- TUI copy MUST say credential (upstream secret), bearer (agent-held), grant, integration; never token or capability (contract 14). CLI flags and audit keys (`--token-name`, `extra.token`) keep their names.

## Purpose
- Rotate a credential's value or edit its scope note after creation without reusing `dop integration add` (which creates / merges); manage bearers without ever losing their portable copy.

## Invariants
- `dop integration set-token` MUST require `--name` and `--token-name` and at least one of `--value`, `--value-stdin`, `--scope-note`.
- The new token value MUST NEVER appear in any log, audit event, stderr output, or process-argv list.
- `--value-stdin` MUST read a single line from stdin, strip trailing CR/LF, and treat the result as the new value.
- A rotation (value change) and a scope edit MUST be settable in a single call atomically.
- `EventIntegrationTokenSet` MUST fire on every mutation call, carrying `token`, `rotated` (bool-as-string), `scope_changed` (bool-as-string). MUST NOT carry the new value.
- Owner-gated: if the integration is `Protected`, the set-token call MUST refuse when session != Owner (same gate as other mutations, contract 15).

## Mandatory Behaviors

### CLI — `dop integration set-token`
- Flags: `--name` (required), `--token-name` (required), `--value` (optional), `--value-stdin` (optional, mutually-sensible with --value), `--scope-note` (optional).
- MUST refuse with exit 2 and message "supply at least one of --value / --value-stdin / --scope-note" when no mutation flag is set.
- MUST refuse with exit 1 when the integration or token doesn't exist, including the available token names in the error message.
- When the value and scope note are both unchanged, MUST exit 0 with a stderr note and NO audit event.
- MUST print a one-line stderr summary: `set-token: <integ>/<tok> → value rotated, scope "..."`.
- MUST include the reseal nudge in stderr when a rotation happened: "`bearers currently holding this token see the new value on their NEXT exec (direct availability) — or after `dop token reseal <subject>` for ed25519-bound bearers.`"

### CLI — `dop integration rename-token`
- `dop integration rename-token --integration <name> --from <old> --to <new> [--passphrase-stdin]`; all three names required (exit 2 otherwise). Admin session required.
- Owner gate (`requireProtectionOwner`) like every integration mutation; a protected integration also takes the approval passphrase (`--passphrase-stdin` for the TUI and scripts): the rename rewrites grants.
- MUST refuse (exit 1) an unknown integration or credential, and a `--to` that already exists on the integration.
- MUST move the `Integration.Tokens` key and rewrite every grant on that integration whose `Token` equals `--from`; other grants untouched. One save + push.
- MUST log one `token_rename` event (contract 10) and print `dop integration rename-token: <integration>: "<old>" → "<new>" (updated <n> grant reference(s))` on stderr.

### CLI — `dop grant rename`
- `dop grant rename --from <id> --to <id> [--passphrase-stdin]`; both ids required (exit 2 otherwise). Admin session required.
- MUST refuse (exit 1) a missing `--from` and an existing `--to`. A protected grant takes the owner gate (`requireProtectionOwner`) and the approval passphrase.
- MUST move the `v.Grants` key and, in every ACTIVE bearer record whose `Grants` lists `--from`, replace the id with `--to` and re-sign through the daemon (`resignCapability` → `putCapability` + sidecar). Revoked and rotated records are left as they are. One save + push.
- Per bearer kind: the same rule for P-256, ed25519 and unclaimed PIN bearers: rewrite + re-sign only, no reseal, no generation bump, no stale bearers. Reason: exec never reads grant ids: it takes env from the bundle or `env_wrapped` (`execcmd.go::resolveBearer`), and that env's keys come from `Grant.EffectivePrefix()` (integration + credential, or `env_prefix`), not from the id (`tokencmd.go::resolveGrantsToEnv`). So the env is unchanged, the `env_wrapped` AAD (lookup + generation) still matches, and the ed25519 bundle stays correct. Grant ids on the record matter only to admin-side checks (`dop use` protected-grant check, grant show), which see the new id.
- MUST log one `grant_rename` event (contract 10) and print `dop grant rename: "<from>" → "<to>" (updated <n> bearer(s))` on stderr.

### TUI — grant rename
- `n` on the grant list or detail, or the Rename action (`grantActions`: Edit, Rename, Remove): one input prefilled with the current id, no review, `enter` saves (a protected grant asks the approval passphrase on the same screen first); running `Renaming grant…`, done `✓ Grant renamed` (grant, was); empty, unchanged or taken ids and CLI failures on the status line. Through `sessionGuard`. After done the grant list shows with the cursor on the new id.

### TUI — integration detail
- `enter` on an integration row MUST open its detail with tabs Info / Credentials N / Grants N (contract 14). `e` edit and `r` remove work from the list and the Info tab.
- Credentials tab rows: name, value as `•••• N chars` (`maskLen`, never the value or a tail), scope note. A placeholder-looking value MUST show an error hint ("Rotate in the real one").
- `enter` on a credential MUST show its actions under the rows (`credActions`, in order): Edit scope note, Rotate value, Rename, Remove credential. No View / Back rows. `n` on the Credentials tab (or in the actions) opens Rename directly.
- Rename (`integModeTokenRename`): one text input prefilled with the current name, no review, `enter` saves (a protected integration asks the approval passphrase on the same screen first); running `Renaming credential…`, done `✓ Credential renamed`; empty, unchanged or taken names and CLI failures on the status line. Shells out through `sessionGuard` (`startRun`).
- `a` on the Credentials tab MUST open Add credential for this integration (`newAddCredentialView`: credential + mandatory grant, contract 16); `a` on the Grants tab opens Add grant with the integration fixed.
- Edit scope note MUST open the `scopePresets` picker on the current note (else `other…`); free text via `other…`.
- Rotate value input MUST be masked and MUST pass the value via `--value-stdin` + stdin pipe (`doTokenRotate`), never `--value`.
- Remove credential confirm MUST list the grants removed with it (`upTo5`) and say bearers holding them are resealed where possible; footer `enter remove · esc cancel`.
- Empty Credentials tab: `No credentials yet. Press a to add one.`

### TUI — integration-level edit
- `e` MUST open the integration edit form (`integModeIntEdit`, `enterIntEdit`, dense form with Normal / Advanced tabs, contract 14) seeded with current name, kind, description, kind slot, projects, tags, protection and the Advanced metadata (contract 16); a review of the changed rows precedes the save.
- Save MUST shell to `dop integration rename --from --to` first when the name changed, then `dop integration add --name <name> …` (idempotent update, contract 16).

### Bearers — `dop token` subcommands
- `issue`, `list`, `show`, `revoke`, `prune`, `repin`, `portable --on|--off`, `reseal`, `add-grant`, `remove-grant`, `rotate`; all admin-session gated (contract 01).
- `repin`, `portable --on` and `rotate` re-issue the bearer through one path (contract 25). `portable` semantics: contract 19.
- `prune [--older-than 30d] [--dry-run] [--yes]` MUST delete only revoked and rotated records whose age (`vault.Capability.TouchedAt`: `revoked_at` for revoked, rotation seal `BearerWrapped.SealedAt` for rotated; records revoked before `revoked_at` existed fall back to the newest of created / claimed / sealed) is older than the cutoff, plus their files; never active records, never `Generations`; one vault save and one `prune` audit event. A rotated record MUST stay until the cutoff so its agent can still pick up `BearerWrapped`.
- Every rewrite of an existing bearer record (revoke, repin, reseal, add/remove-grant, rotate, cascade, grant rename, claim, remote approve, agent migrate, `syncSidecars` re-sign) MUST go through `putCapability`, which carries `PortableWrapped` from the existing entry.

### Protection interaction
- `set-token` on a protected integration owned by someone else MUST refuse (CLI-side via `requireProtectionOwner`), AND MUST be caught by the daemon save-guard if somehow bypassed (per contract 15).
- `set-token` by the OWNER on a protected integration MUST NOT re-prompt the approval passphrase (ownership already proven, mutation is non-structural). This parallels `grant add` on protected integrations.

## Forbidden Behaviors
- MUST NOT accept a new token value on the command line via a shell-visible flag when invoked from the TUI. The TUI MUST always use `--value-stdin` so `ps`/`history` don't capture the secret.
- MUST NOT emit the new value in any audit event, log, or stderr message.
- MUST NOT cascade grant removal when a value is rotated (grants reference the TOKEN NAME, not value; the grant remains valid, env bundle just changes on next exec).
- MUST NOT silently create a new token when `--token-name` doesn't match an existing one — explicit error.
- MUST NOT allow TUI token-rotation to proceed when the integration is protected and the session is not the owner.

## Interfaces
- Inputs: `--name`, `--token-name`, `--value` | `--value-stdin`, `--scope-note` on `dop integration set-token`; `enter` + action keys in the TUI token picker.
- Outputs: audit event `integration_token_set`; stderr summary; mutated vault.
- Events: `EventIntegrationTokenSet` with `extra.token`, `extra.rotated`, `extra.scope_changed`.
- Dependencies: `cmd/dop/integrationcmd.go::runIntegrationSetToken`, `internal/tui/list_remove_views.go` (modes `integModeDetail` tabs, `integModeTokenAction` / `EditScope` / `Rotate` / `Rename` / `RemoveConfirm`, `integModeIntEdit` / `IntReview`), `cmd/dop/integrationcmd.go::runIntegrationRenameToken`, `cmd/dop/protected.go::requireProtectionOwner`, `cmd/dop/tokencmd.go::putCapability`.

## State & Data Rules
- The token's `Value` field in `vault.Integration.Tokens[name]` is replaced atomically on rotation.
- The token's `ScopeNote` field is replaced atomically on scope edit.
- No new vault schema fields are introduced by this feature.
- The Credentials tab state (`tokenNames`, `tokenCursor`) MUST be reloaded on each detail open (`refreshTokens`); the rotate / scope buffer (`tokenEditBuf`) MUST be reset when an action opens.
- The integration-edit state (`intEditField`, `intEditKindChoice`, `intEditDescBuf`, `intEditKindSlotBuf`) MUST be seeded with current values on each `enterIntEdit()` call.

## Acceptance Criteria
- PASS if `testdata/e2e/v1_1360_integration_set_token.sh` passes (9 steps covering rotate-only, scope-only, both, missing-flags refusal, unknown-token refusal, audit event, no value leak, stdin path, protected owner-set-token).
- PASS if `go test ./internal/tui/` passes (unit tests remain green, no regression on handoff shape).
- PASS if a token rotation emits an audit event with `rotated=true` and the new value does NOT appear anywhere in `audit.jsonl`.
- PASS if the TUI `e` key on an integration row opens the integration edit form with current values pre-populated.
- PASS if `TestPutCapabilityKeepsPortableStash` passes (stash survives revoke, reseal, grant edits, re-sign, generation bump).
- PASS if the TUI token-rotate flow sends the new value via stdin (ps/history of the subprocess don't contain the value).
- FAIL if any CLI mutation path puts a new token value on an argv line visible via `ps`.
- FAIL if the Credentials tab of an integration with zero credentials shows anything but the empty-state line.
- FAIL if any bearer record rewrite drops `PortableWrapped`.

## Regression Checks
- Verify `cmd/dop/integrationcmd.go::runIntegrationSetToken` reads the stdin value in `--value-stdin` mode via `readValueStdin()` which strips CR/LF.
- Verify the audit event emission site in `runIntegrationSetToken` does not pass `tok.Value` or `*newValue` into the Event struct.
- Verify `internal/tui/list_remove_views.go::doTokenRotate` builds `exec.Command` with `--value-stdin` and sets `cmd.Stdin`, NOT with a `--value <literal>` flag.
- Verify `credActions` lists exactly 4 actions in the order: Edit scope note, Rotate value, Rename, Remove credential.
- PASS if `TestRenameGrant` passes (key moved, active bearers carrying it hold the new id with a valid signature, revoked and unrelated bearers untouched, missing source and existing target refused, `grant_rename` logged with `bearers`).
- PASS if `TestRenameToken` passes (key moved, referencing grant rewritten, other grant untouched, existing target refused, `token_rename` logged).
- Verify `cmd/dop` has no `v.Capabilities[id] = capability2VaultCapability(` outside `issueBearer`.
- Verify `enterIntEdit` picks the current kind in the kind row (so Edit opens on today's value).

## Open Questions
- Should `set-token` support a `--audit-reason "..."` flag for operator-supplied free-text that lands in `extra.reason`? Would help forensic review when rotating in response to a suspected leak. Not implemented yet.
- Should rotation emit an additional event (`EventTokenRotated`) distinct from `EventIntegrationTokenSet`? Current contract folds both into one event with `rotated=true` — simpler but less filterable in `dop watch`.
- Resolved: the integration edit form flips protection with the passphrase gate (contract 15).
