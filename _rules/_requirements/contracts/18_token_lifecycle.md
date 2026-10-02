# Feature Contract — Token Lifecycle (set / rotate / remove)

## Scope
- The `dop integration set-token` CLI command, the TUI token drill-down (enter on an integration row → tokenListView parity with grantListView), and the `EventIntegrationTokenSet` audit event. Introduced in v1.13.0-rc16.

## Purpose
- Give operators first-class tools to rotate a token's value or edit its scope note after creation, without reusing `dop integration add` (which creates/merges). Mirrors `dop grant` CRUD parity: tokens are now a first-class drill-down target with view / edit / rotate / remove actions.

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
- MUST emit the audit event even when the new values exactly match the old values (so `rotated=false` + `scope_changed=false` events exist in the trail — proves "someone tried, nothing changed").
- Actually: when BOTH `rotated=false` AND `scope_changed=false`, MUST early-exit with a stderr note and NO audit event (nothing happened, keeps the log clean). Prefer this over noise.
- MUST print a one-line stderr summary: `set-token: <integ>/<tok> → value rotated, scope "..."`.
- MUST include the reseal nudge in stderr when a rotation happened: "`bearers currently holding this token see the new value on their NEXT exec (direct availability) — or after `dop token reseal <subject>` for ed25519-bound bearers.`"

### TUI — token drill-down
- Enter on an integration row MUST open the token picker for that integration (previously opened the detail pane).
- The main integration list help legend MUST advertise the new key bindings: enter manage tokens, d details, e edit integration, r remove.
- The token picker MUST render each token as a row with name + scope note, cursor arrow prefix on the active row.
- Enter on a token row MUST open the per-token action menu: View details / Edit scope note / Rotate value / Remove / Back.
- Rotate value input MUST be masked (render with `•` glyphs) and MUST pass the value to the CLI via `--value-stdin` + stdin pipe, never via `--value` on the command line.
- Edit scope note input MUST pre-populate with the existing scope note.
- Remove confirmation MUST accept `y/Y/enter` as confirm and `n/N/esc` as cancel (per contract 14).
- Backspace on an empty edit buffer MUST return to the parent action menu.

### TUI — integration-level edit (sibling feature)
- `e` on the integration list MUST open the integration-level edit form (new mode `integModeIntEdit`).
- Form fields: Kind preset picker, Description, KindSlot (label + hint change per kind — mirrors add-integration flow).
- Save MUST shell to `dop integration add --name <existing> --kind <new> …` which per contract 16 is idempotent-update when the integration exists.

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
- Dependencies: `cmd/dop/integrationcmd.go::runIntegrationSetToken`, `internal/tui/list_remove_views.go` (new modes `integModeTokenList`/`Action`/`Detail`/`EditScope`/`Rotate`/`RemoveConfirm` + `integModeIntEdit`), `cmd/dop/protected.go::requireProtectionOwner`.

## State & Data Rules
- The token's `Value` field in `vault.Integration.Tokens[name]` is replaced atomically on rotation.
- The token's `ScopeNote` field is replaced atomically on scope edit.
- No new vault schema fields are introduced by this feature.
- The TUI's token drill-down state (`tokenNames`, `tokenCursor`, `tokenEditBuf`, `tokenPending`) MUST be reset on each `enterTokenList()` call.
- The integration-edit state (`intEditField`, `intEditKindChoice`, `intEditDescBuf`, `intEditKindSlotBuf`) MUST be seeded with current values on each `enterIntEdit()` call.

## Acceptance Criteria
- PASS if `testdata/e2e/v1_1360_integration_set_token.sh` passes (9 steps covering rotate-only, scope-only, both, missing-flags refusal, unknown-token refusal, audit event, no value leak, stdin path, protected owner-set-token).
- PASS if `go test ./internal/tui/` passes (unit tests remain green, no regression on handoff shape).
- PASS if a token rotation emits an audit event with `rotated=true` and the new value does NOT appear anywhere in `audit.jsonl`.
- PASS if the TUI `e` key on an integration row opens the integration edit form with current values pre-populated.
- PASS if the TUI token-rotate flow sends the new value via stdin (ps/history of the subprocess don't contain the value).
- FAIL if any CLI mutation path puts a new token value on an argv line visible via `ps`.
- FAIL if the token picker is reachable for an integration with zero tokens WITHOUT a clear "(no tokens)" state in the view.

## Regression Checks
- Verify `cmd/dop/integrationcmd.go::runIntegrationSetToken` reads the stdin value in `--value-stdin` mode via `readValueStdin()` which strips CR/LF.
- Verify the audit event emission site in `runIntegrationSetToken` does not pass `tok.Value` or `*newValue` into the Event struct.
- Verify `internal/tui/list_remove_views.go::doTokenRotate` builds `exec.Command` with `--value-stdin` and sets `cmd.Stdin`, NOT with a `--value <literal>` flag.
- Verify `renderTokenActionMenu` lists exactly 5 actions in the order: View details, Edit scope note, Rotate value, Remove, Back.
- Verify the integration list footer help mentions `enter manage tokens`.
- Verify `enterIntEdit` positions the kind cursor on the current kind (so Edit opens on today's value).

## Open Questions
- Should `set-token` support a `--audit-reason "..."` flag for operator-supplied free-text that lands in `extra.reason`? Would help forensic review when rotating in response to a suspected leak. Not implemented yet.
- Should rotation emit an additional event (`EventTokenRotated`) distinct from `EventIntegrationTokenSet`? Current contract folds both into one event with `rotated=true` — simpler but less filterable in `dop watch`.
- The TUI integration-edit form doesn't yet support flipping `Protected` on/off. Protection changes still require the add-integration CLI/TUI flow with its passphrase gate. Should the edit form prompt-and-flip? Deferred.
