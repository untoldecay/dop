# Feature Contract — Integration Kinds & Env Bundle Shape

## Scope
- The `Kind string` field on `vault.Integration`, the four recognized kind values (api / cli / mcp / other), the canonical env suffixes promoted from metadata at bundle-resolution time, the legacy-default behavior for empty Kind, and the mutable-kind semantics. Introduced in v1.13.0-rc13.

## Purpose
- Make the env bundle delivered to agents self-describing: a bearer carrying `${NAME}_TOKEN` + `${NAME}_KIND` + the appropriate kind-specific hint keys tells the agent "this is an HTTP API, probe its endpoints doc at this URL" or "this is a CLI, invoke this binary" without a separate out-of-band step.

## Invariants
- `Kind` MUST be one of: `api`, `cli`, `mcp`, `other`, or empty (empty is treated as `api` for backward compatibility).
- `vault.IntegrationKindOf(integ)` MUST be the single source of truth for the effective kind — callers MUST NOT read `integ.Kind` directly for behavior decisions.
- `vault.ValidIntegrationKind(s)` MUST be the sole validator on CLI input.
- Every env bundle entry for a grant MUST include `${PREFIX}_TOKEN` and `${PREFIX}_KIND`.
- The promoted env suffix set is CLOSED and canonical: the 13 rows of the table below (`promotedMetadataKeys`). Adding a new one requires updating this contract.

## Mandatory Behaviors

### Schema
- `vault.Integration.Kind` MUST serialize via `yaml:"kind,omitempty"` so pre-rc13 vaults don't require migration.
- Reading a pre-rc13 integration (Kind=="") MUST return `IntegrationKindAPI` via `IntegrationKindOf`.

### Env bundle promotion (`resolveGrantsToEnv`)
- MUST emit `${PREFIX}_TOKEN` and `${PREFIX}_KIND` for every grant whose integration + token resolves.
- MUST promote these metadata keys (if present + non-empty) to canonical env suffixes via `promotedMetadataKeys()`:

  | Metadata key    | Env suffix        | Primary kind | Since   |
  |-----------------|-------------------|--------------|---------|
  | `base_url`      | `_BASE_URL`       | api          | rc13    |
  | `endpoints_url` | `_ENDPOINTS_URL`  | api          | rc13    |
  | `auth_header`   | `_AUTH_HEADER`    | api          | rc13    |
  | `auth_style`    | `_AUTH_STYLE`     | api          | rc17    |
  | `cli_cmd`       | `_CMD`            | cli          | rc13    |
  | `cli_args_hint` | `_ARGS_HINT`      | cli          | rc13    |
  | `cli_auth_env`  | `_CLI_AUTH_ENV`   | cli          | rc17    |
  | `cli_install`   | `_CLI_INSTALL`    | cli          | rc17    |
  | `cli_help`      | `_CLI_HELP`       | cli          | rc17    |
  | `mcp_url`       | `_MCP_URL`        | mcp          | rc13    |
  | `mcp_cmd`       | `_MCP_CMD`        | mcp          | rc13    |
  | `server_root`   | `_SERVER_ROOT`    | any          | rc17    |
  | `allowed`       | `_ALLOWED`        | any          | rc17    |

### cli_auth_env template expansion (v1.13.0-rc17)
- MUST parse `cli_auth_env` as a `KEY=VAL;KEY=VAL` template, splitting on `;` and taking the first `=` of each pair.
- MUST substitute `$TOKEN` → the resolved token value, `$SERVER_ROOT` → `server_root` metadata (falling back to `base_url` when `server_root` is empty), `$BASE_URL` → `base_url` metadata. Substitutions are plain string replace, not shell expansion.
- MUST export each expanded KEY=VAL pair DIRECTLY into the env bundle (NOT prefixed by `${PREFIX}_`) so a CLI that reads its own well-known env names (e.g. `BOILER_TOKEN`, `BOILER_SERVER`) picks them up without an agent-side wrapper.
- MUST refuse to export expanded keys whose uppercase form matches a known-dangerous name: `PATH`, `HOME`, `USER`, `SHELL`, `PWD`, `TMPDIR`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`, `DOP_TOKEN`, `DOP_TOKEN_FILE`, `DOP_NO_TUI`, `DOP_ALLOW_FILE_KEYS`, `DOP_SIGN_IDENTITY`, `DOP_NO_KEYCHAIN`, `DOP_NO_NOTIFY`.
- MUST refuse to export keys that don't match POSIX env-var naming (`[A-Z_][A-Z0-9_]*`).
- The template string ITSELF is also exported under `${PREFIX}_CLI_AUTH_ENV` for transparency / debugging.

- Non-promoted metadata keys MUST still fall through under their `vault.SanitizeEnvKey`-sanitized name so free-form metadata keeps working.
- `PREFIX` MUST be `grant.EffectivePrefix()` (which defaults to `<INTEGRATION>_<TOKEN>` sanitized).
- Promotion MUST be case-stable: `base_url` in metadata always exports to `_BASE_URL`, regardless of how it was stored.

### CLI
- `dop integration add --kind {api|cli|mcp|other}` MUST validate against `ValidIntegrationKind` and exit non-zero on invalid kind.
- Per-kind hint flags MUST fold into metadata under their canonical key: `--endpoints-url` → `endpoints_url`, `--cmd` → `cli_cmd`, `--mcp-url` → `mcp_url`, etc.
- `--token` MUST be required when CREATING a new integration (no existing row with that name).
- `--token` MUST be OPTIONAL when updating an existing integration — so operators can flip Kind or edit hints without restating tokens.
- `--kind` on an existing integration MUST update the stored Kind (mutable); omitting `--kind` MUST preserve the existing Kind.
- `dop integration list` MUST prefix every row with `[<kind>]` where `<kind>` is the effective kind.

### TUI (Add integration dense form, `internal/tui/integration_views.go`)
- First screen picks `New integration` or an existing one (`pickOpts`). An existing integration starts at the Credential step and is never mutated: no integration-level row is asked or sent.
- Stepper `Integration › Credential › Grant`, one dense form per step (contract 14), then review, running, done.
- Integration step rows: name, kind (`kindPresets`, order api → cli → mcp → other, no escape row), description, then the kind slot: api `base URL` + `scan for docs`, cli `command`, mcp `URL or launcher`, other nothing. Changing the kind in the picker MUST clear the kind slot value (add and edit forms), so a value typed for one kind is never sent as another kind's flag.
- The kind slot MUST route to `--base-url` (api), `--cmd` (cli), `--mcp-url` when it starts with `http(s)://` else `--mcp-cmd` (mcp) (`integArgs`).
- A name that already exists MUST be refused at the Integration step ("pick it on the first screen to add a credential").
- Credential step, Normal tab: credential (prefilled with the integration name once), value (masked), scope note (`scopePresets` + `other…`), and for a new integration protection (+ passphrase when protected).
- Credential step, Advanced tab (new integrations only, `tab` switches): `advFieldSpecs` filtered by kind (`advFieldsForKind`). Mapping (row → flag → metadata key, kinds):

  | Row | Flag | Metadata key | Kinds |
  |---|---|---|---|
  | auth env template | `--cli-auth-env` | `cli_auth_env` | cli |
  | server root | `--server-root` | `server_root` | all |
  | allowed scope hint | `--allowed` | `allowed` | all |
  | auth style | `--auth-style` | `auth_style` | api |
  | install hint | `--cli-install` | `cli_install` | cli |
  | help entry | `--cli-help` | `cli_help` | cli |
  | endpoints URL | `--endpoints-url` | `endpoints_url` | api |
  | auth header | `--auth-header` | `auth_header` | api |
  | args hint | `--args-hint` | `cli_args_hint` | cli |
- Every Advanced field MUST be integration-level metadata. A credential stores only `value` and `scope_note` (`vault.Token`); the TUI sends it as `--token <cred>=<value>:<scope|->`.
- An existing credential name on the integration MUST be refused ("already has a credential"); `integration add` would overwrite it.
- Grant step is mandatory for a new credential: grant id (default `<integration>.<scope>` for read-only / read-write / admin, else `<integration>`, `-2`, `-3`… when taken), integration + credential fixed, env prefix default `vault.SanitizeEnvKey(<integration>_<credential>)` (= `Grant.EffectivePrefix`), projects, tags.
- An env prefix equal to the default MUST NOT be sent (`--env-prefix` omitted, record stays empty).
- Save runs `dop integration add` then `dop grant add`; if the second fails the retry only re-runs the grant (`integSaved`).
- The integration Info tab MUST show `kind` as its first row (`infoBody`); the integration edit form (`e`, dense form, contract 14) MUST allow changing name, kind, description, kind slot, scan for docs, projects, tags, protection, and on its Advanced tab every `advFieldSpecs` row for the kind, prefilled from `Integration.Metadata[metaKey]`.
- The edit form reuses the add flow's row builders (`integRows`, `slotRows`, `slotArgs`, `advRows`). Save sends every Normal row to `dop integration add`; an Advanced row only when changed (the CLI merges and keeps metadata it is not given); a cleared Advanced row is sent as `--metadata <key>=` (stored empty, treated as not set).

### Protection interaction
- `cmd/dop/protected.go::integrationEqual` MUST compare Kind so a non-owner flipping Kind on a protected integration gets reverted by `enforceProtectedOnSave`.
- Flipping Kind on a protected integration owned by someone else MUST emit `EventProtectedBypassAttempt`.

## Forbidden Behaviors
- MUST NOT emit duplicate env entries for a single metadata key (promoted + sanitized-raw — if the metadata key is in `promotedMetadataKeys()`, suppress the raw fallthrough).
- MUST NOT emit `${PREFIX}_KIND` from the integration's raw Metadata if an operator mis-stores a `kind` key there — Kind lives on the struct field, not in metadata.
- MUST NOT promote metadata values that are the empty string (treat empty as "key not set").
- MUST NOT accept a `--kind` value outside the four recognized values; empty is only valid on READ, not on write.
- MUST NOT auto-fetch any URL (`endpoints_url`, `mcp_url`) at integration-add or env-resolve time. Hints are inert URLs; DOP never follows them.

## Interfaces
- Inputs: `--kind`, `--base-url`, `--endpoints-url`, `--auth-header`, `--auth-style`, `--cmd`, `--args-hint`, `--cli-auth-env`, `--cli-install`, `--cli-help`, `--mcp-url`, `--mcp-cmd`, `--server-root`, `--allowed` on `dop integration add`.
- Outputs: env bundle (map[string]string) with promoted suffixes; CLI list prefix; TUI dense form with kind-adaptive rows.
- Events: no new audit events (Protected emits `EventProtectedBypassAttempt` on Kind-flip by non-owner).
- Dependencies: `internal/vault.IntegrationKindOf`, `internal/vault.ValidIntegrationKind`, `cmd/dop/tokencmd.go::resolveGrantsToEnv`, `cmd/dop/tokencmd.go::promotedMetadataKeys`.

## State & Data Rules
- `Kind` lives on `vault.Integration`, NOT on `vault.Grant`. A grant inherits its parent integration's effective Kind at env-resolve time; the grant does NOT store its own Kind.
- `promotedMetadataKeys()` is the single source of truth for the promotion table. Adding a new promoted suffix requires updating this function AND this contract.

## Acceptance Criteria
- PASS if `testdata/e2e/v1_1340_integration_kind.sh` passes (8 steps, all kinds exercised).
- PASS if an api-kind integration with `base_url`, `endpoints_url`, `auth_header` set exports `_BASE_URL`, `_ENDPOINTS_URL`, `_AUTH_HEADER` with the exact values.
- PASS if a cli-kind integration with `cli_cmd`, `cli_args_hint` set exports `_CMD`, `_ARGS_HINT` and does NOT export `_BASE_URL`.
- PASS if an other-kind integration exports only `_TOKEN` and `_KIND='other'`.
- PASS if a pre-rc13 vault (no Kind field) reads back with `_KIND='api'` for every integration.
- PASS if `dop integration list` shows `[api]`, `[cli]`, `[mcp]`, `[other]` prefixes correctly.
- FAIL if `_KIND` is missing from any env bundle entry.
- FAIL if a promoted metadata key double-exports (once as `_BASE_URL` and once as `_BASE_URL` sanitized-raw).

## Regression Checks
- Verify `cmd/dop/tokencmd.go::promotedMetadataKeys` returns exactly the 13 keys from the table above.
- Verify `internal/vault.IntegrationKindOf` substitutes `api` for empty Kind.
- Verify `cmd/dop/integrationcmd.go::runIntegrationAdd` validates `--kind` via `ValidIntegrationKind`.
- Verify `cmd/dop/integrationcmd.go::runIntegrationAdd` makes `--token` optional only when the integration already exists.
- Verify `internal/tui/integration_views.go::kindPresets` lists exactly 4 kinds in order (api, cli, mcp, other) — no "other…" escape row (kinds are closed, not open-ended).
- Verify `addIntegrationView.rows` shows a different kind-slot label per kind and none for `other`.
- Verify `useExisting` reads Kind via `IntegrationKindOf` and starts at the Credential step.
- Verify `integArgs` sends no integration-level flag for an existing integration and every Advanced field as an `integration add` flag.

## Open Questions
- Should the probe-on-add feature (planned rc15) store its result in `endpoints_url` even if the operator passed `--kind api` without `--endpoints-url`? Current contract says `endpoints_url` is a hint URL, operator-supplied; probe would make it DOP-populated. May need to add a `probed_endpoints_url` separate key to distinguish operator-supplied from auto-discovered.
- Should MCP kind support BOTH `mcp_url` and `mcp_cmd` on the same integration (for failover)? Current contract allows either; env bundle emits whichever is set.
- Should `auth_header` default to `Bearer` on the agent side if unset for api kind, or should the agent be told explicitly? Currently unset means absent in env; agent reads documentation.
