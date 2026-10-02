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
- The promoted env suffix set is CLOSED and canonical: {`BASE_URL`, `ENDPOINTS_URL`, `AUTH_HEADER`, `CMD`, `ARGS_HINT`, `MCP_URL`, `MCP_CMD`}. Adding a new one requires updating this contract.

## Mandatory Behaviors

### Schema
- `vault.Integration.Kind` MUST serialize via `yaml:"kind,omitempty"` so pre-rc13 vaults don't require migration.
- Reading a pre-rc13 integration (Kind=="") MUST return `IntegrationKindAPI` via `IntegrationKindOf`.

### Env bundle promotion (`resolveGrantsToEnv`)
- MUST emit `${PREFIX}_TOKEN` and `${PREFIX}_KIND` for every grant whose integration + token resolves.
- MUST promote these metadata keys (if present + non-empty) to canonical env suffixes via `promotedMetadataKeys()`:

  | Metadata key   | Env suffix       | Primary kind |
  |----------------|------------------|--------------|
  | `base_url`     | `_BASE_URL`      | api          |
  | `endpoints_url`| `_ENDPOINTS_URL` | api          |
  | `auth_header`  | `_AUTH_HEADER`   | api          |
  | `cli_cmd`      | `_CMD`           | cli          |
  | `cli_args_hint`| `_ARGS_HINT`     | cli          |
  | `mcp_url`      | `_MCP_URL`       | mcp          |
  | `mcp_cmd`      | `_MCP_CMD`       | mcp          |

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

### TUI
- The add-integration flow MUST include a Kind preset step (step 1, after service name) with the four kinds in the order api → cli → mcp → other.
- When an operator picks an EXISTING service at step 0, the flow MUST read that service's stored Kind and skip the Kind step entirely.
- The step after Kind (step 3, KindSlot) MUST change its label + hint per kind:
  - `api` → "Base URL"
  - `cli` → "Command (binary name)"
  - `mcp` → "MCP URL (or stdio cmd)"
  - `other` → row skipped entirely in render + advance.
- The TUI subprocess invocation MUST pass `--kind <kind>` and route the KindSlot buffer to the right flag per kind (`--base-url`, `--cmd`, `--mcp-url`/`--mcp-cmd`).
- The integration detail view MUST render a `kind: <kind>` line directly under description.

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
- Inputs: `--kind`, `--endpoints-url`, `--auth-header`, `--cmd`, `--args-hint`, `--mcp-url`, `--mcp-cmd` on `dop integration add`.
- Outputs: env bundle (map[string]string) with promoted suffixes; CLI list prefix; TUI picker + adaptive step.
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
- Verify `cmd/dop/tokencmd.go::promotedMetadataKeys` returns exactly the 7 keys from the table above.
- Verify `internal/vault.IntegrationKindOf` substitutes `api` for empty Kind.
- Verify `cmd/dop/integrationcmd.go::runIntegrationAdd` validates `--kind` via `ValidIntegrationKind`.
- Verify `cmd/dop/integrationcmd.go::runIntegrationAdd` makes `--token` optional only when the integration already exists.
- Verify `internal/tui/integration_views.go::kindPresets` lists exactly 4 kinds in order (api, cli, mcp, other) — no "other…" escape row (kinds are closed, not open-ended).
- Verify `internal/tui/integration_views.go::kindSlotLabel` returns different labels for each kind.
- Verify the service-picker-pick-existing path inherits Kind via `IntegrationKindOf` (so the Kind step is skipped on second-credential adds).

## Open Questions
- Should the probe-on-add feature (planned rc15) store its result in `endpoints_url` even if the operator passed `--kind api` without `--endpoints-url`? Current contract says `endpoints_url` is a hint URL, operator-supplied; probe would make it DOP-populated. May need to add a `probed_endpoints_url` separate key to distinguish operator-supplied from auto-discovered.
- Should MCP kind support BOTH `mcp_url` and `mcp_cmd` on the same integration (for failover)? Current contract allows either; env bundle emits whichever is set.
- Should `auth_header` default to `Bearer` on the agent side if unset for api kind, or should the agent be told explicitly? Currently unset means absent in env; agent reads documentation.
