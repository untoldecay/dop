# Feature Contract — Endpoints Discovery Probe

## Scope
- The opt-in network probe run at `dop integration add --probe-endpoints` time (CLI + TUI). Covers the ordered OpenAPI path list, the MCP `tools/list` probe, request timeouts, metadata storage of the result, and the audit event emitted on every run (success or failure). Introduced in v1.13.0-rc15.

## Purpose
- Let operators stamp an `endpoints_url` (api kind) or verify liveness (mcp kind) at the moment of integration creation, without forcing them to look up the OpenAPI path by hand. Agents receiving the bearer later get a usable `_ENDPOINTS_URL` without blind-probing.

## Invariants
- The probe MUST be opt-in via `--probe-endpoints`. DOP MUST NOT auto-fetch any URL from stored metadata at any other time.
- The probe MUST NOT fail the parent `integration add` operation. A failed probe writes an audit event and continues to save the integration.
- Every probe run (success OR failure) MUST emit exactly one `EventIntegrationProbed` audit event.
- The probe MUST have a bounded wall-clock time: per-request timeout ≤ 3s, total probe time ≤ 20s for OpenAPI (6 paths × 3s plus overhead), ≤ 5s for MCP (1 request).
- The probe MUST NOT be invoked at env-resolve time, at exec time, or by any admin command other than `integration add`.

## Mandatory Behaviors

### OpenAPI probe (api kind)
- MUST walk `probe.OpenAPIProbePaths` in the declared order: `/.well-known/openapi.json`, `/openapi.json`, `/openapi.yaml`, `/v3/api-docs`, `/swagger.json`, `/api-docs`.
- MUST stop at the first path that returns a 2xx status with a body matching the OpenAPI shape (`openapi:` or `swagger:` field in JSON OR substring match for YAML / truncated JSON).
- MUST stamp `endpoints_url` = resolved full URL and `endpoints_probed_at` = RFC3339 UTC timestamp on the integration metadata on success.
- MUST emit an audit event with `extra.result = "found" | "no_match" | "setup_error"`.
- MUST print a one-line stderr summary: `probe → <url> (<ms>)` on success, `probe → no match on N paths (<ms>)` on no-match.
- MUST skip (with a stderr note) when `--base-url` is empty.
- MUST skip (with a stderr note) when `endpoints_url` was supplied explicitly via `--endpoints-url` or already exists on the integration.

### MCP probe (mcp kind)
- MUST POST a single JSON-RPC `tools/list` request to the stored `--mcp-url`.
- MUST only accept 2xx status + JSON body with `"jsonrpc":"2.0"` + `result.tools` present.
- MUST stamp `mcp_probed_at` = RFC3339 UTC timestamp AND `mcp_probe_result = "ok"` on success.
- MUST emit an audit event with `extra.result = "ok" | "no_match"` and `extra.mcp_url = <url>`.
- MUST skip when `--mcp-url` is empty (operator probably only set `--mcp-cmd`).

### TUI port
- A new preset-picker step (`integAddStepProbe`) MUST render after `integAddStepKindSlot` whenever the chosen kind is `api` or `mcp` (regardless of what's in the URL buffer — see rc16 note below).
- The picker MUST default to `no` (DOP never auto-fetches unless the operator says yes).
- On "yes", the TUI subprocess call MUST append `--probe-endpoints` to the `dop integration add` invocation.
- The Probe row MUST render in the row list for api/mcp integrations; the TUI MUST hide it entirely for cli/other kinds.
- v1.13.0-rc16 update: the earlier rc15 heuristic ("only show probe if URL has http(s) scheme") silently skipped the step for URLs the operator typed without a scheme. That failure mode was invisible — operators could not tell whether a probe had been offered. Now the step is always shown for api/mcp; if "yes" is picked but the base URL is empty or scheme-less, the CLI prints a clear `probe-endpoints skipped (no --base-url set)` and the save still succeeds.

### Validation + user feedback
- Non-200 responses MUST NOT short-circuit the probe — walk the full list.
- Transport errors (DNS, connect, read) MUST be recorded in the audit event's `extra.err` field with the raw error text, truncated to a reasonable length (≤ 256 chars).
- The probe MUST set `User-Agent: dop-probe/1` and send `Accept: application/json, application/yaml, text/yaml` on OpenAPI probes.
- The probe MUST NOT send Authorization headers, cookies, or any other identifying information — it's an unauthenticated probe against operator-supplied URLs only.

## Forbidden Behaviors
- MUST NOT run the probe when `--probe-endpoints` was not supplied.
- MUST NOT follow HTTP redirects outside the probed origin (default net/http follows up to 10 same-origin — acceptable; cross-origin redirects MUST be refused or MAY be logged + skipped).
- MUST NOT persist the probe response body — only the resolved URL.
- MUST NOT retry a failed probe path (one attempt per path per run).
- MUST NOT invoke the probe from any TUI view other than `addIntegrationView`.
- MUST NOT include bearer, PIN, or any upstream token value in the probe request headers or body.
- MUST NOT widen the probe path list without a contract update.

## Interfaces
- Inputs: `--probe-endpoints` flag on `dop integration add`; metadata keys `base_url` or `mcp_url` as the probe target.
- Outputs: metadata stamp (`endpoints_url` + `endpoints_probed_at` for api; `mcp_probed_at` + `mcp_probe_result` for mcp); stderr summary; audit event.
- Events: `EventIntegrationProbed` with `subject` = integration key, `extra.kind` = `"api" | "mcp"`, `extra.result` = outcome, plus kind-specific extras.
- Dependencies: `net/http` stdlib, `encoding/json`, `internal/probe` package.

## State & Data Rules
- The probe is PURE on the vault side — it reads metadata to decide what to probe, mutates metadata to stamp the result, and emits an audit event. No other state.
- `promotedMetadataKeys()` (contract 16) MUST include `endpoints_url` so a successful api probe reaches the agent's env bundle as `${PREFIX}_ENDPOINTS_URL`.
- `mcp_probe_result` is NOT in the promoted set — it's for operator audit only, not for the agent.

## Acceptance Criteria
- PASS if `testdata/e2e/v1_1350_endpoints_probe.sh` passes (6 steps: find on /openapi.json, audit event, dead-port non-fatal, explicit --endpoints-url honored).
- PASS if `go test ./internal/probe/` passes (8 unit tests covering path order, Swagger fallback, no-match, non-OpenAPI body, YAML body, scheme validation, MCP success + wrong-shape).
- PASS if `dop integration add --kind api --base-url <url> --probe-endpoints` against a server that responds with a valid OpenAPI doc at `/openapi.json` stamps `endpoints_url` and `endpoints_probed_at`.
- PASS if the same command against a dead/unresolvable host still saves the integration (probe failure is non-fatal) and emits an audit event with `result="setup_error"` or `result="no_match"`.
- FAIL if any probe is triggered without `--probe-endpoints`.
- FAIL if any probe runs longer than ~20s wall-clock on a dead target.
- FAIL if the audit event is missing on any probe run.

## Regression Checks
- Verify `internal/probe/probe.go::OpenAPIProbePaths` matches the list in this contract exactly.
- Verify `cmd/dop/integrationcmd.go::runProbe` emits an audit event on EVERY path (found / no_match / setup_error / mcp ok / mcp no_match).
- Verify `internal/tui/integration_views.go::probeApplicable` returns false for cli and other kinds.
- Verify `internal/tui/integration_views.go::probePresets` has `no` as the default (zero-cursor) entry.
- Verify no code outside `internal/probe/` + `cmd/dop/integrationcmd.go::runProbe` imports `net/http` for admin-mediated operations other than the existing Cloudflare tunnel + web-approval server.

## Open Questions
- Should the probe set `endpoints_url` even for a Swagger 2.0 response, or distinguish OpenAPI 3 vs Swagger 2? Current contract treats them as equivalent for storage; agents can tell them apart by fetching the doc.
- Should cross-origin redirects be followed or refused? Current behavior inherits net/http defaults (follows same-origin up to 10 hops). Could tighten.
- Should operators be able to configure extra probe paths? Currently the list is closed. Would need `--probe-path` repeatable flag + a security review (operators pointing probes at admin interfaces).
- For MCP, should the probe cache the discovered tool list for later display? Currently no — only a liveness check.
