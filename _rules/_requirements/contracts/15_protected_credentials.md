# Feature Contract — Protected Credentials

## Scope
- The `Protected bool` + `Owner string` fields on `vault.Integration` and `vault.Grant`, the CLI/TUI gates that refuse non-owner mutations, the daemon-side save-guard that reverts non-owner protected changes, and the three audit event kinds that surface the trail. Introduced in v1.13.0-rc12.

## Purpose
- Give multi-admin teams a loud, auditable "this credential belongs to me — don't touch" marker without requiring per-record encryption or coordinated key handoff. Shape B (convention + daemon enforcement) delivers the practical outcome without the operational complexity of per-admin encryption.

## Invariants
- When `Protected == true`, `Owner` MUST be a non-empty ed25519 pubkey hex of a known admin in `vault.Admins`.
- When `Protected == false`, `Owner` MUST be empty.
- A grant on a protected integration inherits `Protected == true` + `Owner` AT CREATION only. v1.14.0-rc3 makes grant-level protection independently settable; after creation, a grant can be locked or unlocked without changing its parent integration. See "Grant-first (v1.14.0-rc3)" below.
- Protected is NOT a cryptographic boundary. Any admin can decrypt the SOPS vault with their key and commit a hand-edited yaml OUTSIDE DOP. The guard only enforces for DOP-mediated writes.
- Every protected-resource bypass MUST produce an `EventProtectedBypassAttempt` audit event.
- v1.14.0-rc3 — every owner-initiated unlock (true→false flip on an integration OR grant) MUST produce an `EventProtectedUnlock` audit event with `extra.kind` + `extra.prior_owner`. The lock/unlock trail is symmetric with `EventProtectedCreate`.

## Grant-first (v1.14.0-rc3)
- Protection is independently settable at the grant level via `dop grant add --protected` (tri-state through `fs.Visit`: unset / `=true` / `=false`). Grants on an unprotected integration can be independently locked; grants on a protected integration can be unlocked independently of their parent.
- Operator intent "lock this one credential" maps to a grant-level lock, not an integration-level lock. Integration-level protection remains available for the rarer "lock the whole catalog" case.
- Flip-to-protected on a grant whose parent integration is NOT already protected (OR whose parent is protected but the operator explicitly set `--protected`): prompts the approval passphrase and stamps the current admin as owner. The inherited case (new grant, parent protected, no explicit flag) uses the parent's owner directly — no new passphrase.
- `dop integration add --protected=false` on a currently-protected integration (owner-only) explicitly unlocks it. Clears `Owner`. Emits `EventProtectedUnlock`. Fixes the pre-rc3 "orphan lock" trap where removing the last protected child left an integration locked with no CLI/TUI path to unlock.
- TUI integration edit + grant edit each expose a Protection row + conditional passphrase row (field only renders when flipping unprotected → protected).

## Mandatory Behaviors

### CLI gate (`requireProtectionOwner`)
- `dop integration add` / `remove` / `remove-token` MUST refuse the operation when the resource is protected and `session.AdminPubkey != resource.Owner`.
- `dop grant add` on a protected integration MUST refuse when session is not the integration's owner.
- `dop grant remove` on a protected grant MUST refuse when session is not the grant's owner.
- `dop token issue` MUST refuse when ANY grant in the bundle is protected and session doesn't own it.
- `dop token add-grant` / `remove-grant` MUST refuse when the target grant is protected and session doesn't own it.
- Every refusal MUST write `"<resource> is protected and owned by another admin (owner=<short>…)"` to stderr and MUST exit non-zero.

### Approval passphrase prompt (`promptProtectionPassphrase`)
- Every mutation that flips `Protected: false → true` or creates a new protected resource MUST prompt for the current admin's approval passphrase (same primitive as `dop admin set-approval`).
- Every bearer-issue that would include a protected grant MUST prompt the approval passphrase once (not once per grant).
- Every `token add-grant` / `remove-grant` of a protected grant MUST prompt the approval passphrase.
- Prompts MUST support `--passphrase-stdin` so TUI subprocess calls and non-interactive scripts can supply the passphrase without TTY prompting.
- An incorrect passphrase MUST be rate-limited by the shared 8-attempt limit from contract 07.

### Daemon-side save-guard (`enforceProtectedOnSave`)
- EVERY call to `saveVaultViaDaemon` MUST load the current on-disk vault via `vault.LoadPlain`, diff it against the proposed vault, and revert any mutation on a protected resource by a non-owner session.
- Pass 1 — existing-resource edit/delete by non-owner: MUST restore the pre-change state and emit `EventProtectedBypassAttempt` with `operation` = `"delete"` or `"edit"`.
- Pass 2 — brand-new protected or flip-to-protected without matching Owner: MUST remove the Protected flag + Owner (or delete the brand-new row entirely) and emit `EventProtectedBypassAttempt` with `operation` = `"claim-ownership"` or `"flip-protection"`.
- On any reversion the admin's stderr MUST print `dop: reverted N protected-resource change(s) ...` with the resource names.
- The save MUST proceed with the reverted (safe) state; the daemon MUST NOT fail the whole write just because some changes were reverted.

### Audit events
- `EventProtectedCreate` MUST fire when a resource is flipped to protected OR created new as protected. Carries `resource_kind` (integration | grant), `resource`, `owner`.
- `EventProtectedTokenIssue` MUST fire alongside the regular `EventIssue` whenever the issued bearer contains at least one protected grant. Carries `subject` and `protected_grants` (CSV).
- `EventProtectedBypassAttempt` MUST fire from `enforceProtectedOnSave` for every reversion. Carries `actor` (session pubkey), `resource_kind`, `resource`, `owner` (when applicable), `operation`.

### Visual surfacing
- `dop integration list` MUST prefix protected rows with `🔒 owner=<short-pubkey>`.
- TUI integration list MUST show a muted `🔒 ` glyph on protected rows, inside the padded column so cursor alignment stays stable.
- TUI integration detail view MUST render `protection: 🔒 owner-locked (owner=<short>)` for protected integrations.

## Forbidden Behaviors
- MUST NOT allow a non-owner to flip `Protected: false → true` on an existing resource (owner is always session on claim).
- MUST NOT skip the save-guard, even for owner-driven writes (keeps the diff fast; wrong-owner writes are rare).
- MUST NOT silently drop reverted changes — operator stderr feedback is required.
- MUST NOT emit `EventProtectedTokenIssue` when the bundle contains zero protected grants.
- MUST NOT store the approval passphrase, prompt text, or any derivative in audit events.
- MUST NOT treat `Owner` as case-sensitive — compare with `strings.EqualFold` since ed25519 pubkey hex is case-insensitive.

## Interfaces
- Inputs: `--protected` flag + `--passphrase-stdin` flag on `integration add` and `token issue`; `--passphrase-stdin` on `token add-grant` / `remove-grant`.
- Outputs: stderr refusal + audit events; TUI/CLI list glyphs.
- Events: `EventProtectedCreate`, `EventProtectedTokenIssue`, `EventProtectedBypassAttempt`.
- Dependencies: `internal/admin.Client.Status().AdminPubkey`, `internal/approval.Verify`, `internal/audit.Append`, `internal/vault.LoadPlain`, `cmd/dop/protected.go` helpers.

## State & Data Rules
- `Protected` + `Owner` MUST serialize via `yaml:"...,omitempty"` so unprotected rows don't bloat the vault.
- `Owner` MUST equal `session.AdminPubkey` at claim time; later admin-key rotations do NOT update stored `Owner` automatically — operator must re-claim via `integration add --protected`.
- `integrationEqual` + `grantEqual` in `cmd/dop/protected.go` MUST compare every field that affects the agent's env bundle (Description, Metadata entries, Tokens, Protected, Owner, Kind). Missing a field here lets a non-owner silently mutate state the save-guard wouldn't catch.

## Acceptance Criteria
- PASS if `dop integration add --protected --passphrase-stdin` with the correct passphrase stores Protected=true + Owner=<session pubkey>.
- PASS if `dop integration add --protected --passphrase-stdin` with the wrong passphrase exits non-zero and does NOT mutate the vault.
- PASS if `dop grant add` against a protected integration owned by someone else exits non-zero.
- PASS if `dop token issue` for a bundle containing a protected grant prompts the passphrase and emits `EventProtectedTokenIssue` on success.
- PASS if an orchestrated non-owner save (test harness simulates admin B saving a vault with admin A's protected integration mutated) results in a reverted write + `EventProtectedBypassAttempt`.
- FAIL if any CLI mutation path mutates a protected resource owned by someone else without emitting an audit event.
- FAIL if the save-guard allows a Protected-flip whose Owner doesn't match the session.

## Regression Checks
- Verify `testdata/e2e/v1_1330_protected_credentials.sh` passes (8 steps, including protected_create and protected_token_issue audit).
- Verify `cmd/dop/protected.go::integrationEqual` compares Kind (added rc13) — forgetting a field here is a silent failure mode.
- Verify `saveVaultViaDaemon` calls `enforceProtectedOnSave` BEFORE the admin-bootstrap self-add, so the guard runs on every write path.
- Verify `README.md` limits section documents the "not a cryptographic boundary" caveat.

## Open Questions
- Should admin-key rotation (future feature) propagate Owner updates to all protected resources the rotating admin owns, or require explicit re-claim?
- Should a protected grant's `remove` emit `EventProtectedBypassAttempt` when the OWNER removes it (currently no — it's a normal grant removal)?
- Should `dop team remove` refuse when the removed admin still owns protected resources (currently no — the resources become orphaned-owner)?
