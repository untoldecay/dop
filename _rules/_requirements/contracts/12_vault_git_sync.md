# Feature Contract — Vault Git Sync

## Scope
- `dop init --vault | --cache`, `dop pull`, `dop push`, the vault-dir `.gitignore`, and the constraints on what lives in the working tree.

## Purpose
- Use plain git as the transport for the encrypted vault + public sidecars, with predictable working-tree hygiene.

## Invariants
- MUST accept HTTPS / SSH / `file://` sources plus local paths for `dop init --vault`/`--cache`.
- MUST bootstrap a local bare repo when the source path does not yet exist (single-user quickstart).
- MUST refuse to attach into a non-empty directory (`ensureDestClear`).
- MUST require git on `$PATH`; refuse cleanly when missing.
- MUST place the vault clone at `<Vault> = paths.Vault` (typically `~/Library/Application Support/dop/vault`).

## Mandatory Behaviors
- `dop init --vault` MUST refuse when no admin key exists locally (points at `dop admin init`).
- `dop init --cache` MUST refuse when an admin key already exists (points at removing keys first).
- `dop init --vault` MUST seed `.gitignore` inside the vault checkout on first attach.
- `dop init --vault` MUST call `seedTrustIfPossible` after clone if an admin session is active, but MUST NOT overwrite an existing `admins.trust`.
- `dop pull` MUST run `git pull --ff-only`.
- `dop push` MUST run `git add -A` then `git commit -am` (if there are changes) then `git push`.

## Forbidden Behaviors
- MUST NOT create `keys/` on an agent install.
- MUST NOT commit `.dop-encrypt-*.yaml` (SOPS staging), `*.tmp` (atomic-rename orphans), `.vault-edit-*.yaml`, `*.swp`, or `.DS_Store` — enforced by the seeded `.gitignore`.
- MUST NOT commit `agent-keys/` (that lives under `<Root>`, not `<Vault>`, so it's naturally excluded).
- MUST NOT auto-merge conflicting `vault.yaml` changes — no merge driver ships; `--ff-only` fails loudly.

## Interfaces
- Inputs: `--vault SRC`, `--cache SRC`; `dop pull`; `dop push`.
- Outputs: git working tree at `<Vault>`; `.gitignore` seeded on first attach.
- Events: none directly (git commands invoked as subprocesses).
- Dependencies: `git` binary, `internal/config` for paths, `internal/admin` for plane detection, `internal/trust` for optional seed.

## State & Data Rules
- MUST persist gen-cache and agent-keys under `<Root>` (not `<Vault>`) so they never enter git.
- MUST publish `admins.trust`, `vault-context.bin`, `capabilities/*.bundle`, `capabilities/*.record`, `vault.yaml`, `.sops.yaml`, `.gitignore` — those ARE the vault repo contents.

## Acceptance Criteria
- PASS if `dop init --vault` on a fresh admin creates the `.gitignore` file and (if session is unlocked) `admins.trust`.
- PASS if `dop init --cache` refuses on an admin install.
- PASS if a second admin's `dop init --vault` preserves the existing `admins.trust`.
- FAIL if `.dop-encrypt-*.yaml` leftover files are committed by `dop push`.
- FAIL if `dop pull` accepts a non-fast-forward merge silently.

## Regression Checks
- `v1_v163_gaps.sh` step [2] verifies `.gitignore` is seeded.
- `v1_v163_gaps.sh` step [3] verifies `admins.trust` is bootstrapped when session is active.
- `v1_remote_server.sh` verifies clone-based cross-machine flow.

## Open Questions
- Do we ship a `.gitattributes` (or a custom merge driver) so concurrent admin issues stop being a race-to-push problem? Currently deferred (documented as an architecture-scope item).
