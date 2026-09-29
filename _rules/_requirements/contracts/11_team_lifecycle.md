# Feature Contract — Team Lifecycle

## Scope
- `dop team add-key` / `list` / `remove` and the trust + revocation guarantees that come with a multi-admin vault.

## Purpose
- Let more than one operator administer the vault without letting removal be a foot-gun.

## Invariants
- MUST allow the admin plane to add another admin's age recipient + ed25519 pubkey via `dop team add-key`.
- MUST list every admin (name, age, ed25519, note) via `dop team list`.
- MUST enforce the removal safeguards defined below on every `dop team remove` invocation.

## Mandatory Behaviors
- `dop team add-key` MUST accept `--name`, `--pubkey age1...`, `--ed25519 <hex>`, optional `--note`.
- `dop team add-key` MUST refuse a non-`age1` recipient and MUST require both name and pubkey.
- `dop team remove` MUST refuse to remove the last admin (`len(v.Admins) <= 1`), even under `--force`.
- `dop team remove` MUST refuse self-removal (session pubkey == victim pubkey), even under `--force`.
- `dop team remove` MUST fail-closed on `client.Status()` errors (cannot verify self ⇒ refuse).
- `dop team remove --force` MUST also revoke every active capability whose `issued_by` matches the removed admin's ed25519, delete their `.bundle` + `.record` files, and emit `revoke` audit events with `reason=admin_removed`.
- `dop team remove` MUST print the upstream-rotation checklist listing every integration token that the removed admin could have seen.
- `dop team remove` MUST always re-encrypt the vault with the reduced admin recipient set on success.

## Forbidden Behaviors
- MUST NOT let `--force` override the self- or last-admin refusal.
- MUST NOT silently reintroduce a removed admin via the "bootstrap self" path in `saveVaultViaDaemon` (fixed in v1.6.3 by matching by pubkey, not hostname).
- MUST NOT leave orphan `.bundle` or `.record` files for the removed admin's capabilities on disk.
- MUST NOT overwrite an existing `admins.trust` when a joining admin runs `dop init --vault` (stat guard).

## Interfaces
- Inputs: `dop team add-key --name N --pubkey age1... [--ed25519 hex] [--note …]`, `dop team list`, `dop team remove --name N [--force]`.
- Outputs: mutated `v.Admins` + regenerated `admins.trust` + re-encrypted vault; audit events on force-revocations.
- Events: `revoke` per force-removed capability.
- Dependencies: `internal/trust`, `internal/vault`, `internal/audit`, `internal/admin` (session Status for self-check).

## State & Data Rules
- MUST identify admins by ed25519 pubkey internally; hostname keys are only display.
- MUST disambiguate hostname collisions on save by appending `-2`, `-3`, … when a different pubkey already owns the base hostname.
- MUST regenerate `admins.trust` on any `v.Admins` mutation via `saveVaultViaDaemon`.

## Acceptance Criteria
- PASS if `dop team remove --name $(hostname) --force` on a single-admin vault refuses with "only admin".
- PASS if `dop team remove --name self --force` after `add-key` refuses with "refusing to remove yourself".
- PASS if removing a peer admin also revokes their capabilities and deletes sidecars.
- FAIL if `client.Status()` failure silently lets self-removal proceed.

## Regression Checks
- `v1_v163_gaps.sh` step [8] (last-admin refusal) and step [9] (self-remove refusal with a second admin present).
- `v1_team_lifecycle.sh` covers happy add-key + list.

## Open Questions
- Should removing an admin also revoke `admins.trust` entries retroactively across historical git commits? Currently the removed admin's local vault clone still decrypts committed history.
