# Feature Contract — Signed Record + Trust Anchor

## Scope
- The per-capability `.record` JSON sidecar and the vault-wide `admins.trust` file that together let the agent-plane verify admin signatures without ever opening the vault.

## Purpose
- Make "the record was signed by a trusted admin" a real read-path check, not a design claim.

## Invariants
- MUST write a `<lookup_id>.record` file next to every `<lookup_id>.bundle` at issue / claim / re-issue (repin, portable --on, rotate) time.
- MUST write `admins.trust` (JSON, mode 0644) alongside `vault-context.bin` on every `saveVaultViaDaemon` call.
- MUST include exactly these fields in each record: `capability_id, subject, grants[], created_at, expires_at, generation, lookup_id, bundle_hash, issued_by, status, binding?, signature`.
- MUST use ed25519 for signatures with the canonical payload defined by `Record.SigningPayload()`.
- MUST include the `binding` object in the signed canonical form when present, using `binding.kind` + `pin_expiry?` + `pubkey?` + `claimed_at?`.

## Mandatory Behaviors
- `dop exec` MUST call `verifySignedRecord` BEFORE decrypting the bundle.
- `verifySignedRecord` MUST verify: `status == active`, `lookup_id == derived`, `bundle_hash == sha256(bundle bytes)`, `issued_by ∈ admins.trust`, ed25519 signature.
- `syncSidecars` MUST run at the top of `saveVaultViaDaemon`, re-signing any drifted record and deleting orphan sidecars.
- `sidecarMatches` MUST compare Subject, Grants, Generation, BundleHash, Status, IssuedBy, ExpiresAt, CreatedAt, and the full Binding (Kind, Pubkey, PinExpiry, ClaimedAt) to decide whether to skip re-signing.
- `seedTrustIfPossible` MUST refuse to overwrite an existing `admins.trust` (stat-guard preserves multi-admin trust).

## Forbidden Behaviors
- MUST NOT let exec proceed if `admins.trust` is missing OR lists zero admins.
- MUST NOT trust a record whose `issued_by` is not in `admins.trust` even if the signature verifies.
- MUST NOT accept a record whose `bundle_hash` disagrees with the on-disk `.bundle` file.
- MUST NOT publish signed records with `status: revoked` — the sidecar must be deleted instead.

## Interfaces
- Inputs: `capability.Record` in memory; ed25519 sign RPC to the admin daemon.
- Outputs: JSON files at `<Vault>/capabilities/<lookup_id>.record` (0644) and `<Vault>/admins.trust` (0644).
- Events: `issue`, `revoke`, `claim`, `repin`, `portable` audit events accompany writes.
- Every rewrite of an existing record in `vault.Capabilities` goes through `putCapability` (keeps the unsigned `PortableWrapped` stash; contracts 19, 25).
- Dependencies: `internal/capability` (Record + SigningPayload + Verify), `internal/trust` (Path/Write/Load).

## State & Data Rules
- MUST store admin pubkeys in `admins.trust` as `{name, ed25519_pubkey, age_recipient, note?}`.
- MUST NOT include the ed25519 private key or any age secret in `admins.trust`.
- MUST keep `admins.trust` in the git working tree — it MUST be committed and pushed with the vault.

## Acceptance Criteria
- PASS if `dop exec` refuses when `.record` is absent, `admins.trust` is absent, `bundle_hash` disagrees, or `issued_by` is unknown.
- PASS if `dop vault edit` flipping `status` to `revoked` deletes the `.record` sidecar via `syncSidecars` and subsequent exec rejects the bearer.
- PASS if a second admin joining an existing vault via `dop init --vault` preserves the existing `admins.trust`.
- FAIL if a corrupted `.record` (bad signature or unknown `issued_by`) is accepted.

## Regression Checks
- `v1_signature_verify.sh` covers baseline, missing sidecar, missing trust, tampered record, unknown-admin `issued_by`.
- `v1_v163_gaps.sh` step [5] covers vault-edit → sidecar deletion.
- `v1_v163_gaps.sh` step [3] confirms `admins.trust` is bootstrapped at `init --vault`.

## Open Questions
- Should `admins.trust` itself be signed (chain-of-trust) or is git-repo authenticity sufficient? Current design defers this until v2 / multi-org.
