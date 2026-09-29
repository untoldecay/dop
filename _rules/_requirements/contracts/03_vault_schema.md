# Feature Contract — Vault Schema

## Scope
- The v1 vault.yaml schema stored SOPS-encrypted in the vault repo.

## Purpose
- Give admins one auditable source of truth for admins, integrations, grants, issued capabilities, and generation counters.

## Invariants
- MUST carry `schema_version: v1`; any other value MUST be refused by `ParsePlain`.
- MUST support these top-level keys: `schema_version`, `admins`, `integrations`, `grants`, `capabilities`, `generations`, `vault_context`.
- MUST keep `vault_context` unchanged for the life of the vault (it's the HMAC salt for lookup IDs).
- MUST always store integer generation counters, one per subject.

## Mandatory Behaviors
- MUST store each admin as `{age_recipient, ed25519_pubkey, added_at, note}`.
- MUST store each integration as `{description?, metadata?, tokens: {name: {value, scope_note?}}}`.
- MUST store each grant as `{integration, token, env_prefix}` where `env_prefix` defaults to uppercase integration name when empty.
- MUST store each capability as `{subject, grants[], created_at, expires_at, generation, lookup_id, bundle_hash, issued_by, status, binding?, signature}` keyed by hex `capability_id`.
- MUST refuse to migrate a v0.3 numeric schema automatically — the operator MUST start fresh.
- MUST re-encrypt with the age recipients of every current admin on every save.

## Forbidden Behaviors
- MUST NOT store an unencrypted `vault.yaml` in the vault repo working tree at rest — SOPS `sops:` block MUST be present.
- MUST NOT drop `vault_context` on save.
- MUST NOT store bearer tokens in the vault (bearers are ephemeral, delivered once at issue).

## Interfaces
- Inputs: SOPS-encrypted YAML file at `<Vault>/vault.yaml`.
- Outputs: `vault.Vault` struct via `ParsePlain`/`LoadPlain`; `EmitPlain` renders back to YAML.
- Events: none directly — mutations are audited via the calling command (issue/revoke/repin/claim/etc.).
- Dependencies: `gopkg.in/yaml.v3`, `sops` binary (invoked from the daemon), `filippo.io/age` for encryption.

## State & Data Rules
- MUST store the vault context as a 20-byte random value, hex-encoded.
- MUST also expose it as a `vault-context.bin` sidecar (raw bytes, mode 0644) so agents can compute lookup IDs without decrypting.
- MUST NOT let two different admins share the same `ed25519_pubkey`.
- MUST let `Generations` grow monotonically per subject; reads default to 0 for unknown subjects.

## Acceptance Criteria
- PASS if a freshly-created vault carries `schema_version: v1` and a hex `vault_context`.
- PASS if `token issue` bumps `generations[subject]` by 1 and stores the new capability.
- FAIL if a save produces a vault without a `sops:` block.
- FAIL if two admins land with the same ed25519 pubkey.

## Regression Checks
- Verify `v1_issue_and_persist.sh` step 6 (vault SOPS-wrapped).
- Verify `token revoke` bumps generation and marks status revoked (see `v1_lifecycle_ops.sh`).
- Verify `vault_context` sidecar stays intact across issue/revoke cycles.

## Open Questions
- Do we ever need a v2 schema? If yes, we need a version-negotiation path — currently a v2 vault would be rejected outright.
