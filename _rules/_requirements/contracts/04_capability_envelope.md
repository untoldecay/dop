# Feature Contract — Capability Envelope

## Scope
- The binary bundle file (`capabilities/<lookup_id>.bundle`) that carries a bearer's env vars, encrypted so only the bearer holder can open it.

## Purpose
- Deliver credentials to agents without letting anyone else with vault-repo access read them.

## Invariants
- MUST use the fixed-header binary layout: `magic(4)|version(4)|cap_id(32)|generation(8)|expires_at(8)|nonce(24)|wrapped_key(48)|ciphertext`.
- MUST use magic bytes `DOPB` and `version == 1`.
- MUST derive the wrap key with HKDF-SHA256, IKM=bearer, salt=`"dop-v1-wrap"`, info=`"cap:"||capability_id`.
- MUST use XChaCha20-Poly1305 for both the key wrap and the env encryption.
- MUST bind AAD `= capability_id || generation(LE) || expires_at(LE)` on both AEAD operations.
- MUST derive the env-encryption nonce from the outer nonce by XOR'ing byte 0 with 0x01 — safe because K_bundle is unique per issuance.

## Mandatory Behaviors
- MUST refuse to write a bundle when the env map is empty.
- MUST refuse to write a bundle whose `expires_at` is zero.
- MUST refuse to open a bundle with wrong magic, wrong version, or an expired `expires_at`.
- MUST refuse to open a bundle whose generation is lower than the caller's `MinGeneration` — rollback-replay defense.
- MUST verify the inner (plaintext-side) `generation` + `expires_at_unix` fields match the outer header — defense in depth.
- MUST include the encrypted env, subject, and (when set) binding info inside the AEAD-sealed payload.

## Forbidden Behaviors
- MUST NOT store the bearer inside the bundle.
- MUST NOT extend the header format without bumping `Version`.
- MUST NOT reuse the outer nonce as-is for env encryption — the 0x01 XOR is required.

## Interfaces
- Inputs: `capability.WriteOpts{CapabilityID, Bearer, Generation, ExpiresAt, Subject, Env, Binding, Rand?}`.
- Outputs: bundle bytes (also written to `w`); a hex sha256 of those bytes for the record `BundleHash`.
- Events: none directly.
- Dependencies: `golang.org/x/crypto/chacha20poly1305`, `golang.org/x/crypto/hkdf`.

## State & Data Rules
- MUST persist bundles at `<Vault>/capabilities/<lookup_id>.bundle`, mode 0644 (public salt + bearer-locked cipher).
- MUST compute `lookup_id = HMAC-SHA256(vault_context, bearer)[:20]` and use it as the filename.

## Acceptance Criteria
- PASS if a bundle written with bearer B decrypts with B and no other.
- PASS if flipping any byte of the ciphertext or header causes `capability.Read` to fail.
- PASS if a stale bundle (gen < min) is rejected as "superseded".
- FAIL if the same nonce is used across the wrap and env encryption with the SAME key (contract requires different keys).

## Regression Checks
- `v1_exec_flow.sh` tamper test (flip last byte → read fails).
- Wrong-bearer test (unknown bearer → read fails).
- Expiry test (fresh bearer with 1s TTL → read fails after sleep).

## Open Questions
- Should we add a max-bundle-size guard to `capability.Read` so a malicious file can't cause a huge allocation?
