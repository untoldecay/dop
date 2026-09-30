# DOP v1.12 — direct availability + transparent bearer rotation

**Status:** design, not yet implemented.
**Author:** Cam + Claude (Opus 4.7)
**Date:** 2026-09-30

## Goal

Two operator-visible outcomes:

1. **Direct availability of grant edits.** `dop token add-grant <tok> <grant>` or `remove-grant` mutates the token *in place*. The holder's bearer keeps working. Their next `dop exec` sees the new env (or stops seeing the removed one) with no re-claim, no new QR, no PIN dance.
2. **Transparent bearer rotation.** Whenever the admin needs to replace a bearer (rotation policy, incident, key change), dop can hand the new bearer to the agent through the vault without going through the claim UX again. Next `dop exec` picks up the new bearer, replaces the old one locally, proceeds.

Both are gated on the agent having a **Secure Enclave-backed P-256 key** (v1.11 default when the binary is properly codesigned). Ed25519 legacy bearers stay on the bundle-only path; migration path is `dop agent migrate <lookup>`.

## Why the current model can't do this

The bundle is AEAD-encrypted with a key derived from the bearer. Only the bearer holder can decrypt. Admin does not hold the bearer after issuance. Therefore admin cannot rewrite the encrypted env in an issued bundle, and there's no way to slip a new bearer to the agent without re-encrypting.

## Solution: piggyback on the agent's P-256 SE key

Apple SE keys support ECDH. The agent's SE key already exists, is used for signing exec challenges, and has its public key stored on the admin-signed `.record` sidecar.

We add an **admin-to-agent secure channel** by generating an ephemeral P-256 keypair on the admin side and running ECDH against the agent's SE pubkey:

```
shared_secret = ECDH(admin_ephemeral_priv, agent_SE_pub)  // admin side
shared_secret = ECDH(agent_SE_priv,        admin_ephem_pub) // agent side
```

Both sides derive the same 32-byte shared secret. HKDF-Expand into a symmetric key. Use it to AEAD-seal a payload. Admin stores the ephemeral pubkey + the sealed payload on the record. Agent reads the record at exec time, opens the payload with its SE key + the admin ephemeral pubkey.

**Every field write generates a fresh admin ephemeral keypair.** No long-lived admin ECDH key on disk. The ephemeral priv key is thrown away immediately after sealing.

## Record schema additions

```go
type Record struct {
    // ... existing v1.11 fields (unchanged) ...

    // v1.12: env resolved from record.Grants, sealed to the agent's
    // SE pubkey via ECDH. Absent = legacy path (env comes from
    // bundle). Present = agent's dop exec MUST prefer this over the
    // bundle env.
    EnvWrapped *WrappedEnv `json:"env_wrapped,omitempty"`

    // v1.12: replacement bearer, sealed to the agent's SE pubkey.
    // Written when admin wants to rotate the bearer transparently.
    // Agent's dop exec: decrypts, writes bearer atomically to disk,
    // uses it going forward. Absent = no rotation pending.
    BearerWrapped *WrappedBearer `json:"bearer_wrapped,omitempty"`
}

type WrappedEnv struct {
    AdminEphemPub   string          `json:"admin_ephem_pub"`   // hex, uncompressed P-256
    Salt            string          `json:"salt"`              // hex, 32B
    Nonce           string          `json:"nonce"`             // hex, 24B (XChaCha20-Poly1305)
    Ciphertext      string          `json:"ciphertext"`        // hex, encrypts JSON({env: {...}, generation: N})
    SealedAt        time.Time       `json:"sealed_at"`
    Generation      uint64          `json:"generation"`        // matches record.Generation; anti-rollback
}

type WrappedBearer struct {
    AdminEphemPub string    `json:"admin_ephem_pub"`
    Salt          string    `json:"salt"`
    Nonce         string    `json:"nonce"`
    Ciphertext    string    `json:"ciphertext"`   // encrypts new bearer string
    SealedAt      time.Time `json:"sealed_at"`
    NewGeneration uint64    `json:"new_generation"` // the generation this bearer belongs to
}
```

**Signing:** the record's admin signature covers `EnvWrapped` and `BearerWrapped` too. Any tamper flips signature verification.

## Trust model

- **Integrity:** admin's ed25519 signature over the record → agent verifies before trusting any wrapped payload. No one can inject a fake env or bearer.
- **Confidentiality:** payload is ECDH-AEAD-encrypted to the agent's specific SE pubkey. Only the machine physically holding that SE key can open it. Compromising the vault repo alone does NOT expose env.
- **Forward secrecy:** admin ephemeral key is thrown away → past sealed payloads can't be decrypted by anyone else even if admin's long-lived keys leak later. (Note: the past *ciphertexts* are still in git history — agent's SE key is still enough to decrypt them. This is not perfect forward secrecy in the classical sense; it's PFS *against admin key leak only*.)
- **Anti-rollback:** `WrappedEnv.Generation` must equal `record.Generation`. `dop exec` refuses env whose generation is below the local floor (`gen-cache`).

## Backward compatibility

- v1.11 records without `env_wrapped`: `dop exec` reads env from bundle as today.
- v1.12 records with `env_wrapped` **and** a legacy ed25519 bearer: admin shouldn't seal (agent can't ECDH). Guardrail: admin refuses to seal env for records whose `binding.key_type != "p256"`, prints a clear "run `dop agent migrate` on the agent first" error.
- v1.12 records with `env_wrapped` + P-256 bearer: exec reads from wrapped, ignores bundle env.

Any admin ≥ v1.12 processing a record ≤ v1.11 leaves the env_wrapped field unset — no forced upgrade.

## Failure modes (agent side)

- **`env_wrapped` open fails** (agent SE key deleted, admin ephemeral corrupted, wrong generation, ...): exec errors with actionable message, does NOT silently fall back to bundle env (that would be a downgrade). Admin can `dop token reseal <tok>` to rewrap.
- **`bearer_wrapped` open fails**: exec keeps using existing bearer, logs a WARN. Non-fatal — the old bearer is still valid until admin explicitly revokes.

## Failure modes (admin side)

- **Agent's SE pubkey is stale** (agent rotated their key): admin's seal encrypts to the wrong pubkey; agent can't open. Solution: agent's `dop agent migrate` triggers admin-side re-seal (via a "please rewrap" marker in the vault). For v1.12 M1-M3, we defer this: assume SE pubkey is stable until v1.13.

## CLI additions

```
# READ (already in v1.11.1)
dop token show <lookup|subject>
dop grant show <grant-id>

# WRITE (v1.12 new)
dop token add-grant    <tok> <grant-id> [--force-legacy]
dop token remove-grant <tok> <grant-id>
dop token reseal       <tok>                     # rewrap env_wrapped from current grants
dop token rotate       <tok>                     # generate new bearer, wrap it, agent picks up next exec

# GRANT-INVERSE (nice-to-have, v1.12 M3)
dop grant add-token    <grant> <tok>
dop grant remove-token <grant> <tok>
```

## Implementation plan (milestones)

- **M1** — ECDH primitive package (`internal/agentkey/ecdh.go`)
  - Admin-side: `SealTo(agentP256Pub, plaintext) → (ephemPub, salt, nonce, ciphertext)`
  - Agent-side: `Open(ephemPub, salt, nonce, ciphertext, agentSEKey) → plaintext`
  - Uses stdlib `crypto/ecdh` + `golang.org/x/crypto/hkdf` + `chacha20poly1305`
  - Unit tests: roundtrip, tamper (auth failure), wrong-key (auth failure)

- **M2** — Wire seal/open into schema + admin/exec
  - Add `EnvWrapped` / `BearerWrapped` fields to `capability.Record` + YAML/JSON
  - Update `signRecordViaDaemon` to sign the new fields
  - Admin: on issue for P-256 bearers, generate `EnvWrapped` alongside the bundle env
  - Exec: prefer `EnvWrapped` over bundle env when present; verify generation

- **M3** — CLI: `dop token add-grant` / `remove-grant` / `reseal`
  - Load record → mutate `Grants` → resolve fresh env from vault → re-seal `EnvWrapped` → re-sign → save
  - E2E: issue → add-grant → verify agent's exec picks up new env

- **M4** — CLI: `dop token rotate` (bearer rotation)
  - Generate new bearer string → wrap → set `BearerWrapped` → re-sign
  - Agent exec: opens `BearerWrapped`, writes new bearer to disk, replaces old, continues with new
  - Old bearer stays valid until admin explicitly revokes (grace period)

- **M5** — Docs + full regression + release
  - Update contracts docs, PIN-Claim-and-Approval, README
  - New e2e: v1_1120_direct_availability.sh, v1_1120_bearer_rotation.sh
  - Cut v1.12

## Non-goals

- Perfect forward secrecy against a compromised agent SE key.
- Multi-agent broadcast (multiple agents sharing one record). Each record is single-agent by design; multi-agent = multiple records.
- Retroactive SE migration during admin ops. Admin refuses to seal for legacy ed25519 bearers with a clear "migrate first" message.

## Open questions

1. Cipher choice: `XChaCha20-Poly1305` (24B nonce, random-nonce safe) vs `AES-256-GCM` (12B nonce, faster on ARM crypto). Recommendation: XChaCha20 for nonce-hygiene safety since we don't need FIPS.
2. Key derivation: HKDF-SHA-256 from ECDH secret is standard; salt = per-payload random 32B. Confirmed.
3. Should we also encrypt `.bundle` env to the SE key on issue for defense-in-depth, or does `env_wrapped` in the record supersede the bundle env entirely? Recommendation: for P-256 bearers on v1.12, drop bundle env (set to empty map); env_wrapped is the truth. Backwards-compat only for older bearers.
