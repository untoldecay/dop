# v1.11 — agent private keys → Secure Enclave

Branch: `feat/v1.11-agent-key-secure-enclave`

## Goal

Kill the "cp `agent-keys/<lookup>.key` + `capability.bundle` + `vault-context.bin` to another Mac, dop exec works from there" attack. The key file today is a raw 64-byte ed25519 at mode 0600, portable to any machine.

## Decision matrix

| Item | Decision | Rationale |
|---|---|---|
| Key scheme | ECDSA P-256 | Apple's Secure Enclave supports P-256 as a first-class key type; Ed25519 is *not* SE-backed on macOS. |
| Signature encoding | X9.62 / DER | What `SecKeyCreateSignature` returns for `kSecKeyAlgorithmECDSASignatureMessageX962SHA256`. |
| Legacy Ed25519 | Kept indefinitely as `key_type: ed25519` | Verifier keeps both paths; existing bearers keep working. |
| Backward-compat marker | `binding.key_type` (empty ⇒ ed25519) | Schema-additive; old records don't need rewriting. |
| Migration | Explicit `dop agent migrate <lookup-id>`, needs admin session | Auto-migration risks bricking claims; admin needed to re-sign the record. |
| Old-key retention | 12h after successful migration, then delete | Escape hatch if the SE-backed key is broken; auto-cleanup so users don't accumulate cruft. |
| Ownership | Daemon owns SE key; CLI talks over Unix socket | Single signing chokepoint, auditable, matches existing admin-key model. |
| Biometric prompt | None (Mode 1) | Zero-UX-regression from today. Optional biometric mode is a future opt-in per grant. |
| Linux/CI | File-backed P-256 with `DOP_ALLOW_FILE_KEYS=1` | Doesn't silently downgrade; makes the risk visible in `dop doctor`. |
| macOS w/o usable SE (rare) | Refuse unless `DOP_ALLOW_FILE_KEYS=1` | Prevents accidental extractable-key shipments on hardware that could have used SE. |

## Threat model — what this fixes vs doesn't

**Fixes:**
- Copy of `~/.config/dop` to another Mac → SE key doesn't come with; new machine can't exec.
- Laptop theft (unlocked but the SE requires TCC / signed process) → key material never leaves hardware.

**Does NOT fix:**
- Malicious process running as your uid on your Mac can still ask the daemon to sign (or ask the CLI, if we allowed direct CLI SE access — we don't).
- A compromised agent that has completed `dop exec` still receives the injected env vars and can exfiltrate.
- Vault sops+age keys are unchanged (admin's threat model, not this release).

The critical framing (from advisor): "SE removes portable key theft, but it does not change the same-machine trust model. Pair with brokered operations if you want more."

## Package layout

```
internal/agentkey/
  store.go                    Store + Backend interfaces
  file_backend.go             ed25519 (legacy) + P-256 (opt-in) file storage
  keychain_backend_darwin.go  SE-backed P-256 (cgo stub for now)
  keychain_backend_other.go   Non-darwin no-op
  select.go                   Open() + Create() + Delete() facade
  verify.go                   Signature verify branching on key type
  hash.go                     SHA-256 helper
```

`cmd/dop/claimcmd.go` and `cmd/dop/execcmd.go` migrate their `writeAgentKey` / `loadAgentKey` calls to `agentkey.Create` / `agentkey.Open`. The daemon gains new socket ops for `sign_challenge`.

## Schema

`vault.Binding`:
```yaml
kind: pin
pubkey: <hex>         # 32 bytes ed25519 OR 65 bytes P-256 uncompressed (0x04||X||Y)
key_type: p256        # NEW in v1.11; empty means "ed25519" for old records
claimed_at: ...
```

`capability.EnvelopeBinding` (bearer-locked view inside the bundle):
```json
{
  "kind": "pin",
  "pubkey": "...",
  "key_type": "p256"
}
```

## Verifier branching

`internal/agentkey.Verify(keyType, pubkey, challenge, sig)` handles both:

- `"" | "ed25519"` → `ed25519.Verify(pub, challenge, sig)`
- `"p256"` → `ecdsa.VerifyASN1(pub, sha256(challenge), sig)`

`cmd/dop/execcmd.go:verifyBinding` uses `EffectiveKeyType()` to pick.

## Daemon socket protocol (upcoming commit)

New op: `sign_challenge`
```
Request:  { "op": "sign_challenge", "data": { "lookup_id": "...", "challenge_b64": "..." } }
Response: { "signature_b64": "..." }
```

The daemon:
1. Loads the Store via `agentkey.Open`
2. Enforces session TTL (already the case for all daemon ops)
3. Signs and returns
4. Audit-logs `agent_key_sign` with `lookup_id` and caller `pid` (for local anomaly detection)

## Migration flow (upcoming commit)

`dop agent migrate <lookup-id>`:

1. Require admin session
2. Load the current bearer's binding (must be `kind: pin`, currently claimed)
3. `agentkey.Create(paths, lookupID, "p256")` — new SE-backed key
4. Prompt for approval passphrase (mirror the claim approval gate — this is a real re-enrollment)
5. Re-sign the capability record with the new pubkey + `key_type: p256`
6. `saveVaultViaDaemon` → autopush
7. Record the migration event in the audit log
8. Set a deferred-delete marker on the old key file (12h TTL)

Background sweep (in `dop admin login` or `dop doctor`):
- Scan `agent-keys/*.key` files with migration markers older than 12h → delete

## Doctor + status surfacing

`dop doctor`:
```
agent keys:
  3 keys backed by macOS Secure Enclave  ✓
  1 key backed by file  (legacy ed25519 — run 'dop agent migrate <lookup>' to harden)
```

`dop admin status`:
```
agent keys: SE=3 file=1 (1 pending migration)
```

## Testing plan

Unit (already):
- ed25519 + p256 round-trip
- P-256 file backend refuses without opt-in
- Load prefers ed25519 then p256
- Loose file perms refused

E2E (upcoming):
- Fresh claim on macOS → P-256 SE (via mock or `DOP_KEYCHAIN_STUB=1`)
- Fresh claim on Linux → refuse without opt-in; succeed with `DOP_ALLOW_FILE_KEYS=1`
- Legacy ed25519 keys continue to `dop exec` correctly
- Migration end-to-end: verify old key stops working after 12h grace
- Delete cleans up both `.key` and `.p256` files

## Open questions (for follow-up)

- SE cgo bridge: build via `cgo -F Security` — need to confirm no runtime dylib load issues in Homebrew installs
- Signature envelope format: raw bytes with `key_type` alongside vs. a self-describing container — leaning toward the current approach (pubkey + sig + key_type are all first-class fields, no envelope)
- Whether the migration command should also revoke the *bundle* (which is keyed off the bearer) — my current answer: no, keep the bundle; just update the pubkey binding in the record
