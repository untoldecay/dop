# Feature Contract — PIN-Claim Binding

## Scope
- Binding a bearer to a per-agent ed25519 keypair via a short-lived PIN, so bearer leakage alone doesn't grant execution.

## Purpose
- Turn a stolen bearer into a useless token: the exec-side proof of possession requires a private key that never travels through chat.

## Invariants
- MUST default `dop token issue` to `--bind` (PIN-claim binding on).
- MUST offer three binding modes: `pin` (default), `pubkey` (admin-supplied), `none` (opt-out).
- MUST generate PINs as `XX-XX-XX` using the alphabet `ABCDEFGHJKMNPQRSTUVWXYZ` (24 chars, confusables removed).
- MUST HMAC the PIN with the bearer as key (`capability.HashPIN`) and store the hex hash inside the bundle envelope.
- MUST default the PIN TTL to 5 minutes and store `pin_expiry` as unix seconds in the envelope binding.
- MUST persist agent private keys at `<Root>/agent-keys/<lookup_id>.key`, mode 0600, raw ed25519.

## Mandatory Behaviors
- `dop token issue --bind` MUST print `bearer\nPIN\n` on stdout and human text on stderr.
- `dop claim <PIN>` MUST require the same bearer that was issued.
- `dop claim` MUST refuse when the bundle binding is missing, kind is not `pin`, already carries a `pubkey`, or the PIN is expired.
- `dop claim` MUST verify the PIN via `capability.VerifyPIN` (constant-time compare).
- `dop claim` MUST reorder the persistence steps as: agent key → bundle rename → record sidecar → vault save.
- `dop claim` MUST refuse to run without an active admin session (vault mutation requires signing).
- `dop token repin --subject S` MUST regenerate the PIN while keeping the bearer intact.

## Forbidden Behaviors
- MUST NOT store the PIN anywhere in plaintext — only its bearer-keyed HMAC.
- MUST NOT allow a second `dop claim` on an already-claimed bearer (must revoke + reissue).
- MUST NOT allow `token repin` on a claimed capability (only unclaimed ones).
- MUST NOT persist the agent private key under any group-readable mode.

## Interfaces
- Inputs: `$DOP_TOKEN` or `--token-file <path>`; PIN as CLI arg.
- Outputs: bearer + PIN at issue; agent key file at `<Root>/agent-keys/<lookup_id>.key`; updated bundle + record.
- Events: `issue` (with binding kind), `claim_pending`, `claim` (with pubkey), `claim_denied` (reason), `repin`.
- Dependencies: `internal/capability`, `internal/vault`, `internal/pendingclaim`, `internal/approvalserver`, `internal/audit`.

## State & Data Rules
- MUST update the vault record's `binding.pubkey` + `claimed_at` on successful claim.
- MUST bump the subject's generation counter as part of every claim (rollback-replay hardening).
- MUST NOT rewrite the bundle to remove the pin hash until after the pubkey binding has been written.

## Acceptance Criteria
- PASS if `dop token issue` with default flags emits bearer + PIN.
- PASS if `dop claim WRONG-XX-YZ` fails while the correct PIN succeeds.
- PASS if `dop exec` on an unclaimed bound bearer fails with "requires a PIN claim first".
- PASS if `dop exec` after successful claim verifies the local agent key matches `binding.pubkey`.
- FAIL if PIN expiry is not enforced.
- FAIL if double-claim on the same bearer succeeds.

## Regression Checks
- `v1_pin_claim.sh` covers the full happy path + wrong PIN + double claim + PIN expiry + `token repin`.
- `v1_sas_approval.sh` covers the SAS/pending-claim slice via `--no-tunnel`.

## Open Questions
- Should PIN entropy be increased if we ever remove the argon-cost-and-rate-limit web gate? Currently 24^6 ≈ 191M is sized against the 5-min claim window and rate-limited approval.
