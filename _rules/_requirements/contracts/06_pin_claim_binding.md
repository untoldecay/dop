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
- MUST default the PIN TTL to `defaultPinTTL` (1h, rc11; fits a chat back-and-forth) and store `pin_expiry` as unix seconds in the envelope binding.
- MUST persist agent private keys at `<Root>/agent-keys/<lookup_id>.key`, mode 0600, raw ed25519.

## Mandatory Behaviors
- `dop token issue --bind` MUST print `bearer\nPIN\n` on stdout and human text on stderr.
- `dop claim <PIN>` MUST require the same bearer that was issued.
- `dop claim` MUST refuse when the bundle binding is missing, kind is not `pin`, already carries a `pubkey`, or the PIN is expired.
- `dop claim` MUST verify the PIN via `capability.VerifyPIN` (constant-time compare).
- `dop claim` MUST reorder the persistence steps as: agent key → bundle rename → record sidecar → vault save.
- `dop claim` MUST refuse to run without an active admin session (vault mutation requires signing).
- `dop token repin --subject S [--pin-ttl D]` MUST re-issue the unclaimed PIN-bound bearer: new bearer + new PIN, same subject / grants / expiry, old record revoked in the same save, portable stash carried. No bearer paste. Rules in contract 25.
- The TUI bearer detail MUST offer Repin only on an unclaimed PIN-bound bearer, with a PIN validity picker (`repinTTLPresets`: 1h default, 5m, 30m, 4h, 24h) and a shown-once result screen.

## Forbidden Behaviors
- MUST NOT store the PIN anywhere in plaintext — only its bearer-keyed HMAC.
- MUST NOT allow a second `dop claim` on an already-claimed bearer (must revoke + reissue).
- MUST NOT allow `token repin` on a claimed bearer (refused, points at `dop token rotate`) or on a non-PIN bearer.
- MUST NOT keep the old bearer working after a repin (DOP never stores the bearer, so a new PIN needs a new bearer).
- MUST NOT persist the agent private key under any group-readable mode.

## Interfaces
- Inputs: `$DOP_TOKEN` or `--token-file <path>`; PIN as CLI arg.
- Outputs: bearer + PIN at issue; agent key file at `<Root>/agent-keys/<lookup_id>.key`; updated bundle + record.
- Events: `issue` (with binding kind), `claim_pending`, `claim` (with pubkey), `claim_denied` (reason), `repin` (with `extra.pin_ttl`, `extra.replaces`) + `issue` + `revoke` on repin.
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
- `TestTokenRepin` (`cmd/dop/portable_test.go`) covers re-issue, PIN TTL, stash carry-over, claimed / revoked refusal.
- `v1_sas_approval.sh` covers the SAS/pending-claim slice via `--no-tunnel`.

## Open Questions
- Should PIN entropy be increased if we ever remove the argon-cost-and-rate-limit web gate? Currently 24^6 ≈ 191M is sized against the 1h default claim window and rate-limited approval.

## Related contracts
- **25 (Bearer Re-issue)** — repin is one of the three re-issue entry points.
