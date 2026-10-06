# Feature Contract — Bearer Re-issue

## Scope
- The one re-issue path behind `dop token repin`, `dop token portable --on` and `dop token rotate` (`cmd/dop/tokencmd.go`): `reissueUnclaimed`, `rotateBearer`, `issueBearer`, `markRevoked`, `removeBearerFiles`, `activeBySubject`, `gateProtectedGrants`, `defaultPinTTL`.
- TUI callers: bearer detail actions Repin and Portable (`listView.doPortable`).

## Purpose
- DOP never keeps a bearer it handed out, so any change that needs the bearer value (new PIN, portable copy, rotation) mints a new bearer for the same subject. One path, same rules everywhere.

## Invariants
- A re-issue MUST keep subject, grants and expiry of the old record.
- A re-issue MUST retire the old record in the same vault save that stores the new one.
- Eligibility MUST follow the binding state:
  - claimed (`Binding.Pubkey != ""`): rotate in place (`rotateBearer`); P-256 only, ed25519 refused with the `dop agent migrate` hint.
  - unclaimed PIN-bound: new bearer + new PIN (`reissueUnclaimed`).
  - unbound (`none`): new bearer, no PIN (`reissueUnclaimed`, portable --on only).
- `repin` MUST refuse claimed bearers (points at `dop token rotate`) and non-PIN bearers.
- `repin` and `portable --on` MUST refuse an expired bearer ("issue a new one instead").
- The subject MUST resolve to exactly one active record (`activeBySubject`); revoked, rotated or ambiguous subjects are refused.
- A re-issue MUST carry portability: when the old record had a stash, or the caller is `portable --on`, the new bearer is wrapped to the session admin's age recipient and stored as `PortableWrapped` on the new record.

## Mandatory Behaviors

### Old record
- Unclaimed: `markRevoked` (status `revoked`, `revoked_at` now, generation bumped, re-signed, written via `putCapability` so its stash survives); after the new bearer is saved, `removeBearerFiles` deletes its `.bundle`, `.record` and local agent key files.
- Claimed: status `rotated`, generation = new generation, `BearerWrapped` sealed to the bound P-256 pubkey with AAD `dop-bearerwrap-v1|old_lookup=<old>|new_gen=<n>`, re-signed, sidecar rewritten; the agent switches on its next exec (contract 04).

### New record
- Unclaimed: `issueBearer` with the old binding policy; PIN TTL from `--pin-ttl` (repin) or `defaultPinTTL` (`1h`, portable --on).
- Claimed: pubkey binding copied (`KeyType` p256), `ClaimedAt` now, fresh `EnvWrapped` (`sealEnvWrapped`), no PIN.

### Passphrase
- `gateProtectedGrants`: when any grant is protected the caller MUST own every protected grant and enter the approval passphrase once (`--passphrase-stdin` supported). No passphrase otherwise.
- `portable --off` (not a re-issue) always asks the approval passphrase and clears the stash without re-signing.

### Output
- Unclaimed re-issue: bearer (+ PIN) once on stdout through `printguard.Guard` (contract 13 handoff); stderr status lines.
- Claimed portable --on: stderr `rotated <subject> to gen <n>; the agent picks up the new bearer on its next run`, stdout `portable copy stored for <subject>`; the bearer is never printed.
- Plain `dop token rotate` MUST carry an existing portable copy to the new record (re-wrapped from the fresh bearer) and MUST emit the `rotate` audit event (`extra.replaces`, `old_gen`, `new_gen`).
- `token rotate`: old and new lookup prefixes on stderr; no bearer printed.
- TUI: unclaimed results land on a shown-once screen (`onceScreen`, contract 14); claimed portable --on lands on `✓ Bearer is portable`; both show `useGuidance` (contract 13).

### Audit
- Unclaimed re-issue: `issue` (new lookup) + `revoke` (old lookup), plus `protected_token_issue` when protected grants are carried.
- `repin`: `repin` with `extra.pin_ttl`, `extra.replaces` (old lookup).
- `portable --on`: `portable` with `extra.portable=on`, `extra.replaces`; `portable --off`: `portable` with `extra.portable=off`.

## Forbidden Behaviors
- MUST NOT accept a bearer value from the operator (no bearer paste) for any re-issue.
- MUST NOT leave two active records for one subject after a successful re-issue.
- MUST NOT change grants, expiry or subject during a re-issue.
- MUST NOT print a bearer for a claimed rotation; it travels only inside `BearerWrapped` (and the stash).
- MUST NOT put the passphrase in argv.

## Interfaces
- Inputs: `dop token repin --subject S [--pin-ttl D] [--passphrase-stdin]`; `dop token portable --subject S (--on|--off) [--passphrase-stdin]`; `dop token rotate <lookup|subject>`.
- Outputs: vault save (old retired + new active), sidecars, bundle files, stdout bearer/PIN for unclaimed re-issues.
- Events: `issue`, `revoke`, `repin`, `portable`, `protected_token_issue`.
- Dependencies: admin session (`requireAdminSession`), `internal/envseal`, `admin.WrapToRecipient`, `printguard`.

## State & Data Rules
- Every record rewrite MUST go through `putCapability` (stash carried from the existing entry); only a fresh id uses `capability2VaultCapability` directly.
- The stash stays on the retired record (harmless: the bearer no longer works).
- Retired records are deleted only by `dop token prune` (contract 18): revoked or rotated, aged from `revoked_at` or the rotation seal, older than the cutoff (default `30d`). A rotated record ages from its rotation seal (`BearerWrapped.SealedAt`), so its agent keeps the full cutoff to switch; prune MUST NOT remove it earlier.

## Acceptance Criteria
- PASS if `TestTokenRepin`: unclaimed repin → old revoked, new PIN-bound record with the requested PIN TTL, bearer + PIN on stdout, stash carried; claimed and revoked refused.
- PASS if `TestTokenPortable`: `--off` clears the stash only; claimed `--on` rotates (old `rotated` + `BearerWrapped`, new carries the stash); unclaimed `--on` re-issues with a new PIN; revoked refused.
- PASS if `TestPutCapabilityKeepsPortableStash` passes for revoke, reseal, grants, resign, generation.
- FAIL if a re-issue of a portable bearer produces an active record without `PortableWrapped`.

## Regression Checks
- `go test ./cmd/dop -run 'TestTokenPortable|TestTokenRepin|TestPutCapability'`.
- Grep `cmd/dop` for `v.Capabilities[...] = capability2VaultCapability(` outside `issueBearer` — expect none.

## Open Questions
