# Feature Contract — Admin Invite Lifecycle (fire-and-forget)

## Scope
- `dop team invite` stages an invite + exits (no polling).
- `dop team approve-invite <id>` completes the flow when the teammate has responded.
- `dop team cancel-invite <id>` drops a pending invite.
- TUI Team view Pending tab + invite waiting screen.

## Purpose
- Let M1 issue an invite and continue life. M2 joins at their leisure. M1 approves when ready.

## Invariants
- `dop team invite` MUST exit as soon as the invite is staged + pushed. No polling loop.
- `dop team invite` MUST print `invite_id`, `PIN`, `vault URL`, and the approve-later hint on stderr.
- MUST support invite id prefix (≥ 8 hex) in `approve-invite` + `cancel-invite` via `resolveInviteID`.
- Approve path MUST pull vault first, read `response.json`, call `resp.Verify()`, prompt for approval passphrase, run `completeInvite`, push.
- Shared-identity invites (`--share-identity`) MUST short-circuit on approve ("nothing to approve on this side") — the join completes on M2's end automatically.
- Default `--pin-ttl` MUST be `7d` (168h). Accepts d/w suffixes via `parseDurationLoose`.
- Cancel path MUST delete the invite file, the response file (if present), AND the identity-blob file (for shared-identity invites) before `gitAddCommitPush`.

## Mandatory Behaviors
- `dop team invite` MUST NOT poll, wait, or block after push. Operator-visible: subprocess exits in < 2s.
- `dop team approve-invite` MUST return a clear "no response yet" message (rc=1) when no response file exists.
- `dop team approve-invite` MUST fail with a specific error when the response signature doesn't verify.
- `dop team cancel-invite` MUST be idempotent — running on a non-existent id returns a clean "no matching invite" error.
- TUI invite view MUST transition to a `waiting` state on subprocess rc=0, showing PIN + invite_id + vault URL + the full join incantation. Enter closes (invite stays live); esc opens a cancel-confirm overlay.
- TUI Team view MUST render tabs `Members N` / `Pending N` on the title row (contract 14); `tab` switches and resets the cursor; esc leaves the view.
- Pending rows: label, kind, expires in; the invite id goes to the status hint (`midTrunc`).
- `a` on a pending row MUST open an approval-passphrase prompt that pipes to `dop team approve-invite --passphrase-stdin`; on a shared-identity invite it MUST refuse with "nothing to approve here". `d` MUST open a confirm, then shell out `dop team cancel-invite`. Both re-check the session first (`sessionGuard`).
- Pending rows MUST carry `✓ ready` when `admininvite.ReadResponse(paths, id)` succeeds (not for shared-identity invites).
- Empty Pending tab: `No pending invites. Open one from the menu: Add › Device or Team member.`
- `--timeout` flag MUST remain parseable (no-op) for backward-compat with pre-rc7o scripts.

## Forbidden Behaviors
- MUST NOT revive the inline polling loop.
- MUST NOT auto-approve a response signature without the typed approval passphrase (security chokepoint).
- MUST NOT auto-approve on cross-timezone / long-latency responses — the operator is the chokepoint.
- MUST NOT send the approval passphrase as a command-line argument. Always via `--passphrase-stdin`.

## Interfaces
- Inputs:
  - CLI: `dop team invite --name <label> [--share-identity] [--pin-ttl 7d]`, `dop team approve-invite [--passphrase-stdin] <id>`, `dop team cancel-invite <id>`
  - TUI: Team view Pending tab (`a` approve, `d` delete, `tab` members); invite view waiting state (enter close, esc cancel)
- Outputs:
  - stderr: `invite_id`, `PIN`, `vault URL`, approve-later hint, operator-facing success/failure messages
  - vault: `pending-admin-invites/<id>.invite.json`, `.response.json` (M2), `.identity-blob` (shared-identity)
  - git: cleanup commit on cancel
- Events: `invite` (open), `invite_response` (M2 join), `invite_complete` (approve), `invite_cancel` (cancel; not emitted today, see Open Questions)
- Dependencies: `admininvite` package, `approval.Verify`, daemon admin session

## State & Data Rules
- Invite id MUST be 16-hex-char random (`admininvite.NewInviteID`).
- PIN MUST be `XX-XX-XX` alpha format (6 letters, 2 hyphens).
- Response signature MUST be verified before completing the invite.
- `completeInvite` MUST assign a numeric suffix to the admin key when a different pubkey already lives under the invite's name.

## Acceptance Criteria
- PASS if `dop team invite --name alice` exits in < 2s and prints `invite_id`.
- PASS if the invited admin's `dop admin join` writes a response file within the TTL window.
- PASS if `dop team approve-invite <prefix>` with the correct approval passphrase adds the admin + pushes.
- PASS if `dop team cancel-invite <prefix>` deletes the invite + response + blob + pushes.
- PASS if the TUI Pending tab shows `✓ ready` once the response file exists.
- FAIL if the invite subprocess ever polls (sleeps + reads vault repeatedly after push).
- FAIL if an auto-approval ever happens without the operator typing the approval passphrase.
- FAIL if the default `--pin-ttl` reverts to anything less than `7d`.

## Regression Checks
- Verify `dop team invite --name test` exits cleanly without hanging (no polling).
- Verify the Pending tab's `✓ ready` badge updates after an invited machine runs `dop admin join`.
- Verify `dop team cancel-invite <non-existent-id>` returns a clear error without crashing.

## Open Questions
- Add `dop team sweep-expired` to auto-cancel pending invites past their TTL? Not shipped — operators clear via `d` in the TUI.
- Should the TUI auto-detect "response ready" and offer a one-key approve from the waiting screen (bypassing the Team Pending navigation)? Current flow is Team → Pending → `a`.
- `dop team cancel-invite` (`cmd/dop/stubs.go::runTeamCancelInvite`) emits no audit event and `internal/audit` has no `invite_cancel` constant. Contract kept; code finding.
