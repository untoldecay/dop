# Feature Contract — Handoff Text Shape

## Scope
- The clipboard-copied / stderr-rendered text an admin pastes into a receiving agent's chat to deliver a bearer + PIN. Covers the TUI "Issue token" success view and the `dop token issue` CLI output.

## Purpose
- Keep the handoff shaped like data (one command to run) not like directive prose, so prompt-injection detectors in agent harnesses don't block it and so the receiving agent can't be re-prompted by text that is really an admin paste.

## Invariants
- The handoff MUST contain the bearer, the PIN (when PIN-bound), and exactly one `dop claim …` command.
- The handoff MUST NOT contain any text AFTER the claim command that reads as instructions to the receiving agent.
- The handoff MUST NOT contain the strings `poll`, `--status`, `--cancel`, `state`, `approved`, `expired`, `absent`, `abort`.
- The handoff MUST NOT contain multiple imperative sentences chained with "then", "while", or "if".
- Any guidance about how to monitor, interpret, or abort a claim MUST live in the runtime output of `dop claim` itself, not in the paste.

## Mandatory Behaviors
- TUI "Issue token" success view MUST render only: a short noun-phrase preface (≤ 1 line), the bearer, the PIN (if any), and the single claim command.
- `dop token issue` CLI MUST print the bearer and PIN on their own lines on stdout, and MUST print a one-line "Tell your agent: dop claim <PIN>" on stderr. No additional prose on either stream.
- `dop claim` MUST stream polling + abort guidance to stderr when it enters the PENDING state.
- When `DOP_ALLOW_FILE_KEYS=1` is enabled on the admin side, the handoff MUST embed `DOP_ALLOW_FILE_KEYS=1` and `--key-type p256` in the single claim command (no separate explanatory line).

## Forbidden Behaviors
- MUST NOT paste "Run this in your shell", "it blocks until", "poll progress every", "state field means", "If the user wants to abort".
- MUST NOT include ASCII QR art in the paste.
- MUST NOT include URLs (public or LAN) in the paste — those are emitted at claim time.
- MUST NOT include SAS codes in the paste — SAS is emitted at claim time for admin-side verification.

## Interfaces
- Inputs: bearer (string), PIN (string, may be empty for `--no-bind`), `prefs.AllowFileKeys` (bool).
- Outputs: a single string copied to clipboard AND rendered in the TUI success pane; CLI equivalent printed on issue.
- Events: none emitted by the handoff path.
- Dependencies: `copyToClipboard`, `pendingclaim.TTL` (for claim runtime message), terminal QR renderer (claim side only).

## State & Data Rules
- The handoff string is built in `internal/tui/views.go` on the Issue token success render path (single builder, single string).
- The claim runtime message is built in `cmd/dop/claimcmd.go` after the QR + URL block, before the terminal QR art.
- Neither path reads from or writes to persistent state.

## Acceptance Criteria
- PASS if the TUI handoff, run through a case-insensitive grep for any of the forbidden strings, returns no match.
- PASS if the TUI handoff contains exactly one occurrence of `dop claim ` as a substring.
- PASS if the TUI handoff contains the bearer and (when PIN-bound) the PIN.
- PASS if `dop claim` runtime output contains the polling guidance (`--status`, `--cancel`, `pending`, `approved`, `expired`) when it enters PENDING.
- FAIL if any forbidden phrase appears in the handoff builder output.
- FAIL if `dop claim` does NOT print the polling guidance before blocking.

## Regression Checks
- Verify `internal/tui/views.go` handoff block has no trailing prose after the claim command.
- Verify the handoff builder has a comment pointing at this contract so future edits don't drift silently.
- Verify a Go unit test (`internal/tui/handoff_test.go` or equivalent) grep-asserts the forbidden strings and the required substrings.
- Verify `dop claim` runtime output includes the polling + cancel block (shell test on PENDING output).

## Open Questions
- Should the preface line be allowed at all, or should the paste be the bare command? Current contract allows one short noun-phrase line ("Scoped credential access via DOP — run:") because it gives the receiving agent a one-token hint without any imperative verb. If an injection detector flags even that, drop it.
- Should the SAS appear in the paste for defense in depth (admin verifies the SAS on their phone matches what the receiving agent reports)? Currently NO — SAS is a verification artifact between admin and the approval page, not the admin and the agent.
