# Feature Contract — Approval Gate

## Scope
- The approval passphrase, the shared 8-attempt rate limit, and the rules that make claim approval a genuine second factor.
- rc5 Option A expansion: approval also gates every **print surface** (`dop use`, `dop token issue`, `dop env`, `dop claim --shell`) via `internal/cli/printguard`.

## Purpose
- Prevent a same-uid agent (or anyone with the pending-claim URL) from finalizing a claim on their own.
- Prevent an LLM-driven `! dop <print>` call from leaking a bearer into chat transcripts without operator consent.

## Invariants
- MUST maintain an approval passphrase distinct from the admin passphrase.
- MUST hash it with argon2id (t=3, m=64 MiB, p=4, keyLen=32, 16-byte random salt) — RFC-9106 second recommended set.
- MUST require a minimum length of 10 characters when setting the approval passphrase.
- MUST store the hash at `<KeysDir>/approval.hash` mode 0600.
- MUST NOT accept an approval decision without a valid passphrase, on any code path.

## Mandatory Behaviors
- `dop admin init` MUST prompt for the approval passphrase after the admin passphrase.
- `dop admin set-approval` MUST require an active admin session before rotating the hash.
- `dop approve <SAS>` MUST prompt for the passphrase interactively (or `--passphrase-stdin`) BEFORE mutating the pending-claim file.
- Web `POST /c/<token>/approve` MUST verify the passphrase against `approval.Verify` BEFORE calling `markDecided`.
- Both the CLI and web paths MUST share the pending-claim's `FailureCount` field via `pendingclaim.BumpFailure`.
- `BumpFailure` and `SetState` MUST hold a `LOCK_EX` flock on `<PendingDir>/<lookup_id>.lock` for their read-modify-write section.
- The pending claim MUST be auto-rejected when `FailureCount` reaches `pendingclaim.MaxFailures` (8).
- **Print surfaces (rc5 Option A)** — `dop use` / `dop token issue` / `dop env` / `dop claim --shell` MUST route every print through `printguard.Guard`. Guard MUST require approval regardless of tty state. Two bypasses:
  - `DOP_FROM_TUI=1` — TUI subprocess invocation; captured output goes to the TUI render path, not a transcript.
  - `DOP_APPROVAL_PASSPHRASE` — scripted/CI pre-approval, verified via `approval.Verify`.
- **Trust-context cache** — see contract 20. On `KindUse` + `KindEnv` + non-tty + daemon reachable, Guard MUST serve a cache hit without re-prompting.
- **Local osascript dialog** — on darwin with GUI reachability (`launchctl managername == Aqua` AND `/dev/console` uid matches), Guard MUST prompt via `admin.ApprovalPopup` RPC → daemon-side `approvalprompt.Ask`. Timeout from `userprefs.ApprovalPopupTimeoutSeconds` (default 60s).
- **Phone fallback** — on local-popup timeout OR daemon unreachable OR `decision=unsupported`, Guard MUST escalate to `printapproval.Run` (tunnel + QR + mobile approval; see contract 08).

## Forbidden Behaviors
- MUST NOT reuse the admin passphrase for approval (never type the master secret into a phone form).
- MUST NOT fail-open on `client.Status()` errors during `dop team remove` self-check.
- MUST NOT allow `dop admin set-approval` to run without a session.
- MUST NOT allow a same-uid attacker to bypass the shared counter by attacking one path only.
- MUST NOT log the passphrase or its hash anywhere.

## Interfaces
- Inputs: TTY prompt (or `--passphrase-stdin`) for CLI; HTML form for web.
- Outputs: `approval.Verify` returns `(bool, error)`; `pendingclaim.BumpFailure` returns `(count, autoRejected, err)`.
- Events: `claim_approved`, `claim_denied` (with reason=`pin_mismatch`|`rejected`|`approval_timeout`|`pin_expired`), `print_approval_requested`, `print_approval_granted`, `print_approval_denied` (with `extra.surface` ∈ {`print_use`,`print_issue`,`print_env`,`print_claim`} and `extra.channel` ∈ {`local`,`phone`,`env`,`trust_context`,`shell_trust`}).
- Dependencies: `golang.org/x/crypto/argon2`, `golang.org/x/sys/unix` (flock).

## State & Data Rules
- MUST store `{version, salt(b64), hash(b64), t, m, p, k}` in `approval.hash`.
- MUST store `FailureCount` as an integer field inside each pending-claim JSON.
- MUST delete the lockfile when the pending-claim JSON is removed.

## Acceptance Criteria
- PASS if 8 wrong CLI passphrase attempts abort the pending claim.
- PASS if `dop admin set-approval` refuses when locked.
- PASS if a wrong passphrase on the web form reports remaining attempts and does not approve.
- FAIL if the CLI and web paths accept 8 attempts each (16 total).
- FAIL if `handleApprove` runs `markDecided` before verifying the passphrase.

## Regression Checks
- `v1_v163_gaps.sh` step [7] hammers 8 wrong CLI attempts and confirms auto-reject.
- `v1_web_approval.sh` step [4] confirms wrong passphrase does not approve.
- `v1_sas_approval.sh` step [8] confirms wrong passphrase is refused.

## Open Questions
- Should the approval passphrase have an OS-keyring fallback (Touch ID unlock) to eliminate the "typed on phone" exposure?
