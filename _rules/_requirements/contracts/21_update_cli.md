# Feature Contract — Self-Update

## Scope
- `dop update` CLI + TUI `More › Update` entry.
- Rollback store at `~/.local/share/dop/old-versions/`.

## Purpose
- Replace the running `dop` binary from GitHub releases without curl + sudo + tar steps.
- Preserve the last N versions for rollback.

## Invariants
- MUST download to a temp dir, verify SHA256 against `checksums.txt`, extract, THEN atomic-rename over the installed location.
- MUST support `stable` channel (via `/releases/latest`) and `dev` channel (via `/releases?per_page=30` sorted by `published_at` desc).
- MUST keep the last 3 previous binaries at `~/.local/share/dop/old-versions/dop-<version>`; older versions MUST be pruned.
- MUST return exit code 0 when installed version already matches the target.
- MUST NOT touch disk when `--check-only` is set.

## Mandatory Behaviors
- MUST support flags: `--check-only`, `--channel {stable|dev}`, `--version <tag>`, `--rollback`, `--yes`.
- MUST honor `DOP_FROM_TUI=1` as auto-`--yes` (TUI runs its own confirmation screen).
- MUST prompt typed `CONFIRM` on cross-major-minor jumps and downgrades (when `--yes` is not set).
- MUST treat pre-release → stable with same `vX.Y.Z` base as an upgrade (no prompt). The reverse (stable → pre-release same base) is a downgrade (prompt).
- MUST install to the directory of `os.Executable()` when writable; else MUST migrate to `~/.local/bin/dop` and print a `sudo rm <old>` + `hash -r` one-liner for manual cleanup.
- MUST sort GitHub `/releases` results by `published_at` desc before picking the newest — the API returns tag-lexical order which breaks dev-channel on same-minor-line pre-releases.
- `dop update --rollback` MUST pick the most-recently-stored binary in the old-versions dir (skipping the one matching the running version) and atomic-replace.

### TUI (`internal/tui/update_view.go`)
- The view MUST check first (`dop update --check-only --channel <c>`, default `stable`), then confirm, install (streamed lines), done.
- `c` MUST flip the channel (stable ↔ dev) and re-check on the confirm step AND on the done step when nothing was installed: already latest, or the check failed (`canFlipFromDone`). Otherwise an operator on the latest stable could never reach dev.
- `c` MUST NOT flip after a failed install; any other key on the done step leaves.
- After a successful install the TUI MUST quit so the next launch runs the new binary.
- Footers: confirm `enter install · esc back` (`c channel` in the expanded help); done-with-nothing-installed `enter done · c channel`.

## Forbidden Behaviors
- MUST NOT replace the binary without checksum verification. If `checksums.txt` is missing, MUST print a warning and still refuse (there is no "trust" fallback).
- MUST NOT overwrite the running binary without first staging the new one to disk successfully.
- MUST NOT delete the rollback store entries without a successful install (prune only on success).

## Interfaces
- Inputs: `--channel`, `--version`, `--check-only`, `--rollback`, `--yes`, `DOP_FROM_TUI`
- Outputs: stderr log lines ("downloading…", "verifying checksum", "stored prior version at…", "installed <tag> at <path>"); file writes to install path + old-versions dir
- Events: none (self-update not audited today — update may add later)
- Dependencies: GitHub Releases API, `golang.org/x/sys/unix` (none external; stdlib tar/gzip/sha256/net-http only)

## State & Data Rules
- MUST name old-versions files `dop-<version>` (where `<version>` is `version.Version` of the binary being retired).
- MUST set the new binary mode 0o755.
- MUST clean up the temp dir regardless of success/failure (deferred `os.RemoveAll`).

## Acceptance Criteria
- PASS if `dop update --check-only --channel stable` prints `Installed: X / Latest (stable channel): Y` and exits 0.
- PASS if upgrading from any `-smoke` pre-release to `v1.14.0` (same base) proceeds WITHOUT a typed-CONFIRM prompt.
- PASS if `dop update --channel stable` from `v1.15.0` → `v1.14.0` prints the CONFIRM prompt (cross-major-minor downgrade).
- PASS if `dop update --rollback` after one successful update restores the prior binary.
- FAIL if the GitHub `/releases` tag-lexical ordering ever surfaces (dev channel must pick the most-recently-published release).
- FAIL if a failed checksum verification results in the running binary being overwritten.

## Regression Checks
- Verify `go test ./cmd/dop/... -run NeedsConfirmation` covers the pre-release ↔ stable upgrade/downgrade matrix.
- Verify `splitBaseAndPrerelease("v1.14.0-rc7n-smoke")` returns `("v1.14.0", "rc7n-smoke")`.
- Verify `dop update --check-only --channel dev` returns the most-recently-published pre-release, not the lex-largest tag.
- Verify `~/.local/share/dop/old-versions/` contains at most 3 files after multiple updates.
- Verify `go test ./internal/tui -run TestUpdate` (flip from already-latest, flip from check error, other key leaves, no flip after failed install).

## Open Questions
- Should self-update emit audit events (`update_installed`, `update_rollback`)? Currently silent.
- Should `--yes` be documented in `--help` or kept as a TUI-only mechanism? Currently exposed via `--help`.
