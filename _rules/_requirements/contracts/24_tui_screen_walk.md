# Feature Contract — TUI Screen Walk

## Scope
- `internal/tui/walk_test.go` (`TestWalkScreens`): the in-process walk that dumps every TUI screen.
- Its outputs (`.ans` dumps, `index.txt`), the connectivity invariant, the screen check rules, and the review tools `scripts/tui-screens.sh`, `scripts/tui-lab.py`, `scripts/tui-compare.py`.

## Purpose
- Make every TUI screen visible and checkable without a terminal, so contract 14 is enforced on every screen, not on the ones someone remembered to open.

## Invariants
- The walk MUST be opt-in: skipped unless `DOP_TUI_WALK=<outdir>` is set.
- The walk MUST run fully in-process: drive `newRootModel()` with real `tea.KeyMsg`, drop every returned `tea.Cmd`, never spawn a subprocess.
- The walk MUST use a fixture HOME (temp dir under `/tmp`, short for the unix socket limit), a plaintext fixture vault (`walkVault`, no `sops:` key), a fake admin daemon on the real socket path (`walkDaemon`), and a stub PATH (`sops`, `git` only; no clipboard tools).
- The walk MUST swap `clipboardCopy` for a no-op and restore it.
- Async results MUST be injected as the views' own message types (`walker.send`), recorded as `direct:<label>` in the key path.
- Every flow MUST start from launch (`walker.reset`) and reach its screens the way a user does.
- Every screen MUST be dumped at 80x24 and 120x40, exactly `View()` output, colour profile forced to TrueColor.

## Mandatory Behaviors
- Dump names: `<NNN>-<slug>-<cols>x<rows>.ans`; slugs unique (duplicate slug fails the test).
- `index.txt`: one line per dump, tab-separated `filename  title  key path  tags`. Key path `(launch)` for the first screen; typed text quoted; `direct:` for injected messages.
- Tags: `key` (best example of a pattern), `flow:<name>` (added to every dump of the current flow), `edge` (edge or error state).
- Connectivity: before each key press the current state is dumped if no screen sits at its user-key path (`walker.fill`), so every screen is another screen's user keys + exactly one key. The test MUST fail on an unconnected screen.
- The test MUST fail when fewer than 100 screens are dumped or the dumps carry no ANSI escapes.
- Check rules, per 80x24 dump (contract 14):
  - exactly 24 rows; no row wider than 80 cells;
  - exactly one bold run;
  - italic only on an input row (starting `› `);
  - none of `➤ ⚠ ✗ 🔒 👤 ─ ← →`;
  - no `token` word, no `(s)`, no `Reset`, no backtick, no Go duration (`1m30s`, `1h0m`);
  - footer at most 5 ` · ` entries.

## Forbidden Behaviors
- MUST NOT touch the real HOME, real clipboard, real vault or a real daemon.
- MUST NOT execute a returned `tea.Cmd` (they spawn the CLI).
- MUST NOT reach a screen by setting view fields directly when a key path exists.

## Interfaces
- Inputs: `DOP_TUI_WALK=<outdir>`; fixture vault + fake daemon status.
- Outputs: `<outdir>/*.ans`, `<outdir>/index.txt`.
- Tools:
  - `scripts/tui-screens.sh [outdir]`: runs the walk into `<outdir>/ans`, renders PNGs (ansisvg + headless Chrome), writes `<outdir>/index.html` and the lab.
  - `scripts/tui-lab.py <outdir>`: restylable HTML lab from `ans/*-80x24.ans` + `index.txt`; grid filtered by tag, single mode replays key paths.
  - `scripts/tui-compare.py <before> <after> [--changed]`: before/after page of changed, added and removed 80x24 screens.
- Dependencies: `bubbletea`, `lipgloss`, `termenv`; tools need Go, Python 3, Chrome.

## State & Data Rules
- To add a screen: reach it in the matching `walk<Flow>` function with `w.keys` / `w.line` / `w.text` / `w.send`, then `w.dump(slug, title, tags...)` for named states; intermediate states are filled automatically.
- A new view MUST expose `load() tea.Msg` if it loads data in `Init`, so the walk can run it inline (`walker.load`).
- New flows MUST be called from `TestWalkScreens` and set `w.flow`.

## Acceptance Criteria
- PASS if `DOP_TUI_WALK=$d go test ./internal/tui -run TestWalkScreens` exits 0.
- PASS if every 80x24 dump passes the check rules above.
- FAIL if a screen in `index.txt` has no predecessor one key away.

## Regression Checks
- Review ritual for any TUI change: run the walk (or `scripts/tui-screens.sh`) before and after, open `scripts/tui-compare.py` output, inspect every changed screen, then confirm 0 check-rule failures.
- Verify the walk still dumps ≥ 100 screens and every flow function runs.

## Open Questions
- The check rules are not in the repo: only connectivity, screen count and ANSI presence are asserted by `TestWalkScreens`. The rule script lives outside the tree. Move it into `walk_test.go` (or `scripts/`) so CI enforces it.
- `tui-lab.py` `PALETTE` and `KEY` list still name the old theme and old ordinals; `index.txt` tags supersede `KEY`.
