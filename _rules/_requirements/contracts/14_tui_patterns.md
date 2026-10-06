# Feature Contract — TUI Patterns

## Scope
- Every bubbletea view under `internal/tui/`: the screen frame, footer + `?` help, status line, tabs, lists and tables, details, wizards, dense forms, pickers, confirms, running / done / error / empty screens, theme, glyphs, copy vocabulary, Esc, size rules, session guard and the shown-once bearer guard.
- Shared code: `frame.go` (frame, tab, status), `footer.go` (keyMap, footer, toggleHelp), `detail_helpers.go` (wiz, denseForm, multiPick, actionRows, confirmFoot, optRows, padTrunc, midTrunc, vocab), `handoff.go` (onceKey, onceScreen, useGuidance), `tui.go` (theme, guardAdminAction, sessionGuard, stateLine), `views.go` (bearers, issue, status, doctor).
- Enforcement: the screen walk (contract 24).

## Purpose
- Every screen answers one question at first glance; everything else is one key away. One layout, one key vocabulary, one set of words.

## Invariants
- MUST render every screen through `frame()`: row 1 title (+ tabs, + muted context right-aligned), row 2 blank, body (`frameRows(h)` = h-5 rows), blank, status line (row h-1), footer (row h). Nothing below the footer.
- MUST fit every line to the terminal width (`frame` truncates with `…`); zero size renders as 80x24.
- MUST use lipgloss for all styling; no raw ANSI escapes in views.
- MUST keep all view state changes inside `Update`.
- Every child view MUST receive the terminal size: `rootModel.Update` sends one `tea.WindowSizeMsg` to a newly opened child; a parent that opens a sub-view (`v.sub`) forwards its size.
- Esc MUST go back exactly one level: open help → closed; open form row → row value restored; wizard step → previous step; detail → list; list or group → menu. `ctrl+c` always leaves the view.
- MUST NOT bind `h` / `l`. `k` / `j` MAY alias up / down.

## Mandatory Behaviors

### Footer + help (`footer.go`)
- Short footer: at most 4 bindings + `? more` (`keyMap.footerLine`), ` · ` separated, key in body style, verb muted.
- Order: primary action, tab switch, esc back, `? more`. `↑↓ move` lives only in the expanded help.
- `?` toggles the expanded help (`toggleHelp`), bottom-aligned in the body (`keyMap.overlay`); esc closes it; footer then reads `? close`.
- Expanded help MAY carry at most 2 muted note lines (why / how-to / CLI equivalents). Explanations live there, not in the body.
- While a text input holds focus `?` is a character, not help (`wiz.wizMsg` typing flag, `denseForm.typing`).
- A footer MUST list only keys the current Update handles.

### Status line (`frame.go::status`)
- One source at a time: error > flash > hint.
- Error: danger, `! ` prefix. Flash: ok. Hint: muted.
- Flash clears on the next key; error clears only when the input it is about changes (`status.onKey`).
- The cursor row's truncated or secondary data (full name, ids, kind, counts, protection, owner) goes to the hint, not into extra columns (`rowHint`).

### Tabs (`frame.go::tab`)
- Max 3, on the title row; active tab brand + underline, others muted; count inside the label (negative count hidden).
- Only for same-level collections of one object: bearers Active / Revoked (`listView`), bearer detail Info / Grants, integration detail Info / Credentials / Grants, team Members / Pending, Add integration credential step Normal / Advanced.
- `tab` cycles (shift+tab back where offered); switching resets that tab's cursor.

### Lists, tables, details
- Lists use `bubbles/list` via `newNameList` / `nameDelegate`: `›` cursor, name column `nameColW` (30) truncated with `…`, one muted descriptive column, muted lowercase header, no rule line. Count goes in the title-row context.
- Bearers table (`listView.renderTable`): subject · expires · grants; dates relative in lists (`relDate`), absolute in detail (`absDate`).
- Hex ids and keys truncate in the middle (`midTrunc`).
- `enter` opens the detail; the detail holds the actions (`actionRows`), no separate action menu, no Back row. The highlighted action's description is the status hint.
- Detail title is the object's full name; primary kv rows first, secondary rows muted.

### Wizards (`detail_helpers.go::wiz`)
- One question per screen (`wiz.screen`): muted prompt, input rows, optional muted helper line; `n of m` counter in the title-row context (`counter`).
- The prompt echoes the answer it depends on ("Grants for <subject>").
- Last step is a review (`wiz.review`): kv answers, `enter <verb> · esc back · ? more`.
- esc / shift+tab step back one (`wizBack`); from the first step the wizard closes.
- Validation errors go to the status line; the input keeps its value.
- Every form-like view embeds `wiz` (issue, invite, join, setup, login, team add, remove pickers, pending, reset, update, settings custom step); repin / portable reuse its screens.

### Dense forms (`detail_helpers.go::denseForm`)
- One row per field: label column + value column (`formField`: `textRow`, `pickRow`, `fixedRow`), then an action row (`Next` / `Review`).
- `↑↓` move between editable rows; `enter` opens a row in place (text input or picker under the row); `enter` on the action row validates the step (`denseForm.missing` puts the cursor on the first empty required row).
- Empty required rows show muted `required`; masked rows show `•`; fixed rows are muted and skipped by the cursor.
- A picker whose last option is `other…` opens a text input for a custom value.
- `esc` closes an open row (its value restored); on a closed form it leaves the form.
- Used by: Add integration (stepper `Integration › Credential › Grant`), Add grant, the integration edit form and the grant edit form (contracts 15, 16, 18).
- Edit forms follow the same pattern: rows prefilled from the record, a trailing `Review` row, then a review of the changed rows only (`snap` / `changes`; `No changes.` with `enter close` when none, which returns without a CLI call), running, `✓ <noun> saved`, `enter` back to the detail. A failed save returns to the review with the error on the status line.
  - Integration edit (`e`, `integModeIntEdit` / `integModeIntReview`): tabs `Normal` / `Advanced` on the title row, `tab` flips them while no row is open. Normal: name, kind, description, the kind slot, scan for docs (api, mcp), projects, tags, protection, approval passphrase (only when switching to protected). Advanced: the add flow's `advFieldSpecs` rows for the kind. Running `Saving integration…`, done `✓ Integration saved`, back on the Info tab.
  - Grant edit (`e`, `grantModeEdit` / `grantModeReview`): projects, tags, env prefix (the default as placeholder), protection, approval passphrase (only when switching to protected). Running `Saving grant…`, done `✓ Grant saved`, back on the grant detail.

### Pickers
- Single choice (`optRows`, `pickRows`): `›` on the cursor row, label + muted description on the same row; cursor clamps, no wrap; opens on the current value.
- Multi choice (`multiPick`): muted group headers, `●` selected / `○` not, `space` toggle, `ctrl+a` all, `n` none, selection count on the status line, conflicting rows marked with a danger `!` and explained on the status line; scrolls to keep the cursor visible. Used by Issue grants and bearer Add grant.

### Confirms
- Title is the question ("Revoke <subject>?"); body is the facts that change the decision, consequence lists up to 5 names then `and N more` (`upTo5`).
- Footer `enter <verb> · esc cancel` with the destructive verb in danger (`confirmFoot`, `wiz.confirmScreen`). No buttons. `y` / `n` MAY alias.
- The side effect runs only after confirm.

### Running, done, errors, empty
- Running (`wiz.running`): brand spinner + one present-tense line; no footer unless cancel works.
- Done (`wiz.doneScreen`): title `✓ <outcome>`; body is only what to copy or do next; one muted next-step line; footer `enter done`.
- Errors stay on the screen that caused them, on the status line, in plain words (`cliErr` strips the CLI prefix and applies `vocab`); a failed save returns to the review / form with the answers kept.
- Empty state: one body line naming the next action ("No integrations yet. Add one from the menu: Add › Integration."); tabs still show with 0; footer drops keys that do nothing.

### Shown-once bearer screens (`handoff.go`)
- Issue, repin and portable re-issue done screens use `onceScreen` + `onceKey`: `enter` leaves, `esc` needs a second press (status hint warns), `c` copies again, any other key is ignored and disarms esc.
- The handoff is copied with `clipboardCopy` once when the result message arrives, never from `View`.
- The muted lines under the bearer are `useGuidance` (contract 13).

### Session guard (`tui.go`)
- Menu dispatch (`items[i].fn`, `group.direct`) MUST go through `rootModel.guardAdminAction`: run when `SessionActive()`, else stash the action and run `runGUIUnlock`; success refreshes and runs it, failure prints the reason and quits.
- Every view MUST call `sessionGuard.locked(key, &err)` right before shelling out a mutation: locked → status shows `lockedNote`, the GUI unlock opens, and on success the same key is replayed so the save resumes from the same screen (`sessionGuard.unlocked`).
- The menu context shows `locked`, `unlocked · <time left>` (min of idle and absolute left, `shortDuration`), or `unlocked · until logout` (`stateLine`).

### Mutations
- Every state-changing save MUST re-enter the CLI (`exec.Command(self, …)` with `DOP_NO_TUI=1`, `DOP_FROM_TUI=1`) so audit and lifecycle hooks fire once.
- Secrets (values, passphrases) MUST go on stdin (`--value-stdin`, `--passphrase-stdin`), never argv.

## Forbidden Behaviors
- MUST NOT use glyphs other than `›` `●` `○` `✓` `!` (plus `…` truncation, `•` masks, `▎` caret, `·` separator). Banned: `➤ ⚠ ✗ 🔒 👤 ─ ← →`, `[ ]` checkboxes, emoji, `[ Save ]` buttons.
- MUST NOT say `token` or `capability` in copy: bearer (what an agent holds), credential (the upstream secret in an integration), grant, integration. CLI text echoed into the TUI goes through `vocab`.
- MUST NOT show backticks, markdown, version tags or emoji in copy.
- MUST NOT write durations as Go strings (`1h0m0s`); use `30m`, `2h`, `7d` (`shortDuration`).
- MUST NOT render more than one bold run per screen (the title).
- MUST NOT render italic except input placeholders.
- MUST NOT stack two status sources or render anything below the footer.
- MUST NOT read the SOPS-encrypted vault directly or write the vault file from `internal/tui/` (`loadVaultForListing`; saves via the CLI).
- MUST NOT call `clipboardCopy` from `View`.

## Interfaces
- Inputs: `tea.KeyMsg`, `tea.WindowSizeMsg`, per-view result messages (`issueResultMsg`, `integrationAddedMsg`, `listActionMsg`, `guiUnlockResultMsg`, …).
- Outputs: `View()` strings built by `frame`; CLI subprocesses; clipboard.
- Events: none emitted by the TUI; the CLI subprocess emits them.
- Dependencies: `charmbracelet/bubbletea`, `bubbles` (list, help, key, spinner, textinput), `lipgloss`, `x/ansi`. `huh` is not used.

## State & Data Rules
- Theme roles (`tui.go`): title fg bold; body fg; secondary `mutedSt` (headers, descriptions, kv labels, inactive tabs, footer verbs, hints); placeholder muted italic; focus `focusSt` brand (`›`, cursor row, active tab, caret, spinner); success `okSt`; failure `dangerSt` (`!`, errors, destructive verb).
- Palette: fg `#5c5c5c`, brand `#c2c4cc`, muted `#404040`, ok `#10b981`, danger `#ef4444`. Colour marks exceptions only; revoked / expired / protected are muted words.
- Text inputs: `newFormInput` (static cursor, muted italic placeholder, `•` echo when masked); legacy `textField` + `SplitMasked` for passphrase rows in list views.
- Cursors are `int`, zero at construction, clamped by `stepCursor`.

## Acceptance Criteria
- PASS if every dumped screen at 80x24 has exactly 24 rows, no row wider than 80 cells, exactly one bold run, italic only on an input row (contract 24 check).
- PASS if no dumped screen contains a banned glyph, `token`, `(s)`, a backtick or a Go duration.
- PASS if every screen in the walk is one key from another (contract 24 connectivity).
- PASS if a stray key on a shown-once bearer screen keeps the screen and a single esc does not leave it (`issue_success_test.go`).
- FAIL if a footer shows more than 4 bindings plus `? more`.
- FAIL if a mutation shells out without `sessionGuard.locked` first.

## Regression Checks
- Run `DOP_TUI_WALK=<dir> go test ./internal/tui -run TestWalkScreens` and the check rules of contract 24 before merging any TUI change.
- Review changed screens with `scripts/tui-compare.py <before> <after>`.
- Verify `go test ./internal/tui` (handoff shape, shown-once guard, menu, update flip) passes.
- Grep `internal/tui/*.go` (non-test) for `➤`, `🔒`, `[x]`, `huh` — expect none.

## Open Questions
- Bearer list direct keys (`r` revoke, `s` reseal, `p` repin) were proposed; today actions live in the detail only.
- Some confirms still accept `y` / `n` aliases (`integrationListView.updateConfirm`); keep as aliases or drop?
