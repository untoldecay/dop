# Feature Contract — TUI Patterns

## Scope
- Reusable interaction patterns used across the DOP TUI: preset pickers, multi-select pickers, text inputs with inline validation, confirmation prompts, step-form progression, help legends, and visual alignment under cursor styling. Covers every bubbletea view under `internal/tui/`.

## Purpose
- Pin a small, consistent interaction vocabulary so every TUI flow feels the same, forces no surprise key bindings, and renders cleanly across terminals.

## Invariants
- MUST use lipgloss for all styling; no raw ANSI escapes.
- MUST use bubbletea's Update/View/Init contract on every view; no concurrent writes to view state outside Update.
- MUST render cursor-styled rows at the same visible width as un-styled rows (ANSI escapes are zero-width in terminals but non-zero in Go strings — use `lipgloss.NewStyle().Width(N).Render(...)` for the display column so alignment stays stable).
- MUST reset buffer state when returning to a parent view (no stale text leaking into the next session).
- MUST NOT consume `esc` when a nested picker is active without first returning to the parent mode.

## Mandatory Behaviors

### Preset picker (preset + "other…" / "custom…" escape)
- MUST render as a vertical list of labels with a cursor arrow prefix (`➤ `) on the active row.
- MUST support `up` / `k` and `down` / `j` to move the cursor; cursor MUST clamp at both ends (no wrap).
- MUST commit the choice on `enter`.
- MUST drop into free-text input when the operator picks the escape row (`other…`, `custom…`, `+ Create new…`); the escape row MUST be the last entry.
- MUST return to the picker when the operator backspaces an empty text buffer in free-text mode.
- SHOULD show a one-line hint under each option when the hint adds non-obvious context (e.g. "default — any admin can modify" vs "protected — only you").
- Reference: `scopePresets` (rc7), `protectionPresets` (rc12), `kindPresets` (rc13), `issueView::expiryPresets` (rc5), `repinTTLPresets` (rc9).

### Multi-select picker (grants, admins)
- MUST render each item with a leading checkbox-style indicator (`[x] ` selected, `[ ] ` unselected).
- MUST toggle the item under the cursor on `space`.
- MUST support `a` to select all and `n` to clear all on-screen.
- MUST commit the full selection on `enter` and MUST NOT commit per-row changes.
- MUST support `esc` to abandon the whole selection without side effects.
- Reference: `grantPickSelected` in `listView` (rc5), token-detail grant attach / remove.

### Form step progression
- Each step MUST have exactly one `curBuf()` return value (which strings.Builder it writes to); switch-cased, no shared buffer.
- `enter` MUST advance to the next step after validation; `tab` / `down` MUST advance without validation; `shift+tab` / `up` MUST go back.
- Required-field errors MUST render inline directly under the active row, in `failSt`, prefixed with no icon.
- Validation errors on list-type steps MUST render in the footer area (below the help legend), not under the row.
- MUST prefill downstream fields from upstream when the default is a predictable derivation (e.g. credential name prefilled from service name — rc6).
- MUST re-render fields with the password/token mask (`strings.Repeat("•", len(v))`) when `mask: true` is set, both when active and when past.

### Confirmation prompt
- MUST accept `y` / `Y` / `enter` as confirm.
- MUST accept `n` / `N` / `esc` as cancel.
- MUST render a help legend `y/enter confirm · n/esc cancel`.
- MUST execute the destructive side effect only after confirm.
- Reference: `updateConfirm` on integration list (rc8 cascade), remove-grant flow.

### Help legend
- MUST appear below the main view content, in `helpSt`.
- MUST include ONLY the keys the operator needs on the current screen (not aspirational shortcuts for future screens).
- MUST use `·` as the separator (middle dot), e.g. `↑↓ move · enter select · esc back`.
- SHOULD NOT include modifier-key hints that aren't bound.

### List rows — spacing + icon columns (v1.14.0-rc3)
- Every row-level column that CAN carry a glyph (lock, person, bullet, etc.) OR be empty across different rows in the SAME list MUST reserve a fixed cell width via `lipgloss.NewStyle().Width(N).Render(glyph)`. Direct string concatenation of `"  "` as a placeholder vs. `"🔒 "` as the icon slot is FORBIDDEN — emoji cell width is terminal-dependent (1 or 2 cells; usually 2 but no guarantee), so the two forms don't line up and the subject column shifts by 1 whenever a glyph appears.
- Icon slot width MUST account for the trailing visual separator. Pattern: `glyphWithoutTrailingSpace := "🔒"; slot := lipgloss.NewStyle().Width(3).Render(glyphWithoutTrailingSpace)`. 3 cells = emoji (worst-case 2) + 1 separator space. Pure ASCII glyphs (`[ ]`, `○`, `●`) can use `.Width(2)` since their width is deterministic — but using Width-pinning uniformly across row types is strictly cleaner.
- Multiple icon columns on the same row (e.g. owner glyph + portable prefix) MUST each be independently Width-pinned. Do NOT add a literal `+ " "` between Width-pinned slots — the trailing separator is already inside each slot's reserved width.
- Subject / name column pad MUST use the same primitive: `lipgloss.NewStyle().Width(labelWidth).Render(subj)` where `labelWidth` is computed as `max(len) + 2` from the longest row name in the current list (minimum floor per view, see references).
- When a list has ZERO rows that could carry a glyph (e.g. the grants list has no protection icon today), the icon column SHOULD NOT be reserved. Introducing a glyph later means introducing the Width-pinned slot at the same commit.
- Row metadata that varies per-selection (`grants=N`, `tokens=N`, `expires=…`) MUST live in the status bar below the list, NOT inline on each row. Rows stay scannable; the status bar fills contextual detail for the cursor row.
- References: `list_remove_views.go` integration list + integration-remove picker (lock column, Width 3), `views.go` bearers list (owner glyph + `p.` prefix, Width 3 each).

### Esc behavior
- `esc` at the ROOT view returns to the main menu.
- `esc` inside a nested picker returns to the picker's parent step, not the main menu.
- `ctrl+c` MUST always exit the whole TUI, regardless of nesting depth.

### Flash + error separation
- One-shot success messages (`okSt`) MUST clear after being read once (set a flag or clear in the next Update).
- Persistent errors stay visible until the next successful action.
- Flash and error MUST NOT render in the same frame; error wins.

### Text input + caret (rc6f)
- Every editable text field in the TUI MUST use `internal/tui.textField` (not `strings.Builder`).
- `textField` MUST support left/right/home/end/delete/backspace in the handler layer; rune insert at cursor.
- Views MUST render the active field via `Split()` or `SplitMasked()` so the `▎` caret glyph appears at the real cursor position, not always at the end.
- UTF-8 safety: `textField` operates on rune slices, never byte-indexed slices into strings.

### Settings pattern (rc7l)
- Settings view MUST use a two-state list→picker navigation: list mode shows every setting with its current value in `[...]` brackets; cursor moves with ↑↓; enter opens a picker for the active row.
- Picker MUST open with the cursor on the current value so enter-without-moving is a no-op commit.
- A setting MAY add a `custom…` choice that drops into a text-input mode (operator types a free-form value, enter commits + returns to list, esc returns to picker).
- MUST NOT use per-key toggle shortcuts (`f` / `t` / `h`) for settings — the select pattern is the one way.

### Tabs pattern (rc7m)
- When a view has distinct sub-pages (e.g. Team's `Members` / `Pending`), MUST render them as a tab bar in the title line: `Team   [1] Members (N)   [2] Pending (M)`.
- `tab` key MUST cycle; `1`..`N` MUST jump to a specific tab; `esc` MUST exit the view (not the tab).
- Each tab manages its own cursor; switching tabs resets cursor to 0.

### Session-expiry guard (rc7h)
- Every admin-gated menu dispatch (every `items[cursor].fn` and `g.direct` call in the hierarchical groups menu) MUST route through `rootModel.guardAdminAction(fn)`.
- `guardAdminAction` MUST check `adminClient.SessionActive()` first. On active → call `fn(m)` directly.
- On locked → stash `fn` in `pendingUnlockFn`, fire the `runGUIUnlock()` tea.Cmd (shells out to `dop admin __gui-unlock`).
- `guiUnlockResultMsg` success → refresh state, rebuild menu, invoke stashed `fn`.
- `guiUnlockResultMsg` failure → print specific stderr reason + `tea.Quit`.

### Fire-and-forget subprocess pattern (rc7o)
- When a TUI subprocess exits with rc=0 and the operation is intentionally async (e.g. invite waiting on remote response), MUST transition to a `waiting` state instead of marking the child done.
- Waiting state MUST show the relevant handoff details (PIN, URL, invite_id) and a clear hint for the next step.
- Enter on waiting MUST close the view without side effects.
- Esc on waiting MUST open a cancel-confirm overlay (y/n); confirmed cancel runs a separate subprocess (`cancel-invite` style).

### Locked-field pattern (rc7n)
- When a form flow enters a sub-mode where some fields are display-only (e.g. "add credential to existing integration"), locked rows MUST render with a `🔒 ` prefix (via `mutedSt`) so operators scan them as read-only.
- The step-navigation handler MUST clamp shift+tab/up so the cursor cannot enter a locked step.
- Title + subtitle MUST change to reflect the sub-mode (e.g. `Add credential to <service>` + "Integration-level fields are locked for view.").

## Forbidden Behaviors
- MUST NOT render any UI element whose visible width depends on terminal width without `lipgloss.Width()` measurement.
- MUST NOT use raw space-padding (`"  "`, `"   "`) as a reservation for a column that elsewhere in the SAME list may contain an emoji or a mixed-cell-width glyph. Pin the slot via `lipgloss.NewStyle().Width(N).Render(glyph)` so every row produces exactly N cells regardless of what the terminal does with the glyph.
- MUST NOT bind `h` / `l` to anything (collides with vim-user expectation of horizontal cursor motion).
- MUST NOT silently drop keystrokes — unmapped keys are no-ops but MUST NOT trigger side effects.
- MUST NOT prompt for a passphrase or any sensitive input without `strings.Repeat("•", len(v))` masking.
- MUST NOT render destructive-action labels (`Remove`, `Revoke`, `Delete`) in the default style — use `failSt` for the label text whether or not the row is active.

## Interfaces
- Inputs: `tea.KeyMsg` + custom async msgs (`integrationAddedMsg`, `grantAddedMsg`, etc.).
- Outputs: `string` from each view's `View()` method; `copyToClipboard` for post-save handoffs.
- Events: no audit events emitted directly from the TUI layer; the subprocess calls (`exec.Command(self, args...)` to re-enter CLI mode with `DOP_NO_TUI=1`) are the audit-emitting path.
- Dependencies: `charmbracelet/bubbletea`, `charmbracelet/lipgloss`, `internal/admin.Client`, `internal/config`.

## State & Data Rules
- Picker cursors MUST be `int`, zero-initialized at view construction.
- `*Mode` flags (`serviceMode`, `scopeMode`) MUST default to `true` (picker on first entry) and flip to `false` only when the operator picks the escape row.
- No TUI view may read the vault's SOPS-encrypted bytes; use `loadVaultForListing` through the daemon.
- The TUI MUST re-enter the CLI (`exec.Command(self, ...)` with `DOP_NO_TUI=1`) for any state-mutating save, so audit + lifecycle hooks fire exactly once per operation.

## Acceptance Criteria
- PASS if every preset picker in `internal/tui/` renders an arrow prefix (`➤ `) exactly on the cursor row and no other row.
- PASS if every multi-select handles space / a / n / enter per the rules above.
- PASS if every confirmation accepts both y/enter and n/esc as symmetric pairs.
- PASS if `lipgloss.Width(cursorSt.Render(x))` equals `lipgloss.Width(x)` for every integration/grant/token row.
- PASS if, for every list that has an icon column, the cell width of a row WITH the icon equals the cell width of a row WITHOUT the icon up to the first non-icon column (measured via `lipgloss.Width` applied to each row prefix slice).
- FAIL if any help legend mentions a key that is not bound in the current view's Update.
- FAIL if any destructive label is rendered in the default (non-failSt) style.

## Regression Checks
- Verify `internal/tui/integration_views.go::scopePresets` ends with an `other…` escape row.
- Verify `internal/tui/integration_views.go::kindPresets` is 4 entries (api/cli/mcp/other), no escape row.
- Verify `internal/tui/views.go::grantPickSelected` responds to space/a/n/enter.
- Verify `internal/tui/list_remove_views.go::updateConfirm` accepts y/Y/enter and n/N/esc symmetrically.
- Verify cursor rows in the integration list use `lipgloss.NewStyle().Width(20).Render(disp)` (rc7 fix).
- v1.14.0-rc3 — verify every icon slot in `internal/tui/list_remove_views.go` + `internal/tui/views.go` uses `lipgloss.NewStyle().Width(N).Render(glyph)`, NOT ad-hoc `"  "` placeholders. Grep for the anti-pattern: `lock := "  "`, `ownerGlyph := "  "`, `portPrefix := "   "`.
- Verify no TUI view writes directly to the vault file (grep for `vault.Save` / `vault.SaveEncrypted` in `internal/tui/`).

## Open Questions
- Multi-step forms vary in whether they prefill from upstream fields. Should the contract require prefill on specific upstream→downstream pairs (service name → credential name) or just allow it where sensible? Current contract allows it; future audit may want to pin specific pairs.
- The `other…` label is used by scope-note (rc7) but `+ Create new…` is used by the service picker (rc6). Should the escape-row label be standardized? Current contract allows both; the semantic distinction is "edit free-text" vs "create entirely new entity".
- Terminal-width awareness: no view currently reflows based on terminal width. Lock to minimum 80col? Current implementation assumes it; not written down.
