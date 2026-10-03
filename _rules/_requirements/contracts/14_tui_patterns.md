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

### Esc behavior
- `esc` at the ROOT view returns to the main menu.
- `esc` inside a nested picker returns to the picker's parent step, not the main menu.
- `ctrl+c` MUST always exit the whole TUI, regardless of nesting depth.

### Flash + error separation
- One-shot success messages (`okSt`) MUST clear after being read once (set a flag or clear in the next Update).
- Persistent errors stay visible until the next successful action.
- Flash and error MUST NOT render in the same frame; error wins.

## Forbidden Behaviors
- MUST NOT render any UI element whose visible width depends on terminal width without `lipgloss.Width()` measurement.
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
- FAIL if any help legend mentions a key that is not bound in the current view's Update.
- FAIL if any destructive label is rendered in the default (non-failSt) style.

## Regression Checks
- Verify `internal/tui/integration_views.go::scopePresets` ends with an `other…` escape row.
- Verify `internal/tui/integration_views.go::kindPresets` is 4 entries (api/cli/mcp/other), no escape row.
- Verify `internal/tui/views.go::grantPickSelected` responds to space/a/n/enter.
- Verify `internal/tui/list_remove_views.go::updateConfirm` accepts y/Y/enter and n/N/esc symmetrically.
- Verify cursor rows in the integration list use `lipgloss.NewStyle().Width(20).Render(disp)` (rc7 fix).
- Verify no TUI view writes directly to the vault file (grep for `vault.Save` / `vault.SaveEncrypted` in `internal/tui/`).

## Open Questions
- Multi-step forms vary in whether they prefill from upstream fields. Should the contract require prefill on specific upstream→downstream pairs (service name → credential name) or just allow it where sensible? Current contract allows it; future audit may want to pin specific pairs.
- The `other…` label is used by scope-note (rc7) but `+ Create new…` is used by the service picker (rc6). Should the escape-row label be standardized? Current contract allows both; the semantic distinction is "edit free-text" vs "create entirely new entity".
- Terminal-width awareness: no view currently reflows based on terminal width. Lock to minimum 80col? Current implementation assumes it; not written down.
