# TUI Reference

**Date:** 2026-09-29
**Contracts:** none direct — TUI is a thin front-end over the CLI. Behavior invariants live in the underlying contracts (01, 02, 03, 06, 08).
**Style guide:** [`../_projects/DOP/TUI_GUIDELINES.md`](../../_rules/_projects/DOP/TUI_GUIDELINES.md) (canonical visual rules).

The TUI is a Bubble Tea + Lipgloss front-end. It shells out to the same CLI subcommands documented elsewhere — never re-implements them. This doc is a walkthrough of what you see and where each panel maps to.

---

## Entering the TUI

Type `dop` alone on a TTY (both stdin AND stdout must be terminals). To force off, set `DOP_NO_TUI=1` or pass `--no-tui`. Tests disable it.

`shouldLaunchTUI()` in `cmd/dop/main.go:130` gates the launch.

---

## Root menu

Sections + items, in this order (per `TUI_GUIDELINES.md`):

**Vault**
- Add integration
- Add grant
- List integrations
- Remove integration
- List grants
- Remove grant
- Edit vault

**Tokens**
- Issue token
- List tokens
- Revoke token

**Team**
- Add team member
- List team
- Remove team member

**Sync**
- Pull vault
- Push vault

**System**
- Status
- Doctor
- Logout
- Quit

Menu conventions:
- Section headers in muted style, one blank line before each section.
- Fixed-width label column so descriptions line up.
- Cursor: `➤ ` prefix, active label in `cursorSt` (brand amber).
- Shortcut keys shown in the footer, not inline.
- No borders. Whitespace is the separator.

State header (line 2 of the view): `admin · unlocked · 13m10s idle` or equivalent.

---

## Pre-ready menus

When the machine isn't ready, the root menu becomes a single flat section:

- **No admin key**: `Setup admin`, `Attach vault (agent)`, `Doctor`, `Quit`.
- **Admin locked**: `Login`, `Doctor`, `Quit`.
- **Vault unattached (admin unlocked)**: `Attach vault`, `Doctor`, `Logout`, `Quit`.

Users in these states are confused; extra sections add cognitive load.

---

## Issue token flow

`internal/tui/views.go`

Three steps:
1. **Subject** — free-text label.
2. **Grants** — multi-select list (v1.6.1a). Falls back to text entry when the vault has no grants declared yet.
3. **Expires** — duration string (default `72h`).

Grants picker bindings (from `TUI_GUIDELINES.md`):
- `↑` / `↓` (or `k` / `j`) — move
- `space` — toggle
- `a` — select all
- `n` — none
- `enter` — commit selection

On success, the view shows:
- Bearer + PIN on separate lines (bold).
- The `DOP_TOKEN=... dop claim ...` handoff line in muted style.
- Copies the handoff to clipboard automatically via `copyToClipboard`.

---

## List-picker views (Revoke, Remove *)

Same picker style as grants — cursor + selection markers + right-column metadata. See TUI_GUIDELINES §"List-picker views".

---

## Status & Doctor views

Detail views: pairs of `mutedSt` label + value column, aligned. Footer says `any key to go back`.

`Doctor` maps to `dop doctor [--security]`.

---

## Color palette

| Constant | Color | Use |
|---|---|---|
| `brand` | amber `#f5c93a` | Title, cursor, active label |
| `muted` | grey `#6d7280` | Descriptions, section headers, state header, footer |
| `ok` | green `#10b981` | Success indicators |
| `danger` | red `#ef4444` | Errors, "revoked" |
| terminal default | — | Body values |

Defined in `internal/tui/tui.go`.

---

## Do NOT

- Add borders / frames.
- Put `[X]` shortcuts inline on menu rows.
- Show more than 4 shortcuts in the footer.
- Print stack traces or raw command output — parse and summarize.
- Bold or color body values in detail views (label carries the styling).

See `TUI_GUIDELINES.md` for the enforceable version of these rules.

---

## Dependencies

- `github.com/charmbracelet/bubbletea` — event loop.
- `github.com/charmbracelet/lipgloss` — styles.
- No `bubbles` sub-package — the picker is hand-rolled to keep the visual discipline consistent (per Mole reference).

---

## Next steps

- List-picker for Revoke token (currently expects a subject typed by hand).
- Live-follow pane inside the TUI mirroring `dop watch`.
- Inline `dop pending` panel with one-key approve when the passphrase is available.
