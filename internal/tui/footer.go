// Shared footer + expanded help, rendered by bubbles/help. A view that
// supplies a keyMap gets the short footer (≤4 bindings + "? more") and
// the "?" toggle: toggleHelp in Update, keyMap.overlay/footerLine in View.

package tui

import (
	"strings"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
)

// Standard footer vocabulary. Bindings are for the legend only — key
// routing stays in each view's Update.
var (
	keyMove   = key.NewBinding(key.WithKeys("up", "down"), key.WithHelp("↑↓", "move"))
	keySelect = key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "select"))
	keyOpen   = key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "open"))
	keyCancel = key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "cancel"))
	keyBack   = key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back"))
	keyQuit   = key.NewBinding(key.WithKeys("q"), key.WithHelp("q", "quit"))
	keyJump   = key.NewBinding(key.WithKeys("1", "2", "3", "4", "5"), key.WithHelp("1–5", "jump"))
	keyTab    = key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "field"))
	keySpace  = key.NewBinding(key.WithKeys(" "), key.WithHelp("space", "toggle"))
	keyMore   = key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "more"))
	keyClose  = key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "close"))
)

// hint builds a one-off legend binding for screen-specific keys.
func hint(k, desc string) key.Binding {
	return key.NewBinding(key.WithKeys(k), key.WithHelp(k, desc))
}

// footer renders bs as one line: keys in fg, verbs muted, " · "-separated,
// truncated to width (0 = no limit).
func footer(width int, bs ...key.Binding) string {
	h := help.New()
	h.Width = width
	h.ShortSeparator = " · "
	h.Styles.ShortKey, h.Styles.ShortDesc, h.Styles.ShortSeparator = bodySt, mutedSt, mutedSt
	return h.ShortHelpView(bs)
}

// keyMap is one screen's keys: the short footer, the expanded help
// columns and up to two muted note lines under them.
type keyMap struct {
	short []key.Binding
	full  [][]key.Binding
	notes []string
}

func (k keyMap) ShortHelp() []key.Binding  { return k.short }
func (k keyMap) FullHelp() [][]key.Binding { return k.full }

// footerLine is the short footer plus "? more", or "? close" when open.
func (k keyMap) footerLine(width int, open bool) string {
	if open {
		return footer(width, keyClose)
	}
	return footer(width, append(k.short[:min(len(k.short), 4):min(len(k.short), 4)], keyMore)...)
}

// helpLines is the expanded help: a key table, then the notes.
func (k keyMap) helpLines(width int) []string {
	h := help.New()
	h.ShowAll = true
	h.Width = max(width-2, 0)
	h.FullSeparator = "    "
	// ponytail: keys padded to 9 cells (shift+tab fits); wider keys wrap.
	h.Styles.FullKey, h.Styles.FullDesc, h.Styles.FullSeparator = bodySt.Width(9), mutedSt, mutedSt
	lines := strings.Split(h.View(k), "\n")
	if len(k.notes) > 0 {
		lines = append(lines, "")
		for _, n := range k.notes[:min(len(k.notes), 2)] {
			lines = append(lines, mutedSt.Render(n))
		}
	}
	for i := range lines {
		lines[i] = "  " + lines[i]
	}
	return lines
}

// overlay bottom-aligns the expanded help in a body of rows lines when
// open; the body keeps its top.
func (k keyMap) overlay(body []string, width, rows int, open bool) []string {
	if !open {
		return body
	}
	hl := k.helpLines(width)
	top := max(rows-len(hl), 0)
	body = strings.Split(strings.Join(body, "\n"), "\n")
	out := append([]string{}, body[:min(max(top-1, 0), len(body))]...) // ≥1 blank row above the help
	for len(out) < top {
		out = append(out, "")
	}
	return append(out, hl...)
}

// toggleHelp: ? toggles the expanded help, esc closes it. Reports
// whether the key was consumed.
func toggleHelp(open *bool, km tea.KeyMsg) bool {
	switch {
	case km.String() == "?":
		*open = !*open
	case *open && km.String() == "esc":
		*open = false
	default:
		return false
	}
	return true
}
