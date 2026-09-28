package views

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/fray/dop/internal/tui/styles"
)

// AttachChoice tells the caller which path the user picked from the
// attach-vault menu.
type AttachChoice int

const (
	AttachNone AttachChoice = iota
	AttachExisting
	AttachCreate
	AttachSkip
)

// AttachVaultModel is a 3-option menu: connect existing / create new / skip.
type AttachVaultModel struct {
	cursor int
	items  []attachItem
	choice AttachChoice
	done   bool
}

type attachItem struct {
	label  string
	hint   string
	choice AttachChoice
}

func NewAttachVault() *AttachVaultModel {
	return &AttachVaultModel{
		items: []attachItem{
			{label: "Connect to an existing vault", hint: "you have a URL from your team", choice: AttachExisting},
			{label: "Create a new vault", hint: "make one now (via gh, a URL, or a local path)", choice: AttachCreate},
			{label: "Skip for now", hint: "use dop for scripts only; add a vault later", choice: AttachSkip},
		},
	}
}

func (m *AttachVaultModel) Init() tea.Cmd  { return nil }
func (m *AttachVaultModel) Done() bool     { return m.done }
func (m *AttachVaultModel) Choice() AttachChoice { return m.choice }

func (m *AttachVaultModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	km, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch km.String() {
	case "ctrl+c", "esc", "q":
		m.done = true
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.items)-1 {
			m.cursor++
		}
	case "enter":
		m.choice = m.items[m.cursor].choice
		m.done = true
	}
	return m, nil
}

func (m *AttachVaultModel) View() string {
	var b strings.Builder
	b.WriteString(styles.Title.Render("Attach a vault") + "\n\n")
	b.WriteString("Vaults hold your credentials. Pick how you want to set one up:\n\n")
	for i, it := range m.items {
		prefix := styles.Bullet.String()
		label := it.label
		if i == m.cursor {
			prefix = styles.Cursor.String()
			label = styles.Selected.Render(it.label)
		}
		b.WriteString(prefix + label + "  " + styles.Muted.Render(it.hint) + "\n")
	}
	b.WriteString("\n" + styles.Help.Render("↑↓ move · enter select · esc quit"))
	return b.String()
}
