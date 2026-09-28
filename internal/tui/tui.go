// Package tui hosts DOP's Bubble Tea interactive front-end.
//
// Launched when `dop` runs with no args on a TTY. All flows call directly
// into the existing internal/ packages — there is no logic duplication
// between the TUI and the scriptable CLI subcommands.
package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/tui/styles"
	"github.com/fray/dop/internal/tui/views"
)

// Run is the TUI entry point. Blocks until the user quits; returns the
// program exit code.
func Run() int {
	m, err := newRootModel()
	if err != nil {
		fmt.Fprintf(fmtStderr(), "dop tui: %v\n", err)
		return 1
	}
	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintf(fmtStderr(), "dop tui: %v\n", err)
		return 1
	}
	return 0
}

// menu items and root state ---------------------------------------------------

type menuItem struct {
	label string
	hint  string
	kind  screenKind
}

type screenKind int

const (
	screenMenu screenKind = iota
	screenStatus
	screenAddIntegration
	screenIssueToken
	screenDoctor
)

type rootModel struct {
	cursor    int
	menu      []menuItem
	screen    screenKind
	child     tea.Model // active sub-model, nil when on the menu
	paths     *config.Paths
	vaultPath string
	width     int
	height    int
	quitting  bool
}

func newRootModel() (*rootModel, error) {
	paths, err := config.Resolve()
	if err != nil {
		return nil, err
	}
	vp := ""
	if paths != nil {
		candidate := paths.Vault + "/vault.yaml"
		if fileExists(candidate) {
			vp = candidate
		}
	}
	return &rootModel{
		menu: []menuItem{
			{label: "Status", hint: "vault + token + health at a glance", kind: screenStatus},
			{label: "Add integration", hint: "guided form: name, base URL, tokens, grants", kind: screenAddIntegration},
			{label: "Issue token", hint: "mint a bearer scoped to a grant bundle", kind: screenIssueToken},
			{label: "Doctor", hint: "run the P8 health suite", kind: screenDoctor},
			{label: "Quit", hint: "exit the TUI", kind: -1},
		},
		screen:    screenMenu,
		paths:     paths,
		vaultPath: vp,
	}, nil
}

func (m *rootModel) Init() tea.Cmd { return nil }

func (m *rootModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Global window sizing.
	if sz, ok := msg.(tea.WindowSizeMsg); ok {
		m.width, m.height = sz.Width, sz.Height
	}

	// Bubble events to the active child first; child returns nil model when done.
	if m.child != nil {
		child, cmd := m.child.Update(msg)
		if closer, ok := child.(views.Closer); ok && closer.Done() {
			m.child = nil
			m.screen = screenMenu
			return m, cmd
		}
		m.child = child
		return m, cmd
	}

	// Root menu key routing.
	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "q", "esc", "ctrl+c":
			m.quitting = true
			return m, tea.Quit
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.menu)-1 {
				m.cursor++
			}
		case "enter":
			return m.launch(m.menu[m.cursor].kind)
		}
	}
	return m, nil
}

func (m *rootModel) launch(k screenKind) (tea.Model, tea.Cmd) {
	if k == -1 {
		m.quitting = true
		return m, tea.Quit
	}
	m.screen = k
	switch k {
	case screenStatus:
		m.child = views.NewStatus(m.vaultPath, m.paths)
	case screenAddIntegration:
		m.child = views.NewAddIntegration(m.vaultPath)
	case screenIssueToken:
		m.child = views.NewIssueToken(m.vaultPath)
	case screenDoctor:
		m.child = views.NewDoctor(m.vaultPath, m.paths)
	default:
		m.screen = screenMenu
	}
	if m.child != nil {
		return m, m.child.Init()
	}
	return m, nil
}

func (m *rootModel) View() string {
	if m.quitting {
		return ""
	}
	if m.child != nil {
		return m.child.View()
	}
	var b strings.Builder
	b.WriteString(styles.Title.Render("dop — Doors of Perception") + "\n")
	b.WriteString(styles.Muted.Render("credentials scoped per agent · git-synced · local-first") + "\n\n")
	for i, item := range m.menu {
		prefix := styles.Bullet.String()
		label := lipgloss.NewStyle().Render(item.label)
		if i == m.cursor {
			prefix = styles.Cursor.String()
			label = styles.Selected.Render(item.label)
		}
		row := prefix + label
		hint := styles.Muted.Render("    " + item.hint)
		b.WriteString(row + hint + "\n")
	}
	b.WriteString("\n" + styles.Help.Render("↑↓ move · enter select · q quit"))
	return b.String()
}
