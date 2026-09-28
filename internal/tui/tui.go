// Package tui hosts the Bubble Tea interactive front-end.
//
// The v1 TUI is state-aware: it detects whether this is an admin install
// (has keys/admin.age.enc), whether an admin session is active, and
// gates the menu accordingly. All actions route through the same CLI
// paths that headless invocation uses — the TUI is a wrapper, not a
// second implementation.
package tui

import (
	"fmt"
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/config"
)

// Run is the TUI entry point. Blocks until the user quits.
func Run() int {
	m := newRootModel()
	p := tea.NewProgram(m, tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		fmt.Fprintln(os.Stderr, "dop tui:", err)
		return 1
	}
	return 0
}

// --- styles ---

var (
	brand    = lipgloss.Color("#f5c93a")
	muted    = lipgloss.Color("#6d7280")
	ok       = lipgloss.Color("#10b981")
	danger   = lipgloss.Color("#ef4444")
	titleSt  = lipgloss.NewStyle().Bold(true).Foreground(brand)
	mutedSt  = lipgloss.NewStyle().Foreground(muted)
	okSt     = lipgloss.NewStyle().Foreground(ok).Bold(true)
	failSt   = lipgloss.NewStyle().Foreground(danger).Bold(true)
	cursorSt = lipgloss.NewStyle().Bold(true).Foreground(brand)
	helpSt   = lipgloss.NewStyle().Foreground(muted).Italic(true)
)

// --- state detection ---

type installKind int

const (
	installUnknown installKind = iota
	installNoKey               // no admin key on disk → this is a fresh machine, or an agent
	installAdmin               // has admin key
)

type sessionState int

const (
	sessionUnknown sessionState = iota
	sessionLocked
	sessionUnlocked
)

// --- root model ---

type screenKind int

const (
	screenMenu screenKind = iota
	screenLogin
	screenStatus
	screenDoctor
	screenIssue
	screenList
)

type rootModel struct {
	install     installKind
	session     sessionState
	paths       *config.Paths
	adminClient *admin.Client

	menu   []menuItem
	cursor int
	screen screenKind
	child  tea.Model

	width, height int
	quitting      bool
	flashMessage  string // one-shot info message shown below the menu
}

type menuItem struct {
	label string
	hint  string
	key   string // single-key shortcut
	fn    func(*rootModel) (tea.Model, tea.Cmd)
}

func newRootModel() *rootModel {
	m := &rootModel{}
	m.refreshState()
	m.rebuildMenu()
	return m
}

func (m *rootModel) refreshState() {
	paths, err := config.Resolve()
	if err != nil {
		return
	}
	m.paths = paths
	if admin.KeyFileExists(paths) {
		m.install = installAdmin
	} else {
		m.install = installNoKey
	}
	m.adminClient = admin.NewClient(admin.SockPath(paths))
	if m.adminClient.SessionActive() {
		m.session = sessionUnlocked
	} else {
		m.session = sessionLocked
	}
}

func (m *rootModel) rebuildMenu() {
	m.menu = m.menu[:0]
	switch {
	case m.install == installNoKey:
		m.menu = []menuItem{
			{label: "Doctor", hint: "health check on this install", key: "d", fn: (*rootModel).openDoctor},
			{label: "Quit", hint: "exit", key: "q", fn: (*rootModel).quit},
		}
	case m.install == installAdmin && m.session == sessionLocked:
		m.menu = []menuItem{
			{label: "Login", hint: "unlock admin session (passphrase)", key: "l", fn: (*rootModel).openLogin},
			{label: "Doctor", hint: "health check", key: "d", fn: (*rootModel).openDoctor},
			{label: "Quit", hint: "exit", key: "q", fn: (*rootModel).quit},
		}
	case m.install == installAdmin && m.session == sessionUnlocked:
		m.menu = []menuItem{
			{label: "Status", hint: "current admin session state", key: "s", fn: (*rootModel).openStatus},
			{label: "Issue token", hint: "mint a new bearer", key: "i", fn: (*rootModel).openIssue},
			{label: "List tokens", hint: "show issued capabilities", key: "L", fn: (*rootModel).openList},
			{label: "Doctor", hint: "health check", key: "d", fn: (*rootModel).openDoctor},
			{label: "Logout", hint: "end admin session", key: "o", fn: (*rootModel).doLogout},
			{label: "Quit", hint: "exit", key: "q", fn: (*rootModel).quit},
		}
	}
	if m.cursor >= len(m.menu) {
		m.cursor = 0
	}
}

func (m *rootModel) Init() tea.Cmd {
	if m.child != nil {
		return m.child.Init()
	}
	return nil
}

// closeChild interface — child views set Done() = true to be popped.
type doner interface{ Done() bool }

func (m *rootModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch sz := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = sz.Width, sz.Height
	}
	if m.child != nil {
		child, cmd := m.child.Update(msg)
		if d, ok := child.(doner); ok && d.Done() {
			// Post-child: refresh state and go back to the menu.
			m.child = nil
			m.screen = screenMenu
			// Pull one-shot flash message from the child if it exposes one.
			if fm, ok := child.(flasher); ok {
				m.flashMessage = fm.Flash()
			}
			m.refreshState()
			m.rebuildMenu()
			return m, cmd
		}
		m.child = child
		return m, cmd
	}
	// Root menu key routing.
	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "ctrl+c":
			return m.quit()
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.menu)-1 {
				m.cursor++
			}
		case "enter":
			return m.menu[m.cursor].fn(m)
		default:
			// Shortcut key
			for _, it := range m.menu {
				if km.String() == it.key {
					return it.fn(m)
				}
			}
		}
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
	b.WriteString(titleSt.Render("dop — Doors of Perception") + "\n")
	b.WriteString(mutedSt.Render(m.stateLine()) + "\n\n")
	for i, it := range m.menu {
		prefix := "  "
		label := it.label
		if i == m.cursor {
			prefix = cursorSt.Render("➤ ")
			label = cursorSt.Render(it.label)
		}
		key := ""
		if it.key != "" {
			key = mutedSt.Render(fmt.Sprintf(" [%s]", it.key))
		}
		b.WriteString(prefix + label + key + "  " + mutedSt.Render(it.hint) + "\n")
	}
	if m.flashMessage != "" {
		b.WriteString("\n" + okSt.Render(m.flashMessage) + "\n")
	}
	b.WriteString("\n" + helpSt.Render("↑↓ move · enter select · single-letter shortcuts · q quit"))
	return b.String()
}

func (m *rootModel) stateLine() string {
	switch {
	case m.install == installNoKey:
		return "install: agent (no admin key). Run `dop admin init` in a terminal to become admin."
	case m.install == installAdmin && m.session == sessionLocked:
		return "install: admin. Session: locked."
	case m.install == installAdmin && m.session == sessionUnlocked:
		st, _ := m.adminClient.Status()
		if st != nil {
			return fmt.Sprintf("install: admin. Session: unlocked · admin=%s...", st.AdminPubkey[:12])
		}
		return "install: admin. Session: unlocked."
	}
	return ""
}

// --- transitions ---

func (m *rootModel) quit() (tea.Model, tea.Cmd) {
	m.quitting = true
	return m, tea.Quit
}

func (m *rootModel) openStatus() (tea.Model, tea.Cmd) {
	m.child = newStatusView(m.adminClient)
	m.screen = screenStatus
	return m, m.child.Init()
}

func (m *rootModel) openDoctor() (tea.Model, tea.Cmd) {
	m.child = newDoctorView(m.paths, m.adminClient)
	m.screen = screenDoctor
	return m, m.child.Init()
}

func (m *rootModel) openLogin() (tea.Model, tea.Cmd) {
	m.child = newLoginView(m.paths)
	m.screen = screenLogin
	return m, m.child.Init()
}

func (m *rootModel) openIssue() (tea.Model, tea.Cmd) {
	m.child = newIssueView(m.adminClient, m.paths)
	m.screen = screenIssue
	return m, m.child.Init()
}

func (m *rootModel) openList() (tea.Model, tea.Cmd) {
	m.child = newListView(m.adminClient, m.paths)
	m.screen = screenList
	return m, m.child.Init()
}

func (m *rootModel) doLogout() (tea.Model, tea.Cmd) {
	_ = m.adminClient.Logout()
	m.flashMessage = "logout: session ended"
	m.refreshState()
	m.rebuildMenu()
	return m, nil
}

type flasher interface{ Flash() string }
