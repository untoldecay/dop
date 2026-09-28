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
	"time"

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
	label   string
	hint    string
	key     string // single-key shortcut (for the footer legend only)
	section string // grouping header; empty = ungrouped
	fn      func(*rootModel) (tea.Model, tea.Cmd)
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
		// Setup mode: no section headers (per TUI_GUIDELINES.md).
		m.menu = []menuItem{
			{label: "Setup admin", hint: "generate + wrap admin keys", key: "S", fn: (*rootModel).openSetupAdmin},
			{label: "Attach vault", hint: "join an existing vault as agent", key: "a", fn: (*rootModel).openAttachAgent},
			{label: "Doctor", hint: "health check", key: "d", fn: (*rootModel).openDoctor},
			{label: "Quit", hint: "exit", key: "q", fn: (*rootModel).quit},
		}
	case m.install == installAdmin && m.session == sessionLocked:
		m.menu = []menuItem{
			{label: "Login", hint: "unlock admin session", key: "l", fn: (*rootModel).openLogin},
			{label: "Doctor", hint: "health check", key: "d", fn: (*rootModel).openDoctor},
			{label: "Quit", hint: "exit", key: "q", fn: (*rootModel).quit},
		}
	case m.install == installAdmin && m.session == sessionUnlocked && !vaultAttached(m.paths):
		m.menu = []menuItem{
			{label: "Attach vault", hint: "clone/link a vault repo", key: "a", fn: (*rootModel).openAttachAdmin},
			{label: "Doctor", hint: "health check", key: "d", fn: (*rootModel).openDoctor},
			{label: "Logout", hint: "end admin session", key: "o", fn: (*rootModel).doLogout},
			{label: "Quit", hint: "exit", key: "q", fn: (*rootModel).quit},
		}
	case m.install == installAdmin && m.session == sessionUnlocked:
		// Full menu, grouped per TUI_GUIDELINES.md.
		m.menu = []menuItem{
			// Vault
			{section: "Vault", label: "Add integration", hint: "add a service + upstream tokens", fn: (*rootModel).openAddIntegration},
			{section: "Vault", label: "Add grant", hint: "map a grant to an integration/token", fn: (*rootModel).openAddGrant},
			{section: "Vault", label: "List integrations", hint: "show all integrations", fn: (*rootModel).openIntegrationList},
			{section: "Vault", label: "Remove integration", hint: "delete (+ dependent grants)", fn: (*rootModel).openIntegrationRemove},
			{section: "Vault", label: "List grants", hint: "show all grants", fn: (*rootModel).openGrantList},
			{section: "Vault", label: "Remove grant", hint: "delete a grant", fn: (*rootModel).openGrantRemove},
			// Tokens
			{section: "Tokens", label: "Issue token", hint: "mint a new bearer", key: "i", fn: (*rootModel).openIssue},
			{section: "Tokens", label: "List tokens", hint: "show issued capabilities", fn: (*rootModel).openList},
			{section: "Tokens", label: "Revoke token", hint: "kill an issued bearer", fn: (*rootModel).openRevoke},
			// Team
			{section: "Team", label: "Add team member", hint: "add another admin's pubkey", fn: (*rootModel).openTeamAdd},
			{section: "Team", label: "List team", hint: "show all admins", fn: (*rootModel).openTeamList},
			{section: "Team", label: "Remove team member", hint: "with rotation checklist", fn: (*rootModel).openTeamRemove},
			// Sync
			{section: "Sync", label: "Pull vault", hint: "git pull", fn: (*rootModel).openPull},
			{section: "Sync", label: "Push vault", hint: "git add/commit/push", fn: (*rootModel).openPush},
			// System
			{section: "System", label: "Status", hint: "session state", key: "s", fn: (*rootModel).openStatus},
			{section: "System", label: "Doctor", hint: "health check", key: "d", fn: (*rootModel).openDoctor},
			{section: "System", label: "Logout", hint: "end admin session", key: "o", fn: (*rootModel).doLogout},
			{section: "System", label: "Quit", hint: "exit", key: "q", fn: (*rootModel).quit},
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

	// Header — title + one-line state.
	b.WriteString(titleSt.Render("dop — Doors of Perception") + "\n")
	b.WriteString(mutedSt.Render(m.stateLine()) + "\n\n")

	// Compute label column width across all items so descriptions align.
	labelWidth := 0
	for _, it := range m.menu {
		if l := lipgloss.Width(it.label); l > labelWidth {
			labelWidth = l
		}
	}
	labelWidth += 2 // padding before description

	// Render items, inserting section headers on transitions.
	prevSection := ""
	for i, it := range m.menu {
		if it.section != prevSection && it.section != "" {
			if prevSection != "" {
				b.WriteString("\n")
			}
			b.WriteString("  " + mutedSt.Render(it.section) + "\n")
			prevSection = it.section
		} else if it.section == "" && prevSection != "" {
			b.WriteString("\n")
			prevSection = ""
		}

		prefix := "    "
		label := it.label
		if i == m.cursor {
			prefix = "  " + cursorSt.Render("➤ ")
			label = cursorSt.Render(it.label)
		}
		// Pad label to column width (padding uses raw spaces so ANSI codes
		// don't distort lipgloss.Width).
		pad := labelWidth - lipgloss.Width(it.label)
		if pad < 1 {
			pad = 1
		}
		b.WriteString(prefix + label + strings.Repeat(" ", pad))
		b.WriteString(mutedSt.Render(it.hint) + "\n")
	}

	if m.flashMessage != "" {
		b.WriteString("\n" + okSt.Render(m.flashMessage) + "\n")
	}

	// Footer — a small legend of the most useful shortcuts.
	footer := "↑↓ move · enter select"
	if m.hasShortcut("s") {
		footer += " · s status"
	}
	if m.hasShortcut("i") {
		footer += " · i issue"
	}
	if m.hasShortcut("l") {
		footer += " · l login"
	}
	footer += " · q quit"
	b.WriteString("\n" + helpSt.Render(footer))
	return b.String()
}

// hasShortcut reports whether any current menu item claims that key.
func (m *rootModel) hasShortcut(k string) bool {
	for _, it := range m.menu {
		if it.key == k {
			return true
		}
	}
	return false
}

func (m *rootModel) stateLine() string {
	switch {
	case m.install == installNoKey:
		return "no admin key — start with Setup admin"
	case m.install == installAdmin && m.session == sessionLocked:
		return "admin · locked"
	case m.install == installAdmin && m.session == sessionUnlocked:
		st, _ := m.adminClient.Status()
		if st != nil {
			return fmt.Sprintf("admin · unlocked · %s idle", remainingHuman(st.IdleTTLSeconds, st.LastActivityUnix))
		}
		return "admin · unlocked"
	}
	return ""
}

// remainingHuman is a small helper used by the state line (mirrors what
// views.go's `remaining` does — kept separate here to avoid circular type
// concerns).
func remainingHuman(ttl int64, ref int64) string {
	r := time.Until(time.Unix(ref, 0).Add(time.Duration(ttl) * time.Second))
	if r < 0 {
		r = 0
	}
	return r.Round(time.Second).String()
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

// --- new (batch 1) view openers ---

func (m *rootModel) openSetupAdmin() (tea.Model, tea.Cmd) {
	m.child = newSetupAdminView(m.paths)
	return m, m.child.Init()
}

func (m *rootModel) openAttachAdmin() (tea.Model, tea.Cmd) {
	m.child = newAttachVaultView(m.paths, true)
	return m, m.child.Init()
}

func (m *rootModel) openAttachAgent() (tea.Model, tea.Cmd) {
	m.child = newAttachVaultView(m.paths, false)
	return m, m.child.Init()
}

func (m *rootModel) openAddIntegration() (tea.Model, tea.Cmd) {
	m.child = newAddIntegrationView(m.adminClient, m.paths)
	return m, m.child.Init()
}

func (m *rootModel) openAddGrant() (tea.Model, tea.Cmd) {
	m.child = newAddGrantView(m.adminClient, m.paths)
	return m, m.child.Init()
}

// --- batch 2 openers ---
func (m *rootModel) openRevoke() (tea.Model, tea.Cmd) {
	m.child = newRevokeView(m.adminClient, m.paths)
	return m, m.child.Init()
}
func (m *rootModel) openTeamAdd() (tea.Model, tea.Cmd) {
	m.child = newTeamAddView(m.adminClient, m.paths)
	return m, m.child.Init()
}
func (m *rootModel) openTeamList() (tea.Model, tea.Cmd) {
	m.child = newTeamListView(m.adminClient, m.paths)
	return m, m.child.Init()
}
func (m *rootModel) openTeamRemove() (tea.Model, tea.Cmd) {
	m.child = newTeamRemoveView(m.adminClient, m.paths)
	return m, m.child.Init()
}

// --- batch 3 openers ---
func (m *rootModel) openIntegrationList() (tea.Model, tea.Cmd) {
	m.child = newIntegrationListView(m.adminClient, m.paths)
	return m, m.child.Init()
}
func (m *rootModel) openIntegrationRemove() (tea.Model, tea.Cmd) {
	m.child = newIntegrationRemoveView(m.adminClient, m.paths)
	return m, m.child.Init()
}
func (m *rootModel) openGrantList() (tea.Model, tea.Cmd) {
	m.child = newGrantListView(m.adminClient, m.paths)
	return m, m.child.Init()
}
func (m *rootModel) openGrantRemove() (tea.Model, tea.Cmd) {
	m.child = newGrantRemoveView(m.adminClient, m.paths)
	return m, m.child.Init()
}

// --- batch 4 openers ---
func (m *rootModel) openPull() (tea.Model, tea.Cmd) {
	m.child = newSyncView("pull", m.paths)
	return m, m.child.Init()
}
func (m *rootModel) openPush() (tea.Model, tea.Cmd) {
	m.child = newSyncView("push", m.paths)
	return m, m.child.Init()
}
