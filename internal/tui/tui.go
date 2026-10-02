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
	"github.com/fray/dop/internal/pendingclaim"
	"github.com/fray/dop/internal/version"
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
	screenPending  // v1.7: inline pending-claim approve panel
	screenSettings // v1.13: TUI prefs (allow-file-keys toggle)
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

	// v1.13.0-rc19 — hierarchical menu state. groups is populated only
	// in the admin-unlocked case; otherwise len(groups)==0 and the
	// flat `menu` renders as before. inGroup=-1 → top-level groups
	// list is shown; inGroup>=0 → leaves of groups[inGroup] are shown.
	groups  []menuGroup
	inGroup int

	width, height int
	quitting      bool
	flashMessage  string // one-shot info message shown below the menu

	pendingCount int // v1.7 — surfaced as a banner above the menu
}

type menuItem struct {
	label   string
	hint    string
	key     string // single-key shortcut (for the footer legend only)
	section string // grouping header; empty = ungrouped
	fn      func(*rootModel) (tea.Model, tea.Cmd)
}

// v1.13.0-rc19 — hierarchical menu for the full admin-unlocked state.
// Each group has a 1-char key (1-5 for primaries, M for the overflow
// drawer) and holds a flat list of leaf menuItems. All other install
// states (NoKey / Locked / NoVault) still use the flat `menu` field —
// those menus are small enough that nesting adds no value.
type menuGroup struct {
	label string
	hint  string
	key   string // "1".."5", "M"
	items []menuItem
	// direct is set when the group is really a single leaf — e.g. the
	// "Issue" primary opens the issue flow directly instead of a
	// sub-page. When direct != nil, items is ignored.
	direct func(*rootModel) (tea.Model, tea.Cmd)
}

func newRootModel() *rootModel {
	m := &rootModel{inGroup: -1}
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
	// v1.7 — pending-claim banner. Only counts non-expired entries.
	m.pendingCount = 0
	if all, err := pendingclaim.List(paths); err == nil {
		now := time.Now()
		for _, r := range all {
			if !r.Expired(now) {
				m.pendingCount++
			}
		}
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
			{label: "Join existing vault", hint: "become an admin device via invite PIN (v1.9)", key: "j", fn: (*rootModel).openJoin},
			{label: "Doctor", hint: "health check", key: "d", fn: (*rootModel).openDoctor},
			{label: "Uninstall", hint: "wipe DOP from this machine", fn: (*rootModel).openReset},
			{label: "Quit", hint: "exit", key: "q", fn: (*rootModel).quit},
		}
	case m.install == installAdmin && m.session == sessionLocked:
		m.menu = []menuItem{
			{label: "Login", hint: "unlock admin session", key: "l", fn: (*rootModel).openLogin},
			{label: "Doctor", hint: "health check", key: "d", fn: (*rootModel).openDoctor},
			{label: "Uninstall", hint: "wipe DOP from this machine", fn: (*rootModel).openReset},
			{label: "Quit", hint: "exit", key: "q", fn: (*rootModel).quit},
		}
	case m.install == installAdmin && m.session == sessionUnlocked && !vaultAttached(m.paths):
		m.menu = []menuItem{
			{label: "Attach vault", hint: "clone/link a vault repo", key: "a", fn: (*rootModel).openAttachAdmin},
			{label: "Doctor", hint: "health check", key: "d", fn: (*rootModel).openDoctor},
			{label: "Uninstall", hint: "wipe DOP from this machine", fn: (*rootModel).openReset},
			{label: "Logout", hint: "end admin session", key: "o", fn: (*rootModel).doLogout},
			{label: "Quit", hint: "exit", key: "q", fn: (*rootModel).quit},
		}
	case m.install == installAdmin && m.session == sessionUnlocked:
		// v1.13.0-rc19 — hierarchical menu. Six primaries (1-5 + M).
		// Every leaf still calls an existing openX method — this is a
		// pure layout refactor; no feature is added or removed.
		m.menu = nil
		m.groups = []menuGroup{
			{
				label: "Add", hint: "register a service, grant, or team member", key: "1",
				items: []menuItem{
					{label: "Integration", hint: "add a service + upstream tokens", fn: (*rootModel).openAddIntegration},
					{label: "Grant", hint: "map a grant to an integration/token", fn: (*rootModel).openAddGrant},
					{label: "Device", hint: "invite another machine of yours (v1.9)", fn: (*rootModel).openInviteDevice},
					{label: "Team member (invite)", hint: "invite another human as admin (v1.9)", fn: (*rootModel).openInviteMember},
					{label: "Team member (manual)", hint: "add another admin's pubkey directly", fn: (*rootModel).openTeamAdd},
				},
			},
			{
				label: "Issue", hint: "hand a bearer to an agent", key: "2",
				direct: (*rootModel).openIssue,
			},
			{
				label: "List", hint: "browse integrations, grants, bearers, team", key: "3",
				items: []menuItem{
					{label: "Integrations", hint: "all services + their tokens", fn: (*rootModel).openIntegrationList},
					{label: "Grants", hint: "named bindings", fn: (*rootModel).openGrantList},
					{label: "Bearers", hint: "active issued tokens", fn: (*rootModel).openList},
					{label: "Team", hint: "all admins", fn: (*rootModel).openTeamList},
				},
			},
			{
				label: "Remove", hint: "revoke a bearer, drop a grant, retire a service", key: "4",
				items: []menuItem{
					{label: "Bearer", hint: "revoke an issued token", fn: (*rootModel).openRevoke},
					{label: "Grant", hint: "drop a grant", fn: (*rootModel).openGrantRemove},
					{label: "Integration", hint: "drill into a service, pick credentials to remove (+ cascade)", fn: (*rootModel).openIntegrationRemove},
					{label: "Team member", hint: "with rotation checklist", fn: (*rootModel).openTeamRemove},
				},
			},
			{
				label: "Vault", hint: "status · pull · push · doctor", key: "5",
				items: []menuItem{
					{label: "Status", hint: "session + vault state", fn: (*rootModel).openStatus},
					{label: "Pull", hint: "git pull", fn: (*rootModel).openPull},
					{label: "Push", hint: "git add/commit/push", fn: (*rootModel).openPush},
					{label: "Doctor", hint: "health check", fn: (*rootModel).openDoctor},
				},
			},
			{
				label: "More", hint: "settings · logout · uninstall · quit", key: "M",
				items: []menuItem{
					{label: "Settings", hint: "TUI preferences (file keys, …) · press F to toggle", fn: (*rootModel).openSettings},
					{label: "Logout", hint: "end admin session", fn: (*rootModel).doLogout},
					{label: "Uninstall", hint: "wipe every DOP file on this machine (keeps the vault repo)", fn: (*rootModel).openReset},
					{label: "Quit", hint: "exit", fn: (*rootModel).quit},
				},
			},
		}
		if m.inGroup >= len(m.groups) {
			m.inGroup = -1
		}
	default:
		// Any flat-menu state: clear groups so View renders the flat path.
		m.groups = nil
		m.inGroup = -1
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
		// Hierarchical path when groups are populated (admin-unlocked only).
		if len(m.groups) > 0 {
			return m.updateGroupsMenu(km)
		}
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
		case "a":
			if m.pendingCount > 0 {
				return m.openPendingApprove()
			}
			// fall through to menu shortcuts
			for _, it := range m.menu {
				if km.String() == it.key {
					return it.fn(m)
				}
			}
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

// updateGroupsMenu handles key routing for the v1.13.0-rc19 hierarchical
// menu. Top level (inGroup == -1): 1-5 jumps to a primary, M opens
// More, Enter opens the group under the cursor. Inside a group:
// Enter runs the leaf, 1-N jumps to it, esc goes back up.
// `a` still opens the pending-claim approver when the banner is visible.
// `q` quits from anywhere. Ctrl+C always quits.
func (m *rootModel) updateGroupsMenu(km tea.KeyMsg) (tea.Model, tea.Cmd) {
	s := km.String()
	// Global shortcuts work from any level.
	switch s {
	case "ctrl+c":
		return m.quit()
	case "q":
		return m.quit()
	case "a":
		if m.pendingCount > 0 {
			return m.openPendingApprove()
		}
	}
	if m.inGroup < 0 {
		// At the top level — show the six primaries.
		switch s {
		case "up", "k":
			if m.cursor > 0 {
				m.cursor--
			}
		case "down", "j":
			if m.cursor < len(m.groups)-1 {
				m.cursor++
			}
		case "enter":
			return m.enterGroup(m.cursor)
		}
		// Numbered / M shortcut jumps.
		for i, g := range m.groups {
			if s == g.key || s == strings.ToLower(g.key) {
				return m.enterGroup(i)
			}
		}
		return m, nil
	}
	// Inside a group — show its items.
	items := m.groups[m.inGroup].items
	switch s {
	case "esc", "backspace":
		m.inGroup = -1
		m.cursor = 0
		return m, nil
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(items)-1 {
			m.cursor++
		}
	case "enter":
		if m.cursor >= 0 && m.cursor < len(items) {
			return items[m.cursor].fn(m)
		}
	}
	// Numeric shortcut within the sub-menu (1..len(items)).
	if n, ok := parseDigit(s); ok {
		if n >= 1 && n <= len(items) {
			return items[n-1].fn(m)
		}
	}
	return m, nil
}

// enterGroup opens the group at index i. If the group has `direct` set,
// it runs the leaf immediately (e.g. Issue). Otherwise it switches to
// the group's sub-menu view.
func (m *rootModel) enterGroup(i int) (tea.Model, tea.Cmd) {
	if i < 0 || i >= len(m.groups) {
		return m, nil
	}
	g := m.groups[i]
	if g.direct != nil {
		return g.direct(m)
	}
	m.inGroup = i
	m.cursor = 0
	return m, nil
}

// parseDigit returns the integer value of a single-digit key press.
func parseDigit(s string) (int, bool) {
	if len(s) != 1 {
		return 0, false
	}
	c := s[0]
	if c < '0' || c > '9' {
		return 0, false
	}
	return int(c - '0'), true
}

func (m *rootModel) View() string {
	if m.quitting {
		return ""
	}
	if m.child != nil {
		return m.child.View()
	}
	var b strings.Builder

	// Header — title + version. v1.13.0-rc19: short title (just "dop")
	// per the Mole-inspired reorg; the longform tagline is in the README.
	b.WriteString(titleSt.Render("dop") + "  " +
		mutedSt.Render(version.Short()) + "\n")
	b.WriteString(mutedSt.Render(m.stateLine()) + "\n")

	// v1.7 — pending-claim banner. Draws attention when an agent is
	// waiting for approval; `a` from the menu opens the inline approver.
	if m.pendingCount > 0 {
		banner := fmt.Sprintf("⚠  %d pending claim(s) — press 'a' to review", m.pendingCount)
		b.WriteString(lipgloss.NewStyle().Foreground(brand).Bold(true).Render(banner) + "\n")
	}
	b.WriteString("\n")

	// v1.13.0-rc19 — hierarchical path.
	if len(m.groups) > 0 {
		return b.String() + m.viewGroups()
	}

	// Flat-menu path (Setup / Locked / NoVault).
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

// viewGroups renders the hierarchical menu. Top level shows the six
// primaries numbered 1-5 + M; inside a group shows numbered leaves
// 1..N. Flash message + footer legend render below the list.
func (m *rootModel) viewGroups() string {
	var b strings.Builder

	// Determine what to render.
	type row struct {
		key   string // "1".."5", "M", or "" for leaves beyond 9
		label string
		hint  string
	}
	var rows []row
	var breadcrumb string
	if m.inGroup < 0 {
		breadcrumb = ""
		for _, g := range m.groups {
			rows = append(rows, row{key: g.key, label: g.label, hint: g.hint})
		}
	} else {
		g := m.groups[m.inGroup]
		breadcrumb = g.label
		for i, it := range g.items {
			k := ""
			if i+1 <= 9 {
				k = fmt.Sprintf("%d", i+1)
			}
			rows = append(rows, row{key: k, label: it.label, hint: it.hint})
		}
	}

	if breadcrumb != "" {
		b.WriteString(cursorSt.Render(breadcrumb) + mutedSt.Render("                                             esc back") + "\n\n")
	}

	// Alignment: widest "N. Label" wins so hints line up.
	labelWidth := 0
	for _, r := range rows {
		w := lipgloss.Width("    "+r.key+". "+r.label) - 4
		if w > labelWidth {
			labelWidth = w
		}
	}
	labelWidth += 3

	for i, r := range rows {
		prefix := "  "
		cursor := "  "
		label := r.label
		if i == m.cursor {
			cursor = cursorSt.Render("➤ ")
			label = cursorSt.Render(r.label)
		}
		keyBit := "  "
		if r.key != "" {
			keyBit = mutedSt.Render(r.key + ". ")
		}
		raw := r.key + ". " + r.label
		pad := labelWidth - lipgloss.Width(raw)
		if pad < 1 {
			pad = 1
		}
		b.WriteString(prefix + cursor + keyBit + label + strings.Repeat(" ", pad))
		b.WriteString(mutedSt.Render(r.hint) + "\n")
	}

	if m.flashMessage != "" {
		b.WriteString("\n" + okSt.Render(m.flashMessage) + "\n")
	}

	// Footer — different per level.
	var footer string
	if m.inGroup < 0 {
		footer = "↑↓ move · 1-5 jump · enter select · M more · q quit"
	} else {
		max := len(m.groups[m.inGroup].items)
		if max > 9 {
			max = 9
		}
		footer = fmt.Sprintf("↑↓ move · 1-%d jump · enter select · esc back · q quit", max)
	}
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

func (m *rootModel) openSettings() (tea.Model, tea.Cmd) {
	m.child = newSettingsView(m.paths)
	m.screen = screenSettings
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
func (m *rootModel) openInviteDevice() (tea.Model, tea.Cmd) {
	m.child = newInviteView(m.paths, inviteKindDevice)
	return m, m.child.Init()
}
func (m *rootModel) openInviteMember() (tea.Model, tea.Cmd) {
	m.child = newInviteView(m.paths, inviteKindTeamMember)
	return m, m.child.Init()
}
func (m *rootModel) openJoin() (tea.Model, tea.Cmd) {
	m.child = newJoinView(m.paths)
	return m, m.child.Init()
}
func (m *rootModel) openReset() (tea.Model, tea.Cmd) {
	m.child = newResetView(m.paths)
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
