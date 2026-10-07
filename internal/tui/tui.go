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
	"os/exec"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
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

// Theme: fg is painted explicitly, bg never (light terminals keep theirs).
// One bold per screen (titleSt), one italic (placeholderSt).
var (
	fg            = lipgloss.Color("#5c5c5c")
	brand         = lipgloss.Color("#c2c4cc")
	muted         = lipgloss.Color("#404040")
	ok            = lipgloss.Color("#10b981")
	danger        = lipgloss.Color("#ef4444")
	titleSt       = lipgloss.NewStyle().Bold(true).Foreground(fg)
	bodySt        = lipgloss.NewStyle().Foreground(fg)
	mutedSt       = lipgloss.NewStyle().Foreground(muted)
	placeholderSt = lipgloss.NewStyle().Foreground(muted).Italic(true)
	focusSt       = lipgloss.NewStyle().Foreground(brand)
	okSt          = lipgloss.NewStyle().Foreground(ok)
	dangerSt      = lipgloss.NewStyle().Foreground(danger)

	// ponytail: old names kept as aliases until every view moves to the
	// role names above (waves 2-8).
	failSt   = dangerSt
	cursorSt = focusSt
	helpSt   = mutedSt
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
	sized       tea.Model // child that already got the terminal size
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
	st            status // menu status line (row 23)
	help          bool   // ? expanded help on the menu

	pendingCount int // v1.7 — surfaced as a banner above the menu

	// rc7h — session-expiry guard. When a leaf dispatch sees a locked
	// session, it stashes the target fn here and fires the osascript
	// unlock subprocess. On completion, Update handles guiUnlockResultMsg
	// by either invoking pendingUnlockFn (on success) or printing a
	// stderr line + tea.Quit (on failure).
	pendingUnlockFn func(*rootModel) (tea.Model, tea.Cmd)

	// pendingSyncFn is the screen waiting for the screen-entry vault
	// pull (syncThen) to finish; keys are ignored meanwhile.
	pendingSyncFn func(*rootModel) (tea.Model, tea.Cmd)
}

// vaultSyncedMsg — the screen-entry pull finished. note is a merge
// conflict line to show, or "".
type vaultSyncedMsg struct{ note string }

// syncThen pulls the team vault before opening fn's screen, when the
// last pull is older than the freshness window. Otherwise opens it now.
func (m *rootModel) syncThen(fn func(*rootModel) (tea.Model, tea.Cmd)) (tea.Model, tea.Cmd) {
	if !vaultSyncDue(m.paths) {
		return fn(m)
	}
	m.pendingSyncFn = fn
	m.st.setFlash("syncing with the team vault…")
	paths := m.paths
	return m, func() tea.Msg { return vaultSyncedMsg{note: syncVault(paths)} }
}

// withVaultSync wraps a menu leaf so it opens through syncThen.
func withVaultSync(fn func(*rootModel) (tea.Model, tea.Cmd)) func(*rootModel) (tea.Model, tea.Cmd) {
	return func(m *rootModel) (tea.Model, tea.Cmd) { return m.syncThen(fn) }
}

// guiUnlockResultMsg is delivered by the runGUIUnlock Cmd when the
// `dop admin __gui-unlock` subprocess exits.
type guiUnlockResultMsg struct {
	success bool
	stderr  string
}

type menuItem struct {
	label string
	hint  string
	key   string // single-key shortcut (for the footer legend only)
	fn    func(*rootModel) (tea.Model, tea.Cmd)
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
	// sync pulls the team vault (rate-limited) before any of this
	// group's screens open, so they show the latest team state.
	sync bool
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
	// rc6k-fix [S5] — always clear the groups surface on rebuild. The
	// admin-unlocked branch below repopulates it; every other branch
	// (locked, no-key, no-vault) needs it empty so Update() routes to
	// the flat menu via the default key handler instead of the groups
	// handler. Prior behavior: logout flipped session=locked and built
	// a flat menu, but m.groups stayed populated → updateGroupsMenu
	// took precedence → operator still inside admin "More" submenu
	// until they pressed q + reopened.
	m.groups = nil
	m.inGroup = -1
	switch {
	case m.install == installNoKey:
		// Setup mode: no section headers (per TUI_GUIDELINES.md).
		m.menu = []menuItem{
			{label: "Setup admin", hint: "generate + wrap admin keys", key: "S", fn: (*rootModel).openSetupAdmin},
			{label: "Attach vault", hint: "join an existing vault as agent", key: "a", fn: (*rootModel).openAttachAgent},
			{label: "Join existing vault", hint: "become an admin device via invite PIN", key: "j", fn: (*rootModel).openJoin},
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
				label: "Add", hint: "service, grant, device, team member", key: "1", sync: true,
				items: []menuItem{
					{label: "Integration", hint: "a service and its first credential", fn: (*rootModel).openAddIntegration},
					{label: "Grant", hint: "map a name to a credential", fn: (*rootModel).openAddGrant},
					{label: "Device", hint: "invite another machine of yours", fn: (*rootModel).openInviteDevice},
					{label: "Team member", hint: "invite another admin", fn: (*rootModel).openInviteMember},
					{label: "Team member by key", hint: "add an admin with their public keys", fn: (*rootModel).openTeamAdd},
				},
			},
			{
				label: "Issue", hint: "hand a bearer to an agent", key: "2", sync: true,
				direct: (*rootModel).openIssue,
			},
			{
				label: "List", hint: "integrations, grants, bearers, team", key: "3", sync: true,
				items: []menuItem{
					{label: "Integrations", hint: "services and their credentials", fn: (*rootModel).openIntegrationList},
					{label: "Grants", hint: "names mapped to credentials", fn: (*rootModel).openGrantList},
					{label: "Bearers", hint: "issued bearers", fn: (*rootModel).openList},
					{label: "Team", hint: "all admins", fn: (*rootModel).openTeamList},
				},
			},
			{
				label: "Remove", hint: "revoke a bearer, drop a grant, retire a service", key: "4", sync: true,
				items: []menuItem{
					{label: "Bearer", hint: "revoke an issued bearer", fn: (*rootModel).openRevoke},
					{label: "Grant", hint: "drop a grant", fn: (*rootModel).openGrantRemove},
					{label: "Integration", hint: "retire a service or some of its credentials", fn: (*rootModel).openIntegrationRemove},
					{label: "Team member", hint: "with rotation checklist", fn: (*rootModel).openTeamRemove},
				},
			},
			{
				label: "Vault", hint: "status, pull, push, doctor", key: "5",
				items: []menuItem{
					{label: "Status", hint: "session + vault state", fn: (*rootModel).openStatus},
					{label: "Pull", hint: "git pull", fn: (*rootModel).openPull},
					{label: "Push", hint: "git add/commit/push", fn: (*rootModel).openPush},
					{label: "Doctor", hint: "health check", fn: (*rootModel).openDoctor},
				},
			},
			{
				label: "More", hint: "settings, update, logout, uninstall", key: "M",
				items: []menuItem{
					{label: "Settings", hint: "file keys, session timeout, harness", fn: (*rootModel).openSettings},
					{label: "Update", hint: "check for a newer dop (installed " + version.Short() + ")", fn: (*rootModel).openUpdate},
					{label: "Logout", hint: "end admin session", fn: (*rootModel).doLogout},
					{label: "Uninstall", hint: "wipe every DOP file on this machine, keep the vault repo", fn: (*rootModel).openReset},
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

// Update hands a newly opened child the terminal size once (the
// WindowSizeMsg only arrives at launch and on resize).
func (m *rootModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	_, cmd := m.update(msg)
	if m.child != nil && m.child != m.sized && m.width > 0 {
		m.child, _ = m.child.Update(tea.WindowSizeMsg{Width: m.width, Height: m.height})
		m.sized = m.child
	}
	return m, cmd
}

func (m *rootModel) update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch sz := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = sz.Width, sz.Height
	case vaultSyncedMsg:
		if fn := m.pendingSyncFn; fn != nil {
			m.pendingSyncFn = nil
			m.st.setFlash(sz.note)
			return fn(m)
		}
		return m, nil
	case guiUnlockResultMsg:
		if m.child != nil && m.pendingUnlockFn == nil {
			break // a view's sessionGuard save
		}
		// rc7h — session-guard result handler. On success refresh state
		// so the daemon's new session is visible, then invoke the stashed
		// leaf fn. On failure print the specific error to stderr (so it
		// survives the TUI exit) and quit cleanly — the operator will
		// re-enter at the shell prompt and can `dop admin login` manually.
		if sz.success {
			m.refreshState()
			m.rebuildMenu()
			if fn := m.pendingUnlockFn; fn != nil {
				m.pendingUnlockFn = nil
				return fn(m)
			}
			return m, nil
		}
		fmt.Fprintln(os.Stderr, "dop: admin session expired — unlock cancelled or dialog unavailable.")
		if sz.stderr != "" {
			fmt.Fprintln(os.Stderr, "  "+sz.stderr)
		}
		fmt.Fprintln(os.Stderr, "  run `dop admin login` and re-launch the TUI.")
		return m, tea.Quit
	}
	if m.child != nil {
		child, cmd := m.child.Update(msg)
		if d, ok := child.(doner); ok && d.Done() {
			// Post-child: refresh state and go back to the menu.
			m.child = nil
			m.screen = screenMenu
			m.help = false
			// Pull one-shot flash message from the child if it exposes one.
			if fm, ok := child.(flasher); ok {
				m.st.setFlash(fm.Flash())
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
		if m.pendingSyncFn != nil && km.String() != "ctrl+c" {
			return m, nil // a screen is about to open after the pull
		}
		m.st.onKey(true) // ponytail: the cursor is the menu's only input
		if toggleHelp(&m.help, km) {
			return m, nil
		}
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

// guardAdminAction runs fn if the admin session is still active;
// otherwise it stashes fn in pendingUnlockFn and fires the osascript
// unlock subprocess. The user sees the dialog; on success Update will
// invoke fn; on cancel/fail Update prints a stderr line + quits the TUI.
// rc7h — fixes the "TUI stayed open with stale session, downstream
// subprocess failed cryptically" trap on invite/add/remove/... flows.
func (m *rootModel) guardAdminAction(fn func(*rootModel) (tea.Model, tea.Cmd)) (tea.Model, tea.Cmd) {
	if m.adminClient != nil && m.adminClient.SessionActive() {
		return fn(m)
	}
	m.pendingUnlockFn = fn
	m.st.setFlash("admin session expired, unlock prompt opening…")
	return m, runGUIUnlock()
}

// runGUIUnlock spawns `dop admin __gui-unlock` and returns the result
// as a guiUnlockResultMsg. Blocking subprocess (osascript dialog), so
// the Cmd goroutine stays alive until the user interacts.
func runGUIUnlock() tea.Cmd {
	return func() tea.Msg {
		self, err := os.Executable()
		if err != nil {
			return guiUnlockResultMsg{success: false, stderr: err.Error()}
		}
		cmd := exec.Command(self, "admin", "__gui-unlock",
			"--title", "DOP admin unlock",
			"--body", "The admin session expired. Enter your admin passphrase to continue.")
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
		var stderr strings.Builder
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return guiUnlockResultMsg{success: false, stderr: strings.TrimSpace(stderr.String())}
		}
		return guiUnlockResultMsg{success: true}
	}
}

// lockedNote is a view's status line while the GUI unlock is open.
const lockedNote = "admin session locked, unlock prompt opening…"

// sessionGuard re-checks the admin session right before a view shells
// out to the CLI for a mutation (embedded in wiz and the list views).
type sessionGuard struct {
	retry tea.Msg // the key that started the save, replayed after the unlock
	errp  *string // the view's status-line error
}

// locked is nil when the session is unlocked: run the save now. When it
// is locked the view stays where it is with lockedNote on its status
// line and the GUI unlock opens; once that succeeds key is replayed, so
// the save runs again from the same place.
func (g *sessionGuard) locked(key tea.Msg, errp *string) tea.Cmd {
	paths, err := config.Resolve()
	if err != nil || admin.NewClient(admin.SockPath(paths)).SessionActive() {
		return nil
	}
	g.retry, g.errp, *errp = key, errp, lockedNote
	return runGUIUnlock()
}

// unlocked consumes the GUI unlock result of a locked() save.
func (g *sessionGuard) unlocked(msg tea.Msg) (bool, tea.Cmd) {
	r, ok := msg.(guiUnlockResultMsg)
	if !ok || g.errp == nil {
		return false, nil
	}
	errp, key := g.errp, g.retry
	*g = sessionGuard{}
	if !r.success {
		*errp = "Admin session locked: " + displayOr(r.stderr, "unlock failed")
		return true, nil
	}
	*errp = ""
	return true, func() tea.Msg { return key }
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
			return m.syncThen((*rootModel).openPendingApprove)
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
	leaf := func(i int) func(*rootModel) (tea.Model, tea.Cmd) {
		if m.groups[m.inGroup].sync {
			return withVaultSync(items[i].fn)
		}
		return items[i].fn
	}
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
			return m.guardAdminAction(leaf(m.cursor))
		}
	}
	// Numeric shortcut within the sub-menu (1..len(items)).
	if n, ok := parseDigit(s); ok {
		if n >= 1 && n <= len(items) {
			return m.guardAdminAction(leaf(n - 1))
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
		if g.sync {
			return m.guardAdminAction(withVaultSync(g.direct))
		}
		return m.guardAdminAction(g.direct)
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
	return m.viewMenu()
}

// viewMenu renders every menu (flat, admin top level, group) through
// the frame: one row per item, label + muted description, digits kept
// on the numbered admin menus.
func (m *rootModel) viewMenu() string {
	type row struct{ key, label, hint string } // key: "1".."9", "M", or ""
	var rows []row
	title := "dop"
	k := keyMap{short: []key.Binding{keyOpen}}
	switch {
	case len(m.groups) > 0 && m.inGroup < 0:
		for _, g := range m.groups {
			rows = append(rows, row{g.key, g.label, g.hint})
		}
		k.full = [][]key.Binding{{keyMove, keyJump, hint("m", "more")}, {keyOpen, keyQuit}}
	case len(m.groups) > 0:
		g := m.groups[m.inGroup]
		title = g.label
		for i, it := range g.items {
			rows = append(rows, row{fmt.Sprintf("%d", i+1), it.label, it.hint})
		}
		k.short = []key.Binding{keyOpen, keyBack}
		jump := hint(fmt.Sprintf("1–%d", min(len(g.items), 9)), "jump")
		k.full = [][]key.Binding{{keyMove, jump}, {keyOpen, keyBack, keyQuit}}
	default:
		var keys []key.Binding
		for _, it := range m.menu {
			rows = append(rows, row{"", it.label, it.hint})
			if it.key != "" && it.key != "q" {
				keys = append(keys, hint(it.key, strings.ToLower(it.label)))
			}
		}
		k.full = [][]key.Binding{{keyMove, keyOpen, keyQuit}, keys}
	}
	if m.pendingCount > 0 {
		k.full[0] = append(k.full[0], hint("a", "review pending"))
	}

	labelWidth := 0
	for _, r := range rows {
		labelWidth = max(labelWidth, lipgloss.Width(r.label))
	}
	body := make([]string, 0, len(rows))
	for i, r := range rows {
		label := r.label + strings.Repeat(" ", labelWidth-lipgloss.Width(r.label)+2)
		if r.key != "" {
			label = r.key + ". " + label
		}
		cursor, st := "  ", bodySt
		if i == m.cursor {
			cursor, st = "› ", focusSt
		}
		body = append(body, st.Render(cursor+label)+mutedSt.Render(r.hint))
	}
	body = k.overlay(body, m.width, frameRows(m.height), m.help)

	st := m.st
	if m.pendingCount > 0 {
		st.setHint(fmt.Sprintf("! %s pending, press a to review", plural(m.pendingCount, "claim")))
	}
	return frame(m.width, m.height, title, nil, m.stateLine(), body, st.String(), k.footerLine(m.width, m.help))
}

func (m *rootModel) stateLine() string {
	switch {
	case m.install == installNoKey:
		return "no admin key"
	case m.install == installAdmin && m.session == sessionLocked:
		return "locked"
	case m.install == installAdmin && m.session == sessionUnlocked:
		if m.adminClient == nil {
			return "unlocked"
		}
		st, _ := m.adminClient.Status()
		if st == nil || !st.Unlocked {
			return "locked" // expired since the last refreshState
		}
		left := min(timeLeft(st.IdleTTLSeconds, st.LastActivityUnix), timeLeft(st.AbsTTLSeconds, st.StartedAtUnix))
		if left > 10*365*24*time.Hour {
			return "unlocked · until logout" // ponytail: idle never sets both TTLs to 100 years
		}
		return "unlocked · " + shortDuration(left) + " left"
	}
	return ""
}

// timeLeft is how long until ref + ttl seconds, never negative.
func timeLeft(ttl int64, ref int64) time.Duration {
	return max(time.Until(time.Unix(ref, 0).Add(time.Duration(ttl)*time.Second)), 0)
}

// shortDuration: 45s, 30m, 1h30m, 2h, 7d — no seconds from 1m up, whole
// days from 24h up.
func shortDuration(d time.Duration) string {
	if d < time.Minute {
		return d.Round(time.Second).String()
	}
	d = d.Round(time.Minute)
	if d >= 24*time.Hour {
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	}
	s := strings.TrimSuffix(d.String(), "0s")
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
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
	v := newListView(m.adminClient, m.paths)
	v.width, v.height = m.width, m.height
	m.child = v
	m.screen = screenList
	return m, m.child.Init()
}

func (m *rootModel) doLogout() (tea.Model, tea.Cmd) {
	_ = m.adminClient.Logout()
	m.st.setFlash("logged out")
	m.refreshState()
	// rc6c — the daemon exits ~50ms after returning the logout RPC, so
	// refreshState() running immediately above sees SessionActive() still
	// true and leaves state as sessionUnlocked. Force it so the next
	// menu rebuild lands on the login/attach menu. See rc3-smoke-retakes
	// [S5] (logout doesn't kick out of admin menu).
	m.session = sessionLocked
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
	v := newAddIntegrationView(m.adminClient, m.paths)
	v.width = m.width
	m.child = v
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
func (m *rootModel) openUpdate() (tea.Model, tea.Cmd) {
	m.child = newUpdateView(m.paths)
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
	v := newIntegrationListView(m.adminClient, m.paths)
	v.width, v.height = m.width, m.height
	m.child = v
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
