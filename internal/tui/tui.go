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

	"filippo.io/age"

	"github.com/fray/dop/internal/agekeys"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/tui/styles"
	"github.com/fray/dop/internal/tui/views"
)

// agekeysLoad is a thin indirection so tests can stub if needed.
var agekeysLoad = func(path string) (*age.X25519Identity, error) {
	return agekeys.LoadPrivateKey(path)
}

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
	cursor      int
	menu        []menuItem
	screen      screenKind
	child       tea.Model // active sub-model, nil when on the menu
	paths       *config.Paths
	vaultPath   string
	width       int
	height      int
	quitting    bool

	// First-run coordination.
	setupPhase  setupPhase
	setupPubkey string // filled by Welcome; used by Recipient-Missing screen
}

// setupPhase drives the first-run flow that runs BEFORE the menu shows.
// setupPhaseNone means we're past setup and the menu is live.
type setupPhase int

const (
	setupPhaseNone setupPhase = iota
	setupPhaseWelcome
	setupPhaseAttachMenu
	setupPhaseConnectExisting
	setupPhaseCreateNew
	setupPhaseRecipientMissing
)

func newRootModel() (*rootModel, error) {
	paths, err := config.Resolve()
	if err != nil {
		return nil, err
	}
	state, vp := DetectSetup(paths)
	m := &rootModel{
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
	}
	// Route through the first-run flow if setup isn't ready.
	switch state {
	case SetupNoKey:
		m.setupPhase = setupPhaseWelcome
		m.child = views.NewWelcome(paths)
	case SetupNoVault:
		m.setupPhase = setupPhaseAttachMenu
		m.child = views.NewAttachVault()
	case SetupNotRecipient:
		m.setupPhase = setupPhaseRecipientMissing
		pk := readPubkey(paths)
		m.setupPubkey = pk
		m.child = views.NewRecipientMissing(paths, vp, pk)
	case SetupVaultEmpty, SetupReady:
		// Fall through to menu; nothing to gate on.
	}
	return m, nil
}

func readPubkey(paths *config.Paths) string {
	if paths == nil {
		return ""
	}
	id, err := agekeysLoad(paths.KeyFile)
	if err != nil {
		return ""
	}
	return id.Recipient().String()
}

func (m *rootModel) Init() tea.Cmd {
	if m.child != nil {
		return m.child.Init()
	}
	return nil
}

func (m *rootModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	// Global window sizing.
	if sz, ok := msg.(tea.WindowSizeMsg); ok {
		m.width, m.height = sz.Width, sz.Height
	}

	// Bubble events to the active child first; child returns nil model when done.
	if m.child != nil {
		child, cmd := m.child.Update(msg)
		if closer, ok := child.(views.Closer); ok && closer.Done() {
			// If we're mid-setup, use the child that just closed to decide
			// the next phase, then possibly quit if the user aborted.
			if m.setupPhase != setupPhaseNone {
				return m.advanceSetup(child, cmd)
			}
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

// advanceSetup is called when a setup child screen has hit Done(). It
// figures out the next phase from the child's outcome (via type asserts
// on the sub-model's methods) and either transitions or drops out of
// setup and shows the main menu.
func (m *rootModel) advanceSetup(closedChild tea.Model, prevCmd tea.Cmd) (tea.Model, tea.Cmd) {
	switch m.setupPhase {
	case setupPhaseWelcome:
		if w, ok := closedChild.(*views.WelcomeModel); ok {
			m.setupPubkey = w.Pubkey()
		}
		// Recheck state after keygen; likely we now need to attach a vault.
		state, vp := DetectSetup(m.paths)
		m.vaultPath = vp
		if state == SetupNoVault {
			m.setupPhase = setupPhaseAttachMenu
			m.child = views.NewAttachVault()
			return m, m.child.Init()
		}
		if state == SetupNotRecipient {
			m.setupPhase = setupPhaseRecipientMissing
			m.child = views.NewRecipientMissing(m.paths, vp, m.setupPubkey)
			return m, m.child.Init()
		}
		// Otherwise fall through to menu.
		return m.exitSetup()
	case setupPhaseAttachMenu:
		if av, ok := closedChild.(*views.AttachVaultModel); ok {
			switch av.Choice() {
			case views.AttachExisting:
				m.setupPhase = setupPhaseConnectExisting
				m.child = views.NewConnectExisting(m.paths, m.pubkeyOrRead())
				return m, m.child.Init()
			case views.AttachCreate:
				m.setupPhase = setupPhaseCreateNew
				m.child = views.NewCreateNew(m.paths, m.pubkeyOrRead())
				return m, m.child.Init()
			case views.AttachSkip, views.AttachNone:
				return m.exitSetup()
			}
		}
		return m.exitSetup()
	case setupPhaseConnectExisting:
		// After clone, re-detect. If NotRecipient → next phase. If Ready or
		// VaultEmpty → menu.
		state, vp := DetectSetup(m.paths)
		m.vaultPath = vp
		if state == SetupNotRecipient {
			m.setupPhase = setupPhaseRecipientMissing
			m.child = views.NewRecipientMissing(m.paths, vp, m.pubkeyOrRead())
			return m, m.child.Init()
		}
		// If the user hit a clone failure, kick them back to the attach menu.
		if ce, ok := closedChild.(*views.ConnectExistingModel); ok && ce.NeedsRetry() {
			m.setupPhase = setupPhaseAttachMenu
			m.child = views.NewAttachVault()
			return m, m.child.Init()
		}
		return m.exitSetup()
	case setupPhaseCreateNew:
		state, vp := DetectSetup(m.paths)
		m.vaultPath = vp
		if state == SetupNotRecipient {
			m.setupPhase = setupPhaseRecipientMissing
			m.child = views.NewRecipientMissing(m.paths, vp, m.pubkeyOrRead())
			return m, m.child.Init()
		}
		return m.exitSetup()
	case setupPhaseRecipientMissing:
		if rm, ok := closedChild.(*views.RecipientMissingModel); ok && rm.Ready() {
			return m.exitSetup()
		}
		// The user hit q — quit.
		m.quitting = true
		return m, tea.Quit
	}
	return m.exitSetup()
}

func (m *rootModel) exitSetup() (tea.Model, tea.Cmd) {
	m.setupPhase = setupPhaseNone
	m.child = nil
	m.screen = screenMenu
	return m, nil
}

func (m *rootModel) pubkeyOrRead() string {
	if m.setupPubkey != "" {
		return m.setupPubkey
	}
	m.setupPubkey = readPubkey(m.paths)
	return m.setupPubkey
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
