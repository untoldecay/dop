package views

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/fray/dop/internal/agekeys"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/tui/styles"
)

// WelcomeModel handles case A (no age key on this machine). It generates
// a keypair, writes it to disk with restrictive permissions, shows the
// pubkey (with a note that it may be needed to join an existing vault),
// then transitions.
type WelcomeModel struct {
	paths *config.Paths

	stage    int    // 0 = pre-generate, 1 = generated, 2 = done
	pubkey   string
	errorMsg string
	done     bool
}

func NewWelcome(paths *config.Paths) *WelcomeModel {
	return &WelcomeModel{paths: paths}
}

func (m *WelcomeModel) Init() tea.Cmd { return nil }
func (m *WelcomeModel) Done() bool    { return m.done }
func (m *WelcomeModel) Pubkey() string { return m.pubkey }

func (m *WelcomeModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	km, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch km.String() {
	case "ctrl+c", "esc":
		m.done = true
		return m, nil
	case "enter":
		if m.stage == 0 {
			m.generate()
		} else {
			m.done = true
		}
	}
	return m, nil
}

func (m *WelcomeModel) generate() {
	if m.paths == nil {
		m.errorMsg = "path resolution failed"
		return
	}
	if err := m.paths.EnsureDirs(); err != nil {
		m.errorMsg = err.Error()
		return
	}
	id, err := agekeys.Generate()
	if err != nil {
		m.errorMsg = err.Error()
		return
	}
	if err := agekeys.WritePrivateKey(id, m.paths.KeyFile); err != nil {
		m.errorMsg = err.Error()
		return
	}
	m.pubkey = id.Recipient().String()
	m.stage = 1
}

func (m *WelcomeModel) View() string {
	var b strings.Builder
	b.WriteString(styles.Title.Render("Welcome to dop") + "\n\n")

	if m.stage == 0 {
		b.WriteString("First run on this machine. I'll generate an age keypair\n")
		b.WriteString("that becomes your identity to the vault.\n\n")
		b.WriteString(styles.FormLabel.Render("Location: ") + styles.FormInput.Render(m.paths.KeyFile) + "\n")
		b.WriteString(styles.FormLabel.Render("Mode:     ") + styles.FormInput.Render("0600 (only readable by you)") + "\n\n")
		if m.errorMsg != "" {
			b.WriteString(styles.Status["fail"].Render("error: "+m.errorMsg) + "\n\n")
		}
		b.WriteString(styles.Help.Render("enter generate · esc quit"))
		return b.String()
	}
	// stage 1: show pubkey + next-step hint.
	b.WriteString(styles.Status["ok"].Render("✓ keypair generated") + "\n\n")
	b.WriteString(styles.FormLabel.Render("Your public key (safe to share):") + "\n")
	b.WriteString(styles.FormInput.Render("  " + m.pubkey) + "\n\n")
	b.WriteString(fmt.Sprintf("If you're joining an existing vault, send this to a teammate.\n"))
	b.WriteString("They'll run:\n")
	b.WriteString(styles.Muted.Render("  dop team add-key --name \"cam-macbook\" --pubkey " + m.pubkey) + "\n\n")
	b.WriteString(styles.Help.Render("enter continue"))
	return b.String()
}
