package views

import (
	"os"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/tui/styles"
	"github.com/fray/dop/internal/vault"
	"github.com/fray/dop/internal/vaultsync"
)

// RecipientMissingModel handles case E: the vault is cloned but this
// machine's age key isn't yet a SOPS recipient. The user needs to:
//   1. Copy their pubkey
//   2. Ask a teammate to run `dop team add-key --name X --pubkey <pubkey>`
//   3. Wait for the teammate to push
//   4. Retry (which pulls + tries decrypt again)
type RecipientMissingModel struct {
	paths     *config.Paths
	vaultPath string
	pubkey    string

	step        int // 0 = display, 1 = retrying, 2 = still-missing after retry, 3 = success
	retryOutput strings.Builder
	done        bool
	ready       bool // vault now decrypts
}

func NewRecipientMissing(paths *config.Paths, vaultPath, pubkey string) *RecipientMissingModel {
	return &RecipientMissingModel{paths: paths, vaultPath: vaultPath, pubkey: pubkey}
}

func (m *RecipientMissingModel) Init() tea.Cmd { return nil }
func (m *RecipientMissingModel) Done() bool    { return m.done }
func (m *RecipientMissingModel) Ready() bool   { return m.ready }

type retryResultMsg struct{ ok bool; msg string }

func (m *RecipientMissingModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch mm := msg.(type) {
	case retryResultMsg:
		if mm.ok {
			m.ready = true
			m.step = 3
		} else {
			m.step = 2
			m.retryOutput.WriteString(mm.msg)
		}
		return m, nil
	case tea.KeyMsg:
		switch mm.String() {
		case "ctrl+c", "q":
			m.done = true
			return m, nil
		}
		switch m.step {
		case 0, 2:
			switch mm.String() {
			case "r", "enter":
				m.step = 1
				return m, m.retryCmd()
			}
		case 1:
			// running — ignore
		case 3:
			m.done = true
		}
	}
	return m, nil
}

func (m *RecipientMissingModel) retryCmd() tea.Cmd {
	return func() tea.Msg {
		// Pull first — the teammate may have already pushed the re-encrypted vault.
		vaultsync.EnsureFresh(m.paths.Vault, 0, discardWriter{})
		// Try to load.
		if _, err := vault.Load(m.vaultPath); err == nil {
			return retryResultMsg{ok: true}
		}
		// Read a snippet of stderr for feedback.
		return retryResultMsg{ok: false, msg: "still can't decrypt — the teammate may not have pushed yet"}
	}
}

func (m *RecipientMissingModel) View() string {
	var b strings.Builder
	b.WriteString(styles.Title.Render("Vault access needed") + "\n\n")

	switch m.step {
	case 0:
		b.WriteString(styles.Status["warn"].Render("⚠  You cloned the vault, but this machine's key isn't a recipient yet.") + "\n\n")
		b.WriteString("Your public key (safe to share):\n")
		b.WriteString(styles.FormInput.Render("  "+m.pubkey) + "\n\n")
		hostShort := "this-machine"
		if h, err := os.Hostname(); err == nil {
			// short — up to the first '.'
			if i := indexByte(h, '.'); i > 0 {
				h = h[:i]
			}
			hostShort = h
		}
		b.WriteString("Ask a teammate with vault access to run, on their machine:\n")
		b.WriteString(styles.Muted.Render("  dop team add-key --name \""+hostShort+"\" --pubkey "+m.pubkey) + "\n")
		b.WriteString(styles.Muted.Render("  # then: dop push") + "\n\n")
		b.WriteString(styles.Help.Render("r retry (pulls + re-checks) · q quit"))
	case 1:
		b.WriteString("retrying…\n")
	case 2:
		b.WriteString(styles.Status["warn"].Render("still can't decrypt.") + "\n\n")
		b.WriteString("Give the teammate a moment (they may still be pushing).\n\n")
		b.WriteString(styles.Help.Render("r retry · q quit"))
	case 3:
		b.WriteString(styles.Status["ok"].Render("✓ decryption succeeded — you're in") + "\n\n")
		b.WriteString(styles.Help.Render("any key to continue"))
	}
	return b.String()
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
