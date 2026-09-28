package views

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/gitprobe"
	"github.com/fray/dop/internal/tui/styles"
	"github.com/fray/dop/internal/vaultgit"
)

// ConnectExistingModel walks: URL prompt → probe hints → confirm → clone.
// On success, transitions out; the root re-runs setup detection.
type ConnectExistingModel struct {
	paths *config.Paths

	url        strings.Builder
	step       int // 0 = url input, 1 = probe display, 2 = cloning, 3 = success, 4 = fail
	pubkey     string
	report     gitprobe.Report
	cloneOut   strings.Builder
	cloneErr   string
	done       bool
	needsRetry bool
}

func NewConnectExisting(paths *config.Paths, pubkey string) *ConnectExistingModel {
	return &ConnectExistingModel{paths: paths, pubkey: pubkey}
}

func (m *ConnectExistingModel) Init() tea.Cmd { return nil }
func (m *ConnectExistingModel) Done() bool    { return m.done }
func (m *ConnectExistingModel) NeedsRetry() bool { return m.needsRetry }

type cloneResultMsg struct{ err string }

func (m *ConnectExistingModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch mm := msg.(type) {
	case cloneResultMsg:
		if mm.err != "" {
			m.cloneErr = mm.err
			m.step = 4
		} else {
			m.step = 3
		}
		return m, nil
	case tea.KeyMsg:
		switch mm.String() {
		case "ctrl+c":
			m.done = true
			return m, nil
		}
		switch m.step {
		case 0:
			return m.updateURL(mm)
		case 1:
			return m.updateProbe(mm)
		case 2:
			// While cloning, ignore keys (except ctrl+c above).
		case 3, 4:
			m.done = true
		}
	}
	return m, nil
}

func (m *ConnectExistingModel) updateURL(km tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch km.String() {
	case "esc":
		m.done = true
	case "enter":
		u := strings.TrimSpace(m.url.String())
		if u == "" {
			return m, nil
		}
		m.report = gitprobe.Probe(u)
		m.step = 1
	case "backspace":
		s := m.url.String()
		if len(s) > 0 {
			m.url.Reset()
			m.url.WriteString(s[:len(s)-1])
		}
	default:
		if len(km.Runes) > 0 {
			m.url.WriteString(string(km.Runes))
		}
	}
	return m, nil
}

func (m *ConnectExistingModel) updateProbe(km tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch km.String() {
	case "esc":
		m.step = 0
	case "enter":
		if len(m.report.Blockers) > 0 {
			return m, nil // don't allow proceeding with blockers
		}
		m.step = 2
		return m, m.cloneCmd()
	}
	return m, nil
}

func (m *ConnectExistingModel) cloneCmd() tea.Cmd {
	return func() tea.Msg {
		err := vaultgit.Attach(strings.TrimSpace(m.url.String()), m.paths.Vault, m.pubkey, &m.cloneOut)
		if err != nil {
			return cloneResultMsg{err: err.Error() + "\n" + m.cloneOut.String()}
		}
		return cloneResultMsg{}
	}
}

func (m *ConnectExistingModel) View() string {
	var b strings.Builder
	b.WriteString(styles.Title.Render("Connect to existing vault") + "\n\n")

	switch m.step {
	case 0:
		b.WriteString(styles.FormLabel.Render("Vault repo URL (https or ssh):") + "\n")
		b.WriteString(styles.FormInput.Render("› "+m.url.String()) + "\n\n")
		b.WriteString(styles.Muted.Render("examples:") + "\n")
		b.WriteString(styles.Muted.Render("  https://github.com/you/dop-vault.git") + "\n")
		b.WriteString(styles.Muted.Render("  git@github.com:you/dop-vault.git") + "\n")
		b.WriteString(styles.Muted.Render("  /tmp/local-bare.git   (for testing)") + "\n\n")
		b.WriteString(styles.Help.Render("enter continue · esc back"))
	case 1:
		b.WriteString(styles.FormLabel.Render("URL:") + " " + styles.FormInput.Render(m.report.URL) + "\n")
		b.WriteString(styles.FormLabel.Render("Protocol:") + " " + styles.FormInput.Render(string(m.report.Protocol)) + "\n\n")
		if len(m.report.Blockers) > 0 {
			for _, x := range m.report.Blockers {
				b.WriteString(styles.Status["fail"].Render("✗ "+x) + "\n")
			}
			b.WriteString("\n" + styles.Help.Render("esc go back and fix URL"))
			return b.String()
		}
		if len(m.report.Hints) > 0 {
			for _, x := range m.report.Hints {
				b.WriteString(styles.Status["warn"].Render("! "+x) + "\n")
			}
			b.WriteString("\n")
		} else {
			b.WriteString(styles.Status["ok"].Render("✓ no known issues") + "\n\n")
		}
		b.WriteString(styles.Help.Render("enter clone now · esc go back"))
	case 2:
		b.WriteString("cloning...\n\n")
		b.WriteString(styles.Muted.Render(tail(m.cloneOut.String(), 6)) + "\n")
	case 3:
		b.WriteString(styles.Status["ok"].Render("✓ vault cloned and connected") + "\n\n")
		b.WriteString(styles.Muted.Render("dop will now retry the main flow. If your key isn't a recipient\nyet, you'll see the 'not a recipient' screen.") + "\n\n")
		b.WriteString(styles.Help.Render("any key to continue"))
	case 4:
		b.WriteString(styles.Status["fail"].Render("✗ clone failed") + "\n\n")
		b.WriteString(styles.Muted.Render(tail(m.cloneErr, 12)) + "\n\n")
		b.WriteString(styles.Help.Render("any key to go back to the vault menu"))
		m.needsRetry = true
	}
	return b.String()
}

func tail(s string, n int) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) <= n {
		return strings.Join(lines, "\n")
	}
	return fmt.Sprintf("… %d earlier lines …\n%s", len(lines)-n, strings.Join(lines[len(lines)-n:], "\n"))
}
