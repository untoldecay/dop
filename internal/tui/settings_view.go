// Settings view — one-screen TUI toggle for the small set of operator
// prefs we track in tui-prefs.yaml. Right now the only toggle is
// AllowFileKeys (v1.12 direct-availability unlocker on hosts where
// the Secure Enclave isn't reachable).

package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/fray/dop/internal/config"
)

type settingsView struct {
	paths *config.Paths
	prefs Prefs
	done  bool
	flash string
	err   string
}

func newSettingsView(p *config.Paths) *settingsView {
	return &settingsView{paths: p, prefs: LoadPrefs(p)}
}

func (v *settingsView) Init() tea.Cmd { return nil }
func (v *settingsView) Done() bool    { return v.done }
func (v *settingsView) Flash() string { return v.flash }

func (v *settingsView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	mm, ok := msg.(tea.KeyMsg)
	if !ok {
		return v, nil
	}
	switch mm.String() {
	case "esc", "q", "ctrl+c":
		v.done = true
		return v, nil
	case "f":
		v.prefs.AllowFileKeys = !v.prefs.AllowFileKeys
		if err := SavePrefs(v.paths, v.prefs); err != nil {
			v.err = err.Error()
			return v, nil
		}
		if v.prefs.AllowFileKeys {
			v.flash = "allow-file-keys ON — new tokens issued from TUI will recommend --key-type p256"
		} else {
			v.flash = "allow-file-keys OFF — new tokens use the default (SE on macOS with codesign, else ed25519)"
		}
	}
	return v, nil
}

func (v *settingsView) View() string {
	var b strings.Builder
	b.WriteString(titleSt.Render("Settings") + "\n\n")

	// AllowFileKeys toggle.
	state := "OFF"
	stateSt := mutedSt
	if v.prefs.AllowFileKeys {
		state = "ON"
		stateSt = okSt
	}
	b.WriteString("  " + lipgloss.NewStyle().Bold(true).Render("Allow extractable file-backed P-256 agent keys") + "  ")
	b.WriteString(stateSt.Render("["+state+"]") + "  ")
	b.WriteString(helpSt.Render("press f to toggle") + "\n")
	b.WriteString(mutedSt.Render(
		"    When ON, agent keys are stored as PEM files (not Secure Enclave).\n"+
			"    Required to use v1.12 features (add-grant / remove-grant / rotate)\n"+
			"    on hosts where the dop binary can't reach SE — unsigned/Apple-Dev\n"+
			"    macOS builds, or Linux. The key file is readable by any process\n"+
			"    running as this user — only turn ON if you accept that trade.") + "\n")

	if v.flash != "" {
		b.WriteString("\n" + okSt.Render(v.flash) + "\n")
	}
	if v.err != "" {
		b.WriteString("\n" + failSt.Render(v.err) + "\n")
	}
	b.WriteString("\n" + helpSt.Render("f toggle | esc back"))
	return b.String()
}
