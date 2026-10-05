// Settings view — one-screen TUI toggle for the small set of operator
// prefs we track in tui-prefs.yaml. Right now the only toggle is
// AllowFileKeys (v1.12 direct-availability unlocker on hosts where
// the Secure Enclave isn't reachable).

package tui

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/userprefs"
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
			v.flash = "allow-file-keys ON — new TUI tokens will recommend --key-type p256"
		} else {
			v.flash = "allow-file-keys OFF — new tokens use the default (SE on signed macOS, else ed25519)"
		}
	case "t":
		// Cycle the approval-popup timeout through the supported choices.
		current := v.prefs.ApprovalPopupTimeoutSeconds
		if current == 0 {
			current = userprefs.ApprovalTimeoutDefaultSeconds
		}
		next := userprefs.CycleApprovalTimeout(current)
		v.prefs.ApprovalPopupTimeoutSeconds = next
		if err := SavePrefs(v.paths, v.prefs); err != nil {
			v.err = err.Error()
			return v, nil
		}
		v.flash = fmt.Sprintf("approval popup timeout → %ds", next)
	case "h":
		// rc7i — cycle the harness pref. The resolver reads this via
		// DOP_HARNESS so trust-context cache hits land on whichever
		// session id env var the operator's harness exposes.
		next := userprefs.CycleHarness(v.prefs.Harness)
		v.prefs.Harness = next
		if err := SavePrefs(v.paths, v.prefs); err != nil {
			v.err = err.Error()
			return v, nil
		}
		v.flash = "harness → " + userprefs.HarnessLabel(next)
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

	// rc5b — approval popup timeout cycler.
	timeoutSecs := v.prefs.ApprovalPopupTimeoutSeconds
	if timeoutSecs == 0 {
		timeoutSecs = userprefs.ApprovalTimeoutDefaultSeconds
	}
	b.WriteString("\n")
	b.WriteString("  " + lipgloss.NewStyle().Bold(true).Render("Approval popup timeout") + "  ")
	b.WriteString(okSt.Render(fmt.Sprintf("[%ds]", timeoutSecs)) + "  ")
	b.WriteString(helpSt.Render("press t to cycle (15 → 30 → 60)") + "\n")
	b.WriteString(mutedSt.Render(
		"    How long the native popup waits for your approval passphrase\n"+
			"    before the flow upgrades to tunnel+phone fallback. Shorter is\n"+
			"    faster-to-escalate for remote admins; longer gives you more\n"+
			"    room when you're at the mac.") + "\n")

	// rc7i — harness cycler.
	harness := v.prefs.Harness
	harnessLabel := userprefs.HarnessLabel(harness)
	harnessState := okSt
	if harness == "" {
		harnessState = mutedSt
	}
	b.WriteString("\n")
	b.WriteString("  " + lipgloss.NewStyle().Bold(true).Render("Harness") + "  ")
	b.WriteString(harnessState.Render("["+harnessLabel+"]") + "  ")
	b.WriteString(helpSt.Render("press h to cycle (Claude Code → Codex → opencode → manual → any → none)") + "\n")
	b.WriteString(mutedSt.Render(
		"    Tells DOP which session id env var your AI harness exposes so\n"+
			"    `dop use` only pops the approval dialog once per conversation.\n"+
			"    Claude Code: CLAUDE_CODE_SESSION_ID · Codex CLI: CODEX_THREAD_ID\n"+
			"    opencode: OPENCODE_SESSION_ID · manual: you export DOP_SESSION_ID\n"+
			"    yourself (Cursor / Zed / aider / custom shells). `any` tries all\n"+
			"    three recognized adapters; `none` skips the harness branch.") + "\n")

	if v.flash != "" {
		b.WriteString("\n" + okSt.Render(v.flash) + "\n")
	}
	if v.err != "" {
		b.WriteString("\n" + failSt.Render(v.err) + "\n")
	}
	b.WriteString("\n" + helpSt.Render("f file-keys · t timeout · h harness · esc back"))
	return b.String()
}
