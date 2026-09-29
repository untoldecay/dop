// v1.9.2 — TUI wrapper for `dop admin reset`. System > Reset (wipe
// local state). Requires typing "RESET" to confirm.

package tui

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/charmbracelet/lipgloss"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/fray/dop/internal/config"
)

type resetView struct {
	paths *config.Paths

	step    int // 0 = confirm, 1 = running, 2 = done
	confBuf strings.Builder
	err     string
	done    bool
	flash   string
	rc      int
	stdErr  string
}

type resetDone struct {
	rc  int
	err string
}

func newResetView(paths *config.Paths) *resetView {
	return &resetView{paths: paths}
}

func (v *resetView) Init() tea.Cmd { return nil }
func (v *resetView) Done() bool    { return v.done }
func (v *resetView) Flash() string { return v.flash }

func (v *resetView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch mm := msg.(type) {
	case resetDone:
		v.step = 2
		v.rc = mm.rc
		v.stdErr = mm.err
		if mm.rc == 0 {
			v.flash = "local DOP state wiped — use `dop admin init` or `dop admin join` to start over"
		}
		return v, nil
	case tea.KeyMsg:
		switch mm.String() {
		case "esc", "ctrl+c":
			v.done = true
			return v, nil
		}
		if v.step == 2 {
			v.done = true
			return v, nil
		}
		if v.step == 1 {
			return v, nil // subprocess running, ignore keys
		}
		switch mm.String() {
		case "enter":
			if strings.TrimSpace(v.confBuf.String()) != "RESET" {
				v.err = "must type RESET (all caps) to confirm"
				return v, nil
			}
			v.err = ""
			v.step = 1
			return v, v.launch()
		case "backspace":
			s := v.confBuf.String()
			if len(s) > 0 {
				v.confBuf.Reset()
				v.confBuf.WriteString(s[:len(s)-1])
			}
		default:
			if len(mm.Runes) > 0 {
				v.confBuf.WriteString(string(mm.Runes))
			}
		}
	}
	return v, nil
}

func (v *resetView) launch() tea.Cmd {
	return func() tea.Msg {
		self, err := os.Executable()
		if err != nil {
			return resetDone{rc: 1, err: err.Error()}
		}
		cmd := exec.Command(self, "admin", "reset", "--force")
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		err = cmd.Run()
		rc := 0
		if err != nil {
			rc = 1
		}
		return resetDone{rc: rc, err: strings.TrimSpace(stderr.String())}
	}
}

func (v *resetView) View() string {
	var b strings.Builder
	b.WriteString(titleSt.Render("Reset — wipe local DOP state") + "\n\n")

	warn := lipgloss.NewStyle().Foreground(danger).Bold(true)
	b.WriteString(warn.Render("⚠  This is destructive.") + "\n\n")
	b.WriteString("Will delete everything under:\n")
	b.WriteString("  " + mutedSt.Render(v.paths.Root) + "\n\n")

	b.WriteString(mutedSt.Render("Contents that go away:") + "\n")
	items := []string{
		"wrapped admin keys (admin.age.enc)",
		"approval passphrase hash",
		"vault clone (safe — encrypted at rest, remains on GitHub)",
		"agent private keys",
		"generation cache, pending PIN / remote / invite files",
		"this machine's audit log",
		"credential-map.yaml",
	}
	for _, it := range items {
		b.WriteString("  · " + mutedSt.Render(it) + "\n")
	}
	b.WriteString("\n")
	b.WriteString(mutedSt.Render("The dop binary itself is NOT removed.") + "\n\n")

	if v.step == 0 {
		b.WriteString(cursorSt.Render("Type RESET (all caps) to confirm") + ": ")
		b.WriteString(v.confBuf.String())
		b.WriteString(cursorSt.Render("▎") + "\n")
		if v.err != "" {
			b.WriteString("\n" + failSt.Render(v.err) + "\n")
		}
		b.WriteString("\n" + helpSt.Render("enter confirm · esc cancel"))
	}
	if v.step == 1 {
		b.WriteString(mutedSt.Render("wiping…") + "\n")
	}
	if v.step == 2 {
		b.WriteString("\n")
		if v.rc == 0 {
			b.WriteString(okSt.Render("✓ done — this machine is clean.") + "\n")
			b.WriteString(mutedSt.Render("  the TUI will exit; run `dop admin init` or `dop admin join` to start over.") + "\n")
		} else {
			b.WriteString(failSt.Render("✗ reset failed:") + "\n")
			b.WriteString(mutedSt.Render("  "+v.stdErr) + "\n")
		}
		b.WriteString("\n" + helpSt.Render("any key to exit"))
	}
	fmt.Fprintln(&b)
	return b.String()
}
