// Small utility views: pull, push, and clipboard helper.

package tui

import (
	"bytes"
	"os"
	"os/exec"
	"runtime"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/fray/dop/internal/config"
)

// syncView runs `dop pull` or `dop push` and displays the output.
type syncView struct {
	action string // "pull" or "push"
	paths  *config.Paths
	out    strings.Builder
	err    string
	done   bool
	flash  string
	ran    bool
}

func newSyncView(action string, paths *config.Paths) *syncView {
	return &syncView{action: action, paths: paths}
}
func (v *syncView) Init() tea.Cmd { return v.run() }
func (v *syncView) Done() bool    { return v.done }
func (v *syncView) Flash() string { return v.flash }

type syncResultMsg struct {
	out string
	err string
}

func (v *syncView) run() tea.Cmd {
	action := v.action
	return func() tea.Msg {
		self, _ := os.Executable()
		cmd := exec.Command(self, action)
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1")
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return syncResultMsg{err: strings.TrimSpace(stderr.String() + stdout.String())}
		}
		return syncResultMsg{out: stderr.String() + stdout.String()}
	}
}
func (v *syncView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch mm := msg.(type) {
	case syncResultMsg:
		v.ran = true
		v.err = mm.err
		v.out.WriteString(mm.out)
		if mm.err == "" {
			v.flash = v.action + " succeeded"
		}
	case tea.KeyMsg:
		if v.ran {
			v.done = true
		}
		_ = mm
	}
	return v, nil
}
func (v *syncView) View() string {
	var b strings.Builder
	if v.action == "pull" {
		b.WriteString(titleSt.Render("Pull") + "\n\n")
	} else {
		b.WriteString(titleSt.Render("Push") + "\n\n")
	}
	if !v.ran {
		b.WriteString("running…")
		return b.String()
	}
	if v.err != "" {
		b.WriteString(failSt.Render("failed") + "\n\n" + v.err)
	} else {
		b.WriteString(okSt.Render("done") + "\n\n" + mutedSt.Render(v.out.String()))
	}
	b.WriteString("\n\n" + helpSt.Render("any key to go back"))
	return b.String()
}

// --- clipboard helper (for bearer display) ---

// copyToClipboard tries pbcopy (macOS), xclip / xsel (Linux). Silent
// no-op on failure — bearer stays on screen either way.
func copyToClipboard(s string) bool {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("pbcopy")
	case "linux":
		if _, err := exec.LookPath("xclip"); err == nil {
			cmd = exec.Command("xclip", "-selection", "clipboard")
		} else if _, err := exec.LookPath("xsel"); err == nil {
			cmd = exec.Command("xsel", "--clipboard", "--input")
		} else {
			return false
		}
	default:
		return false
	}
	cmd.Stdin = strings.NewReader(s)
	return cmd.Run() == nil
}
