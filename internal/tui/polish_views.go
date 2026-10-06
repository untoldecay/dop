// Small utility views: pull, push, and clipboard helper.

package tui

import (
	"bytes"
	"github.com/muesli/termenv"
	"os"
	"os/exec"
	"runtime"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/fray/dop/internal/config"
)

// syncView runs `dop pull` or `dop push` and displays the output.
type syncView struct {
	wiz
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
func (v *syncView) Init() tea.Cmd { return tea.Batch(v.spinStart(), v.run()) }
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
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
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
	if ok, cmd := v.wizMsg(msg, false); ok {
		return v, cmd
	}
	switch mm := msg.(type) {
	case syncResultMsg:
		v.ran = true
		v.err = mm.err
		v.out.WriteString(mm.out)
		if mm.err == "" {
			v.flash = "Vault " + v.action + "ed"
		}
	case tea.KeyMsg:
		if v.ran {
			v.done = true
		}
	}
	return v, nil
}
func (v *syncView) View() string {
	verb := map[string]string{"pull": "pulled", "push": "pushed"}[v.action]
	if !v.ran {
		return v.running(strings.ToUpper(v.action[:1])+v.action[1:], map[string]string{"pull": "Pulling", "push": "Pushing"}[v.action]+" the vault")
	}
	text, title, st := vocab(v.out.String()), "✓ Vault "+verb, status{}
	if v.err != "" {
		text, title = vocab(v.err), "! "+strings.ToUpper(v.action[:1])+v.action[1:]+" failed"
		st.setError(firstLine(strings.TrimPrefix(v.err, "! ")))
		if strings.Contains(v.err, "rejected") {
			st.setError("The vault changed on the server. Pull, then retry.")
		}
	}
	var body []string
	for _, l := range strings.Split(strings.TrimSpace(text), "\n") {
		body = append(body, "  "+mutedSt.Render(l))
	}
	return frame(v.width, v.height, title, nil, "", body, st.String(), footer(v.width, hint("enter", "done")))
}

// --- clipboard helper (for bearer display) ---

// clipboardCopy is the seam views call; tests swap it to avoid
// touching the real clipboard.
var clipboardCopy = copyToClipboard

// copyToClipboard copies via OSC 52 (works over SSH and in most modern
// terminals) and also via pbcopy / xclip / xsel when one is installed. Call it
// only from Update, never from View.
func copyToClipboard(s string) bool {
	termenv.NewOutput(os.Stdout).Copy(s)
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("pbcopy")
	case "linux":
		if _, err := exec.LookPath("xclip"); err == nil {
			cmd = exec.Command("xclip", "-selection", "clipboard")
		} else if _, err := exec.LookPath("xsel"); err == nil {
			cmd = exec.Command("xsel", "--clipboard", "--input")
		}
	}
	if cmd != nil {
		cmd.Stdin = strings.NewReader(s)
		_ = cmd.Run()
	}
	return true
}
