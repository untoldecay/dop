// TUI wrapper for `dop admin reset`. System > Uninstall (wipe
// local state). Requires typing "UNINSTALL" to confirm.

package tui

import (
	"bytes"
	"os"
	"os/exec"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/fray/dop/internal/config"
)

type resetView struct {
	wiz
	paths *config.Paths

	step    int // 0 = confirm, 1 = running, 2 = done
	confBuf textinput.Model
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
	v := &resetView{paths: paths, confBuf: newFormInput(false)}
	v.confBuf.Placeholder = "UNINSTALL"
	return v
}

func (v *resetView) Init() tea.Cmd { return nil }
func (v *resetView) Done() bool    { return v.done }
func (v *resetView) Flash() string { return v.flash }

func (v *resetView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if ok, cmd := v.wizMsg(msg, true); ok {
		return v, cmd
	}
	switch mm := msg.(type) {
	case resetDone:
		v.rc, v.stdErr = mm.rc, mm.err
		if mm.rc != 0 {
			v.step, v.err = 0, "Uninstall failed: "+displayOr(firstLine(mm.err), "unknown error")
			return v, nil
		}
		v.step = 2
		v.flash = "DOP wiped from this machine — re-install with the one-liner to come back"
		return v, nil
	case tea.KeyMsg:
		switch {
		case v.step == 1:
			return v, nil // subprocess running, ignore keys
		case v.step == 2:
			// the binary backing this process was just unlinked: quit
			// the TUI instead of returning to a setup menu.
			v.done = true
			return v, tea.Quit
		}
		if mm.String() != "enter" {
			v.err = ""
		}
		switch mm.String() {
		case "esc", "ctrl+c":
			v.done = true
		case "enter":
			if strings.TrimSpace(v.confBuf.Value()) != "UNINSTALL" {
				v.err = "Type UNINSTALL in capitals to confirm"
				return v, nil
			}
			v.step = 1
			return v, tea.Batch(v.spinStart(), v.launch())
		default:
			edit(&v.confBuf, mm)
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
		// rc6n — TUI Uninstall → full purge (state + binary). CLI
		// `dop admin reset` without --purge keeps the binary.
		cmd := exec.Command(self, "admin", "uninstall", "--force", "--purge")
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
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
	switch v.step {
	case 1:
		return v.running("Uninstall", "Uninstalling dop")
	case 2:
		return v.doneScreen("dop uninstalled", nil, "Re-install with the one-liner from github.com/untoldecay/dop to come back.", "")
	}
	binPath, _ := os.Executable()
	body := strings.Split(strings.TrimRight(kv([2]string{"removes", midTrunc(v.paths.Root, 66)}, [2]string{"binary", midTrunc(displayOr(binPath, "the dop binary"), 66)}), "\n"), "\n")
	body = append(body, "", mutedSt.Render("  Admin keys, approval hash, vault clone (the remote stays), agent keys,"),
		mutedSt.Render("  caches, pending files, audit log and credential map go away."), "",
		mutedSt.Render("Type UNINSTALL to confirm"), inputRow(&v.confBuf))
	return frame(v.width, v.height, "Uninstall dop?", nil, "", body, status{err: v.err}.String(), confirmFoot("uninstall"))
}
