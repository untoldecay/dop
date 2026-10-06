// TUI update view — v1.14.0-rc7j. More › Update entry.
//
// Shells out to the existing `dop update` CLI (rc7f) rather than
// reimplementing the GitHub-API + extract + atomic-rename pipeline
// inline. That keeps one code path for all install scenarios (CI,
// terminal, TUI) and inherits the same checksum verification and
// rollback-slot handling.
//
// Flow:
//   1. check phase: run `dop update --check-only` (channel from flag or
//      prefs), parse the stderr for "Latest: <tag>" vs installed.
//   2. confirm phase: operator sees installed → latest, picks y/n, can
//      flip the channel with `c`. `c` also works on the done screen
//      when nothing was installed (already up to date / check failed).
//   3. install phase: run `dop update` (no --check-only), stream
//      stderr. On rc=0, exit TUI so the stale binary doesn't keep
//      running (the renamed file is already in place).

package tui

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/fray/dop/internal/config"
)

type updateStep int

const (
	updateStepChecking   updateStep = 0
	updateStepConfirm    updateStep = 1
	updateStepInstalling updateStep = 2
	updateStepDone       updateStep = 3
)

type updateView struct {
	wiz
	paths   *config.Paths
	step    updateStep
	channel string // "stable" | "dev"

	installed string
	latest    string
	checkErr  string

	cmd     *exec.Cmd
	lineCh  chan string
	linesMu sync.Mutex
	lines   []string

	rc    int
	err   string
	done  bool
	flash string
}

func newUpdateView(paths *config.Paths) *updateView {
	return &updateView{
		paths:   paths,
		step:    updateStepChecking,
		channel: "stable", // operators who want dev set it in-view with `c`
		lineCh:  make(chan string, 32),
	}
}

func (v *updateView) Init() tea.Cmd { return tea.Batch(v.spinStart(), v.runCheck()) }
func (v *updateView) Done() bool    { return v.done }
func (v *updateView) Flash() string { return v.flash }

type updateCheckMsg struct {
	installed string
	latest    string
	err       string
}

type updateLineMsg struct{ line string }
type updateInstallDoneMsg struct {
	rc  int
	err string
}

func (v *updateView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if ok, cmd := v.wizMsg(msg, false); ok {
		return v, cmd
	}
	switch mm := msg.(type) {
	case updateCheckMsg:
		v.installed = mm.installed
		v.latest = mm.latest
		v.checkErr = mm.err
		if mm.err != "" {
			v.step = updateStepDone
			v.rc = 1
			return v, nil
		}
		if mm.installed == mm.latest {
			v.step = updateStepDone
			v.rc = 0
			v.flash = "Already on " + mm.installed + " (" + v.channel + " channel)"
			return v, nil
		}
		v.step = updateStepConfirm
		return v, nil
	case updateLineMsg:
		v.linesMu.Lock()
		v.lines = append(v.lines, mm.line)
		if len(v.lines) > 40 {
			v.lines = v.lines[len(v.lines)-40:]
		}
		v.linesMu.Unlock()
		return v, v.waitForLine()
	case updateInstallDoneMsg:
		v.step = updateStepDone
		v.rc = mm.rc
		v.err = mm.err
		if mm.rc == 0 {
			v.flash = "Updated to " + v.latest + ". Relaunch dop to use it."
		}
		return v, nil
	case tea.KeyMsg:
		switch mm.String() {
		case "esc", "ctrl+c", "q":
			v.done = true
			return v, nil
		}
		if v.step == updateStepDone {
			// Nothing installed (already up to date, or the check
			// failed) → c still flips the channel. Without this, an
			// operator on the latest stable can never reach dev.
			if mm.String() == "c" && v.canFlipFromDone() {
				return v, v.flipChannel()
			}
			v.done = true
			// Successful update means the running binary is stale —
			// exit the TUI so the next `dop` launch gets the new one.
			if v.rc == 0 && v.installed != v.latest && v.latest != "" {
				return v, tea.Quit
			}
			return v, nil
		}
		if v.step == updateStepConfirm {
			switch mm.String() {
			case "y", "enter":
				v.step = updateStepInstalling
				return v, tea.Batch(v.runInstall(), v.waitForLine())
			case "n":
				v.done = true
				v.flash = "Update cancelled"
				return v, nil
			case "c":
				return v, v.flipChannel()
			}
		}
	}
	return v, nil
}

// runCheck shells out `dop update --check-only --channel X` and parses
// the stderr for the "Installed:" and "Latest:" lines.
func (v *updateView) runCheck() tea.Cmd {
	return func() tea.Msg {
		self, err := os.Executable()
		if err != nil {
			return updateCheckMsg{err: err.Error()}
		}
		cmd := exec.Command(self, "update", "--check-only", "--channel", v.channel)
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return updateCheckMsg{err: strings.TrimSpace(stderr.String())}
		}
		installed, latest := parseCheckOutput(stderr.String())
		return updateCheckMsg{installed: installed, latest: latest}
	}
}

// parseCheckOutput — pulls "Installed: X" and "Latest (channel): Y"
// out of `dop update --check-only` stderr.
func parseCheckOutput(s string) (installed, latest string) {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "Installed:"):
			installed = strings.TrimSpace(strings.TrimPrefix(line, "Installed:"))
		case strings.HasPrefix(line, "Latest"):
			// "Latest (dev channel): v1.14.0-rc7i-smoke  (published …)"
			i := strings.Index(line, ":")
			if i < 0 {
				continue
			}
			rest := strings.TrimSpace(line[i+1:])
			// Trim the "(published …)" suffix if present.
			if j := strings.Index(rest, "  ("); j >= 0 {
				rest = rest[:j]
			}
			latest = strings.TrimSpace(rest)
		}
	}
	return
}

// runInstall shells out `dop update --channel X` and streams stderr
// lines to the view through lineCh. On exit, pushes updateInstallDoneMsg.
func (v *updateView) runInstall() tea.Cmd {
	return func() tea.Msg {
		self, err := os.Executable()
		if err != nil {
			return updateInstallDoneMsg{rc: 1, err: err.Error()}
		}
		v.cmd = exec.Command(self, "update", "--channel", v.channel)
		v.cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
		stderr, err := v.cmd.StderrPipe()
		if err != nil {
			return updateInstallDoneMsg{rc: 1, err: err.Error()}
		}
		v.cmd.Stdout = io.Discard
		if err := v.cmd.Start(); err != nil {
			return updateInstallDoneMsg{rc: 1, err: err.Error()}
		}
		go func() {
			sc := bufio.NewScanner(stderr)
			sc.Buffer(make([]byte, 0, 4096), 64*1024)
			for sc.Scan() {
				v.lineCh <- sc.Text()
			}
			err := v.cmd.Wait()
			rc := 0
			msg := ""
			if err != nil {
				rc = 1
				msg = err.Error()
			}
			v.rc = rc
			v.err = msg
			v.lineCh <- "__DONE__"
		}()
		return updateLineMsg{line: fmt.Sprintf("… running: dop update --channel %s", v.channel)}
	}
}

func (v *updateView) waitForLine() tea.Cmd {
	return func() tea.Msg {
		ln, ok := <-v.lineCh
		if !ok || ln == "__DONE__" {
			return updateInstallDoneMsg{rc: v.rc, err: v.err}
		}
		return updateLineMsg{line: ln}
	}
}

var updateKeys = keyMap{
	short: []key.Binding{hint("enter", "install"), keyBack},
	full:  [][]key.Binding{{hint("enter", "install"), hint("c", "channel"), keyBack}},
}

// updateDoneKeys is the keymap of the done screens that installed
// nothing (up to date / check failed): c flips the channel there.
var updateDoneKeys = keyMap{
	short: []key.Binding{hint("enter", "done"), hint("c", "channel")},
	full:  [][]key.Binding{{hint("enter", "done"), hint("c", "channel"), keyBack}},
}

// flipChannel toggles stable ⇄ dev and re-runs the check.
func (v *updateView) flipChannel() tea.Cmd {
	if v.channel == "stable" {
		v.channel = "dev"
	} else {
		v.channel = "stable"
	}
	v.step = updateStepChecking
	v.rc, v.err, v.checkErr, v.flash = 0, "", "", ""
	v.installed, v.latest = "", ""
	return tea.Batch(v.spinStart(), v.runCheck())
}

// canFlipFromDone is true when the done screen was reached without an
// install attempt — up to date, or the check itself failed.
func (v *updateView) canFlipFromDone() bool {
	if v.checkErr != "" {
		return true
	}
	return v.rc == 0 && (v.installed == v.latest || v.latest == "")
}

// otherChannel is where c would switch to.
func (v *updateView) otherChannel() string {
	if v.channel == "stable" {
		return "dev"
	}
	return "stable"
}

func (v *updateView) View() string {
	rows := [][2]string{{"installed", v.installed}, {"latest", v.latest}, {"channel", v.channel}}
	switch v.step {
	case updateStepChecking:
		return v.running("Update", "Checking for the latest release")
	case updateStepConfirm:
		body := append([]string{bodySt.Render("Install " + v.latest + "?"), ""}, strings.Split(strings.TrimRight(kv(rows...), "\n"), "\n")...)
		body = updateKeys.overlay(body, v.width, frameRows(v.height), v.help)
		return frame(v.width, v.height, "Update", nil, "", body, "", updateKeys.footerLine(v.width, v.help))
	case updateStepInstalling:
		body := []string{v.spin.View() + " " + mutedSt.Render("Installing "+v.latest)}
		if v.help {
			v.linesMu.Lock()
			body = append(body, "")
			for _, ln := range v.lines[max(len(v.lines)-10, 0):] {
				body = append(body, "  "+mutedSt.Render(ln))
			}
			v.linesMu.Unlock()
		}
		return frame(v.width, v.height, "Update", nil, "", body, "", "")
	}
	if v.rc == 0 {
		if v.installed == v.latest || v.latest == "" {
			body := strings.Split(strings.TrimRight(kv([2]string{"installed", v.installed}, [2]string{"channel", v.channel}), "\n"), "\n")
			body = updateDoneKeys.overlay(body, v.width, frameRows(v.height), v.help)
			h := "c channel · check the " + v.otherChannel() + " channel"
			return frame(v.width, v.height, "✓ Up to date", nil, "", body, status{hint: h}.String(), updateDoneKeys.footerLine(v.width, v.help))
		}
		return v.doneScreen("Updated to "+v.latest, rows[1:], "Relaunch dop to use the new version.", "")
	}
	reason := displayOr(firstLine(v.checkErr+v.err), "unknown error")
	var body []string
	v.linesMu.Lock()
	for _, ln := range v.lines[max(len(v.lines)-12, 0):] {
		body = append(body, "  "+mutedSt.Render(ln))
	}
	v.linesMu.Unlock()
	if v.canFlipFromDone() {
		// Check failed: the status line carries the error, so the
		// c channel hint goes in the body.
		body = append(body, "", "  "+mutedSt.Render("c channel · check the "+v.otherChannel()+" channel"))
		body = updateDoneKeys.overlay(body, v.width, frameRows(v.height), v.help)
		return frame(v.width, v.height, "! Update failed", nil, "", body, status{err: reason}.String(), updateDoneKeys.footerLine(v.width, v.help))
	}
	return frame(v.width, v.height, "! Update failed", nil, "", body, status{err: reason}.String(), footer(v.width, hint("enter", "done")))
}
