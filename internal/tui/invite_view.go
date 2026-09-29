// v1.9.1 — TUI wrapper for `dop team invite`.
//
// Collects the invite label + approval passphrase, spawns the CLI as
// a subprocess with stdin piped (passphrase) and stderr streamed, and
// renders live progress until the flow completes.

package tui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/fray/dop/internal/config"
)

type inviteKind string

const (
	inviteKindDevice     inviteKind = "device"
	inviteKindTeamMember inviteKind = "team_member"
)

type inviteView struct {
	paths *config.Paths
	kind  inviteKind

	step     int // 0 = name, 1 = passphrase, 2 = running, 3 = done
	nameBuf  strings.Builder
	passBuf  strings.Builder
	err      string
	done     bool
	flash    string

	// Runtime state — set once we spawn the subprocess.
	cmd       *exec.Cmd
	lineCh    chan inviteLine // stderr lines, streamed as tea.Msg
	linesMu   sync.Mutex
	lines     []string
	pin       string
	finalErr  string
	finalRC   int
}

type inviteLine struct{ line string }
type inviteDone struct {
	rc  int
	err string
}

func newInviteView(paths *config.Paths, kind inviteKind) *inviteView {
	return &inviteView{paths: paths, kind: kind, lineCh: make(chan inviteLine, 32)}
}

func (v *inviteView) Init() tea.Cmd { return nil }
func (v *inviteView) Done() bool    { return v.done }
func (v *inviteView) Flash() string { return v.flash }

func (v *inviteView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch mm := msg.(type) {
	case inviteLine:
		v.linesMu.Lock()
		v.lines = append(v.lines, mm.line)
		if len(v.lines) > 40 {
			v.lines = v.lines[len(v.lines)-40:]
		}
		v.linesMu.Unlock()
		if p := extractPIN(mm.line); p != "" {
			v.pin = p
		}
		return v, v.waitForLine()
	case inviteDone:
		v.step = 3
		v.finalRC = mm.rc
		v.finalErr = mm.err
		if mm.rc == 0 {
			v.flash = "invite completed — new admin device added"
		}
		return v, nil
	case tea.KeyMsg:
		switch mm.String() {
		case "esc", "ctrl+c":
			if v.step == 2 && v.cmd != nil && v.cmd.Process != nil {
				// Kill the subprocess so it doesn't linger polling.
				_ = v.cmd.Process.Kill()
			}
			v.done = true
			return v, nil
		}
		if v.step == 3 {
			// Any key returns to menu.
			v.done = true
			return v, nil
		}
		switch mm.String() {
		case "enter":
			return v.advance()
		case "backspace":
			buf := v.currentBuf()
			s := buf.String()
			if len(s) > 0 {
				buf.Reset()
				buf.WriteString(s[:len(s)-1])
			}
		default:
			if len(mm.Runes) > 0 && v.step < 2 {
				v.currentBuf().WriteString(string(mm.Runes))
			}
		}
	}
	return v, nil
}

func (v *inviteView) currentBuf() *strings.Builder {
	switch v.step {
	case 0:
		return &v.nameBuf
	case 1:
		return &v.passBuf
	}
	return &strings.Builder{}
}

func (v *inviteView) advance() (tea.Model, tea.Cmd) {
	switch v.step {
	case 0:
		if strings.TrimSpace(v.nameBuf.String()) == "" {
			v.err = "name required"
			return v, nil
		}
		v.err = ""
		v.step = 1
	case 1:
		if strings.TrimSpace(v.passBuf.String()) == "" {
			v.err = "approval passphrase required"
			return v, nil
		}
		v.err = ""
		v.step = 2
		return v, tea.Batch(v.launch(), v.waitForLine())
	}
	return v, nil
}

// launch spawns `dop team invite --passphrase-stdin --name N --kind K`
// with the passphrase piped in.
func (v *inviteView) launch() tea.Cmd {
	return func() tea.Msg {
		self, err := os.Executable()
		if err != nil {
			return inviteDone{rc: 1, err: err.Error()}
		}
		name := strings.TrimSpace(v.nameBuf.String())
		v.cmd = exec.Command(self, "team", "invite",
			"--passphrase-stdin",
			"--name", name,
			"--kind", string(v.kind),
		)
		v.cmd.Env = append(os.Environ(), "DOP_NO_TUI=1")
		stdin, err := v.cmd.StdinPipe()
		if err != nil {
			return inviteDone{rc: 1, err: err.Error()}
		}
		stderr, err := v.cmd.StderrPipe()
		if err != nil {
			return inviteDone{rc: 1, err: err.Error()}
		}
		v.cmd.Stdout = io.Discard
		if err := v.cmd.Start(); err != nil {
			return inviteDone{rc: 1, err: err.Error()}
		}
		// Send passphrase, then close stdin.
		_, _ = stdin.Write([]byte(v.passBuf.String() + "\n"))
		_ = stdin.Close()

		// Reader goroutine — pushes lines onto v.lineCh.
		go func() {
			sc := bufio.NewScanner(stderr)
			sc.Buffer(make([]byte, 0, 4096), 64*1024)
			for sc.Scan() {
				v.lineCh <- inviteLine{line: sc.Text()}
			}
			// Wait for process exit + emit done.
			err := v.cmd.Wait()
			rc := 0
			msg := ""
			if err != nil {
				rc = 1
				msg = err.Error()
			}
			v.lineCh <- inviteLine{line: "__DONE__"}
			// Send the done sentinel via same channel and a marker.
			v.finalRC = rc
			v.finalErr = msg
		}()
		// Return a marker; the tea program will call waitForLine to get
		// each stderr line as a message.
		return inviteLine{line: fmt.Sprintf("… running: %s team invite --name %s --kind %s", filepathBase(self), name, v.kind)}
	}
}

// waitForLine blocks on the line channel and returns a tea.Msg for the
// next arriving line (or the done sentinel).
func (v *inviteView) waitForLine() tea.Cmd {
	return func() tea.Msg {
		ln, ok := <-v.lineCh
		if !ok || ln.line == "__DONE__" {
			return inviteDone{rc: v.finalRC, err: v.finalErr}
		}
		return ln
	}
}

// extractPIN looks for lines like "  PIN:        XX-XX-XX   (valid …)".
var pinLineRe = regexp.MustCompile(`PIN:\s+([A-Z]{2}-[A-Z]{2}-[A-Z]{2})`)

func extractPIN(s string) string {
	m := pinLineRe.FindStringSubmatch(s)
	if len(m) == 2 {
		return m[1]
	}
	return ""
}

func filepathBase(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func (v *inviteView) View() string {
	var b strings.Builder
	titleLabel := "Add a device"
	if v.kind == inviteKindTeamMember {
		titleLabel = "Invite team member"
	}
	b.WriteString(titleSt.Render(titleLabel) + "\n\n")

	labels := []string{"Device / member label", "Approval passphrase"}
	for i, l := range labels {
		if i > v.step && v.step < 2 {
			break
		}
		style := mutedSt
		if i == v.step {
			style = cursorSt
		}
		b.WriteString(style.Render(l) + ": ")
		if v.step >= 2 && i < 2 {
			if i == 0 {
				b.WriteString(v.nameBuf.String())
			} else {
				b.WriteString(strings.Repeat("•", len(v.passBuf.String())))
			}
			b.WriteString("\n")
			continue
		}
		if i == v.step {
			if i == 1 {
				b.WriteString(strings.Repeat("•", len(v.passBuf.String())))
			} else {
				b.WriteString(v.nameBuf.String())
			}
			b.WriteString(cursorSt.Render("▎"))
		} else {
			if i == 0 {
				b.WriteString(v.nameBuf.String())
			}
		}
		b.WriteString("\n")
	}

	if v.step == 2 {
		b.WriteString("\n")
		if v.pin != "" {
			b.WriteString("  PIN: " + lipgloss.NewStyle().Bold(true).Render(v.pin) + "\n")
			b.WriteString(mutedSt.Render("  Hand this PIN + your vault URL to the new machine.\n"))
			b.WriteString(mutedSt.Render("  On that machine: `dop admin join <VAULT-URL> "+v.pin+"`\n"))
		} else {
			b.WriteString(mutedSt.Render("  Waiting for invite to open…\n"))
		}
		b.WriteString("\n")
		b.WriteString(mutedSt.Render("Live output (tail):") + "\n")
		v.linesMu.Lock()
		start := 0
		if len(v.lines) > 8 {
			start = len(v.lines) - 8
		}
		for _, ln := range v.lines[start:] {
			b.WriteString("  " + mutedSt.Render(ln) + "\n")
		}
		v.linesMu.Unlock()
	}
	if v.step == 3 {
		b.WriteString("\n")
		if v.finalRC == 0 {
			b.WriteString(okSt.Render("✓ invite completed successfully") + "\n")
		} else {
			b.WriteString(failSt.Render("✗ invite failed: "+v.finalErr) + "\n")
		}
	}
	if v.err != "" {
		b.WriteString("\n" + failSt.Render(v.err) + "\n")
	}

	switch v.step {
	case 0, 1:
		b.WriteString("\n" + helpSt.Render("enter next · esc cancel"))
	case 2:
		b.WriteString("\n" + helpSt.Render("esc kill invite · (auto-approves when passphrase matches)"))
	case 3:
		b.WriteString("\n" + helpSt.Render("any key to return to menu"))
	}
	return b.String()
}
