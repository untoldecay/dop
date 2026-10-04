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

// Step ordinals. Device flow uses all five; team-member flow skips
// inviteStepIdentity and goes name → passphrase → running → done.
const (
	inviteStepName       = 0
	inviteStepIdentity   = 1 // device only
	inviteStepPassphrase = 2
	inviteStepRunning    = 3
	inviteStepDone       = 4
)

type inviteView struct {
	paths *config.Paths
	kind  inviteKind

	step          int
	nameBuf       strings.Builder
	passBuf       strings.Builder
	err           string
	done          bool
	flash         string
	shareIdentity bool // v1.9.5 — chosen at inviteStepIdentity (device only)

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
		// v1.10.7 — was hard-coded to 3, but that's inviteStepRunning after
		// the identity step landed. Same class of bug as the v1.9.10 join
		// TUI hang. The CLI completes cleanly on shared-identity flows;
		// this was the reason the TUI stayed on "waiting for response…".
		v.step = inviteStepDone
		v.finalRC = mm.rc
		v.finalErr = mm.err
		if mm.rc == 0 {
			v.flash = "invite completed — new admin device added · synced with team"
		}
		return v, nil
	case tea.KeyMsg:
		switch mm.String() {
		case "esc", "ctrl+c":
			if v.step == inviteStepRunning && v.cmd != nil && v.cmd.Process != nil {
				// Kill the subprocess so it doesn't linger polling.
				_ = v.cmd.Process.Kill()
			}
			v.done = true
			return v, nil
		}
		if v.step == inviteStepDone {
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
		case "left", "right", "up", "down", "tab", " ":
			// v1.9.5 — arrow / space / tab toggle at the identity step.
			if v.step == inviteStepIdentity {
				v.shareIdentity = !v.shareIdentity
			}
		default:
			if len(mm.Runes) > 0 && (v.step == inviteStepName || v.step == inviteStepPassphrase) {
				v.currentBuf().WriteString(string(mm.Runes))
			}
		}
	}
	return v, nil
}

func (v *inviteView) currentBuf() *strings.Builder {
	switch v.step {
	case inviteStepName:
		return &v.nameBuf
	case inviteStepPassphrase:
		return &v.passBuf
	}
	return &strings.Builder{}
}

func (v *inviteView) advance() (tea.Model, tea.Cmd) {
	switch v.step {
	case inviteStepName:
		if strings.TrimSpace(v.nameBuf.String()) == "" {
			v.err = "name required"
			return v, nil
		}
		v.err = ""
		if v.kind == inviteKindDevice {
			v.step = inviteStepIdentity
		} else {
			v.step = inviteStepPassphrase
		}
	case inviteStepIdentity:
		v.err = ""
		v.step = inviteStepPassphrase
	case inviteStepPassphrase:
		if strings.TrimSpace(v.passBuf.String()) == "" {
			v.err = "approval passphrase required"
			return v, nil
		}
		v.err = ""
		v.step = inviteStepRunning
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
		args := []string{"team", "invite",
			"--passphrase-stdin",
			"--name", name,
			"--kind", string(v.kind),
		}
		if v.shareIdentity {
			args = append(args, "--share-identity")
		}
		v.cmd = exec.Command(self, args...)
		v.cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
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
			// v1.10.7 — set the final result fields BEFORE pushing the
			// __DONE__ sentinel. Prior order (sentinel first, fields
			// second) racaced waitForLine reading zero values.
			v.finalRC = rc
			v.finalErr = msg
			v.lineCh <- inviteLine{line: "__DONE__"}
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

	// Field 1: label.
	labelStyle := mutedSt
	if v.step == inviteStepName {
		labelStyle = cursorSt
	}
	b.WriteString(labelStyle.Render("Device / member label") + ": ")
	b.WriteString(v.nameBuf.String())
	if v.step == inviteStepName {
		b.WriteString(cursorSt.Render("▎"))
	}
	b.WriteString("\n")

	// Field 2: identity mode (device only).
	if v.kind == inviteKindDevice && v.step >= inviteStepIdentity {
		idStyle := mutedSt
		if v.step == inviteStepIdentity {
			idStyle = cursorSt
		}
		b.WriteString(idStyle.Render("Identity") + ":       " + renderIdentityChoice(v.shareIdentity, v.step == inviteStepIdentity) + "\n")
		if v.shareIdentity {
			b.WriteString("             " + failSt.Render("⚠  losing EITHER device leaks the shared admin identity") + "\n")
		} else {
			b.WriteString("             " + mutedSt.Render("each device has its own admin key — revoke independently") + "\n")
		}
	}

	// Field 3: passphrase.
	if v.step >= inviteStepPassphrase {
		passStyle := mutedSt
		if v.step == inviteStepPassphrase {
			passStyle = cursorSt
		}
		b.WriteString(passStyle.Render("Approval passphrase") + ":   " + strings.Repeat("•", len(v.passBuf.String())))
		if v.step == inviteStepPassphrase {
			b.WriteString(cursorSt.Render("▎"))
		}
		b.WriteString("\n")
	}

	if v.step == inviteStepRunning {
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
	if v.step == inviteStepDone {
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
	case inviteStepIdentity:
		b.WriteString("\n" + helpSt.Render("← → toggle | enter confirm | esc cancel"))
	case inviteStepName, inviteStepPassphrase:
		b.WriteString("\n" + helpSt.Render("enter next | esc cancel"))
	case inviteStepRunning:
		b.WriteString("\n" + helpSt.Render("esc kill invite | (auto-approves when passphrase matches)"))
	case inviteStepDone:
		b.WriteString("\n" + helpSt.Render("any key to return to menu"))
	}
	return b.String()
}

// renderIdentityChoice draws two pill options side-by-side with the
// active one highlighted. The active pill depends on v.shareIdentity;
// when we're on the identity step we also draw a subtle cursor around
// the currently-focused pill so it's obvious what pressing enter locks
// in.
func renderIdentityChoice(share, focused bool) string {
	sepLabel := " ○ separate identity  "
	sharedLabel := "  ● same identity  "
	if !share {
		sepLabel = " ● separate identity  "
		sharedLabel = "  ○ same identity  "
	}
	sepStyle := mutedSt
	sharedStyle := mutedSt
	if !share {
		sepStyle = okSt
		if focused {
			sepStyle = cursorSt
		}
	} else {
		sharedStyle = failSt
		if focused {
			sharedStyle = cursorSt
		}
	}
	return sepStyle.Render(sepLabel) + sharedStyle.Render(sharedLabel)
}
