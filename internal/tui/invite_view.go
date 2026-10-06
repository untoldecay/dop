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

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/fray/dop/internal/config"
)

type inviteKind string

const (
	inviteKindDevice     inviteKind = "device"
	inviteKindTeamMember inviteKind = "team_member"
)

// Step ordinals. Device flow: name → identity → passphrase → review;
// team member skips identity. Then running → waiting (invite staged,
// the teammate joins later; enter closes, esc cancels the invite).
const (
	inviteStepName          = 0
	inviteStepIdentity      = 1 // device only
	inviteStepPassphrase    = 2
	inviteStepRunning       = 3
	inviteStepWaiting       = 4 // invite staged, waiting on teammate (fire-and-forget)
	inviteStepReview        = 5
	inviteStepCancelConfirm = 6 // "cancel this invite?"
)

// identityOpts is the device identity picker (invite and join).
var identityOpts = [][2]string{
	{"separate", "own admin key per device, revoke independently (default)"},
	{"same", "share one admin identity; losing either device leaks it"},
}

type inviteView struct {
	wiz
	paths *config.Paths
	kind  inviteKind

	step          int
	nameBuf       textinput.Model
	passBuf       textinput.Model
	err           string
	done          bool
	flash         string
	shareIdentity bool // chosen at inviteStepIdentity (device only)
	identityCur   int
	cancelling    bool // the running screen is the cancel subprocess

	// Runtime state — set once we spawn the subprocess.
	cmd      *exec.Cmd
	lineCh   chan inviteLine // stderr lines, streamed as tea.Msg
	linesMu  sync.Mutex
	lines    []string
	pin      string
	inviteID string // captured from subprocess stderr so esc can cancel
	vaultURL string // captured from subprocess stderr for the waiting screen
	finalErr string
	finalRC  int
}

type inviteLine struct{ line string }
type inviteDone struct {
	rc  int
	err string
}

func newInviteView(paths *config.Paths, kind inviteKind) *inviteView {
	v := &inviteView{paths: paths, kind: kind, lineCh: make(chan inviteLine, 32),
		nameBuf: newFormInput(false), passBuf: newFormInput(true)}
	v.nameBuf.Placeholder = map[inviteKind]string{inviteKindDevice: "mac-mini", inviteKindTeamMember: "alex"}[kind]
	return v
}

func (v *inviteView) Init() tea.Cmd { return nil }
func (v *inviteView) Done() bool    { return v.done }
func (v *inviteView) Flash() string { return v.flash }

// flow is the question steps of this invite kind.
func (v *inviteView) flow() []int {
	if v.kind == inviteKindDevice {
		return []int{inviteStepName, inviteStepIdentity, inviteStepPassphrase}
	}
	return []int{inviteStepName, inviteStepPassphrase}
}

func (v *inviteView) curBuf() *textinput.Model {
	return map[int]*textinput.Model{inviteStepName: &v.nameBuf, inviteStepPassphrase: &v.passBuf}[v.step]
}

func (v *inviteView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	in := v.curBuf()
	if ok, cmd := v.wizMsg(msg, in != nil && in.Value() != ""); ok {
		return v, cmd
	}
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
		if id := extractInviteID(mm.line); id != "" {
			v.inviteID = id
		}
		if u := extractVaultURL(mm.line); u != "" {
			v.vaultURL = u
		}
		return v, v.waitForLine()
	case inviteDone:
		v.finalRC, v.finalErr = mm.rc, mm.err
		if mm.rc == 0 {
			// the subprocess exits once the invite is staged + pushed.
			v.step = inviteStepWaiting
			return v, nil
		}
		v.step, v.err = inviteStepReview, "Invite failed: "+v.lastLine()
		return v, nil
	case teamCancelDoneMsg:
		if mm.err != "" {
			v.err = "Cancel failed: " + firstLine(mm.err)
			v.step, v.cancelling = inviteStepWaiting, false
			return v, nil
		}
		v.flash = "invite cancelled"
		v.done = true
		return v, nil
	case tea.KeyMsg:
		k := mm.String()
		if k != "enter" {
			v.err = ""
		}
		switch v.step {
		case inviteStepWaiting:
			switch k {
			case "enter":
				v.flash = "invite open · teammate can join with: dop admin join <URL> " + v.pin
				v.done = true
			case "esc", "ctrl+c":
				v.step = inviteStepCancelConfirm
			}
			return v, nil
		case inviteStepCancelConfirm:
			switch k {
			case "y", "enter":
				if cmd := v.locked(mm, &v.err); cmd != nil {
					return v, cmd
				}
				v.step, v.cancelling = inviteStepRunning, true
				return v, tea.Batch(v.spinStart(), v.cancelInvite(v.inviteID))
			case "n", "esc":
				v.step = inviteStepWaiting
			}
			return v, nil
		case inviteStepRunning:
			if k == "esc" || k == "ctrl+c" {
				if v.cmd != nil && v.cmd.Process != nil {
					_ = v.cmd.Process.Kill() // pre-stage: don't let it linger
				}
				v.done = true
			}
			return v, nil
		}
		fl := v.flow()
		i := stepPos(fl, v.step)
		switch k {
		case "ctrl+c":
			v.done = true
		case "enter":
			return v.advance()
		case "esc", "shift+tab":
			if wizBack(mm, &i) < 0 {
				v.done = true
			} else {
				v.step = fl[i]
			}
		case "up", "down":
			if v.step == inviteStepIdentity {
				stepCursor(&v.identityCur, 2, map[string]int{"up": -1, "down": 1}[k])
			}
		default:
			if in != nil {
				edit(in, mm)
			}
		}
	}
	return v, nil
}

func (v *inviteView) advance() (tea.Model, tea.Cmd) {
	switch v.step {
	case inviteStepName:
		if strings.TrimSpace(v.nameBuf.Value()) == "" {
			v.err = "Label is required"
			return v, nil
		}
	case inviteStepIdentity:
		v.shareIdentity = v.identityCur == 1
	case inviteStepPassphrase:
		if strings.TrimSpace(v.passBuf.Value()) == "" {
			v.err = "Approval passphrase is required"
			return v, nil
		}
	case inviteStepReview:
		if cmd := v.locked(tea.KeyMsg{Type: tea.KeyEnter}, &v.err); cmd != nil {
			return v, cmd
		}
		v.err, v.step = "", inviteStepRunning
		v.lines = nil
		return v, tea.Batch(v.spinStart(), v.launch(), v.waitForLine())
	}
	v.err = ""
	fl := v.flow()
	if i := stepPos(fl, v.step) + 1; i < len(fl) {
		v.step = fl[i]
	} else {
		v.step = inviteStepReview
	}
	return v, nil
}

// lastLine is the last non-empty subprocess line (or the exit error).
func (v *inviteView) lastLine() string {
	v.linesMu.Lock()
	defer v.linesMu.Unlock()
	return lastOutput(v.lines, v.finalErr)
}

// lastOutput is the last non-empty line of out, else fallback.
func lastOutput(out []string, fallback string) string {
	for i := len(out) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(out[i]), "error:")); l != "" {
			return l
		}
	}
	return fallback
}

// launch spawns `dop team invite --passphrase-stdin --name N --kind K`
// with the passphrase piped in.
func (v *inviteView) launch() tea.Cmd {
	return func() tea.Msg {
		self, err := os.Executable()
		if err != nil {
			return inviteDone{rc: 1, err: err.Error()}
		}
		name := strings.TrimSpace(v.nameBuf.Value())
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
		_, _ = stdin.Write([]byte(v.passBuf.Value() + "\n"))
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

// extractInviteID looks for lines like "  invite_id:  <hex>".
// rc7o — the CLI prints this so the TUI can cancel the right invite.
var inviteIDLineRe = regexp.MustCompile(`invite_id:\s+([a-f0-9]{8,})`)

func extractInviteID(s string) string {
	m := inviteIDLineRe.FindStringSubmatch(s)
	if len(m) == 2 {
		return m[1]
	}
	return ""
}

// extractVaultURL grabs the `  vault URL:  <url>` line.
var vaultURLLineRe = regexp.MustCompile(`vault URL:\s+(\S+)`)

func extractVaultURL(s string) string {
	m := vaultURLLineRe.FindStringSubmatch(s)
	if len(m) == 2 && !strings.HasPrefix(m[1], "(") {
		return m[1]
	}
	return ""
}

// cancelInvite shells out to `dop team cancel-invite <id>` and returns
// a teamCancelDoneMsg. Shared with the Team view's cancel action; the
// message type lives in team_views.go.
func (v *inviteView) cancelInvite(id string) tea.Cmd {
	return func() tea.Msg {
		self, err := os.Executable()
		if err != nil {
			return teamCancelDoneMsg{id: id, err: err.Error()}
		}
		cmd := exec.Command(self, "team", "cancel-invite", id)
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
		var stderr strings.Builder
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return teamCancelDoneMsg{id: id, err: strings.TrimSpace(stderr.String())}
		}
		return teamCancelDoneMsg{id: id}
	}
}

func filepathBase(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// outputTail is the last n subprocess lines, muted, for the ? help of
// running and failed screens.
func outputTail(mu *sync.Mutex, lines []string, n int) []string {
	mu.Lock()
	defer mu.Unlock()
	var out []string
	for _, l := range lines[max(len(lines)-n, 0):] {
		out = append(out, mutedSt.Render("  "+l))
	}
	return out
}

func (v *inviteView) View() string {
	title, what := "Invite device", "device"
	if v.kind == inviteKindTeamMember {
		title, what = "Invite team member", "team member"
	}
	label := strings.TrimSpace(v.nameBuf.Value())
	switch v.step {
	case inviteStepRunning:
		if v.help {
			body := append([]string{mutedSt.Render("Last output")}, outputTail(&v.linesMu, v.lines, 10)...)
			return frame(v.width, v.height, title, nil, "", body, "", footer(v.width, keyClose))
		}
		line := "Staging the invite for " + label
		if v.cancelling {
			line = "Cancelling the invite for " + label
		}
		return frame(v.width, v.height, title, nil, "", []string{v.spin.View() + " " + mutedSt.Render(line)}, "",
			footer(v.width, hint("esc", "cancel"), keyMore))
	case inviteStepWaiting:
		url := displayOr(v.vaultURL, "<vault URL>")
		rows := [][2]string{{what, label}, {"PIN", v.pin}, {"they run", "dop admin join " + url + " " + v.pin}}
		note := "Approve later from List > Team > Pending."
		if v.shareIdentity {
			note = "Shared identity: the join completes without your approval."
		}
		body := append(strings.Split(strings.TrimRight(kv(rows...), "\n"), "\n"), "", mutedSt.Render("  "+note))
		st := status{err: v.err, hint: "invite " + safeShortID(v.inviteID) + " · " + url}
		return frame(v.width, v.height, "✓ Invite staged", nil, "", body, st.String(),
			footer(v.width, hint("enter", "done"), keyCancel))
	case inviteStepCancelConfirm:
		body := []string{mutedSt.Render("  The pending invite is removed from the vault and pushed;"),
			mutedSt.Render("  their dop admin join then fails with invite not found.")}
		foot := bodySt.Render("enter") + " " + dangerSt.Render("cancel invite") + mutedSt.Render(" · ") + bodySt.Render("esc") + mutedSt.Render(" keep it")
		return frame(v.width, v.height, "Cancel the invite for "+label+"?", nil, "", body, "", foot)
	case inviteStepReview:
		rows := [][2]string{{what, label}}
		if v.kind == inviteKindDevice {
			rows = append(rows, [2]string{"identity", identityOpts[v.identityCur][0]})
		}
		rows = append(rows, [2]string{"passphrase", strings.Repeat("•", len(v.passBuf.Value()))})
		if v.help && v.err != "" {
			body := append([]string{mutedSt.Render("Last output")}, outputTail(&v.linesMu, v.lines, 10)...)
			return frame(v.width, v.height, title, nil, "review", body, status{err: v.err}.String(), footer(v.width, keyClose))
		}
		return v.review(title, "Invite this "+what+"?", rows, "invite", false, v.err)
	}
	fl := v.flow()
	var prompt, helper string
	var input []string
	switch v.step {
	case inviteStepName:
		prompt, helper = "Label for the new "+what, "Shown in List > Team."
		input = []string{inputRow(&v.nameBuf)}
	case inviteStepIdentity:
		prompt = "Identity of " + label
		input = optRows(identityOpts, v.identityCur)
	case inviteStepPassphrase:
		prompt, helper = "Your approval passphrase", "Signs the invite."
		input = []string{inputRow(&v.passBuf)}
	}
	return v.screen(title, counter(stepPos(fl, v.step), len(fl)), prompt, input, helper, v.err, "", wizKeys("next"))
}

// safeShortID returns the 8-char prefix of id, or a placeholder when
// id is empty (extractInviteID didn't match).
func safeShortID(id string) string {
	if len(id) >= 8 {
		return id[:8]
	}
	return "<id>"
}
