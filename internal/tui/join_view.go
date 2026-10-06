// v1.9.1 — TUI wrapper for `dop admin join`. Shown in the pre-ready
// menu when this machine has no admin key yet (or has one but wants
// to attach to an invited vault).
//
// Collects vault URL + PIN + passphrases, spawns the CLI subprocess
// with stdin piped and stderr streamed, renders progress until done.

package tui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/userprefs"
)

// Join steps. Identity is only asked on a fresh install: with a key on
// disk the local key is unwrapped, so the choice is moot.
const (
	joinStepURL         = 0
	joinStepPIN         = 1
	joinStepIdentity    = 2 // fresh-install only
	joinStepAdminPass   = 3 // keyExists (unwrap) or shared identity (inviting machine's)
	joinStepNewAdmin    = 4 // separate-identity fresh install
	joinStepNewApproval = 5 // separate-identity fresh install
	joinStepRunning     = 6
	joinStepHarness     = 7 // first-start harness picker on a successful join
	joinStepReview      = 8
)

type joinView struct {
	wiz
	paths *config.Paths

	// Whether this machine already has an admin key. Determines if we
	// need to also collect the *new* admin+approval passphrases.
	keyExists     bool
	shareIdentity bool // chosen at joinStepIdentity, only for fresh install
	identityCur   int

	step          int
	urlBuf        textinput.Model
	pinBuf        textinput.Model
	adminPass     textinput.Model
	newAdmin1     textinput.Model // fresh + separate identity: admin passphrase
	newApproval   textinput.Model // fresh + separate identity: approval passphrase
	harnessCursor int             // cursor into userprefs.HarnessChoices
	err           string
	done          bool
	flash         string

	cmd      *exec.Cmd
	lineCh   chan inviteLine
	linesMu  sync.Mutex
	lines    []string
	finalRC  int
	finalErr string
}

func newJoinView(paths *config.Paths) *joinView {
	v := &joinView{paths: paths, lineCh: make(chan inviteLine, 32), urlBuf: newFormInput(false), pinBuf: newFormInput(false),
		adminPass: newFormInput(true), newAdmin1: newFormInput(true), newApproval: newFormInput(true)}
	v.urlBuf.Placeholder, v.pinBuf.Placeholder = "git@github.com:you/dop-vault.git", "AB-CD-EF"
	v.keyExists = admin.KeyFileExists(paths)
	return v
}

func (v *joinView) Init() tea.Cmd { return nil }
func (v *joinView) Done() bool    { return v.done }
func (v *joinView) Flash() string { return v.flash }

// flow is the question steps the answers lead through.
func (v *joinView) flow() []int {
	s := []int{joinStepURL, joinStepPIN}
	switch {
	case v.keyExists:
		return append(s, joinStepAdminPass)
	case v.shareIdentity:
		return append(s, joinStepIdentity, joinStepAdminPass)
	}
	return append(s, joinStepIdentity, joinStepNewAdmin, joinStepNewApproval)
}

func (v *joinView) curBuf() *textinput.Model {
	return map[int]*textinput.Model{joinStepURL: &v.urlBuf, joinStepPIN: &v.pinBuf, joinStepAdminPass: &v.adminPass,
		joinStepNewAdmin: &v.newAdmin1, joinStepNewApproval: &v.newApproval}[v.step]
}

func (v *joinView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
		return v, v.waitForLine()
	case inviteDone:
		v.finalRC, v.finalErr = mm.rc, mm.err
		if mm.rc == 0 {
			v.step = joinStepHarness // first-start harness pick, as after setup
			return v, nil
		}
		v.linesMu.Lock()
		v.err = "Join failed: " + lastOutput(v.lines, v.finalErr)
		v.linesMu.Unlock()
		v.step = joinStepReview
		return v, nil
	case tea.KeyMsg:
		k := mm.String()
		if k != "enter" {
			v.err = ""
		}
		switch v.step {
		case joinStepRunning:
			if k == "esc" || k == "ctrl+c" {
				if v.cmd != nil && v.cmd.Process != nil {
					_ = v.cmd.Process.Kill()
				}
				v.done = true
			}
			return v, nil
		case joinStepHarness:
			if k == "esc" || k == "ctrl+c" {
				v.flash = "joined · harness not set (Settings > Harness)"
				v.done = true
				return v, nil
			}
			return v.updateHarnessStep(mm)
		case joinStepReview:
			switch k {
			case "enter":
				v.step, v.lines = joinStepRunning, nil
				return v, tea.Batch(v.spinStart(), v.launch(), v.waitForLine())
			case "esc", "shift+tab":
				fl := v.flow()
				v.step = fl[len(fl)-1]
			case "ctrl+c":
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
			if v.step == joinStepIdentity {
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

// updateHarnessStep mirrors setupAdminView's picker.
func (v *joinView) updateHarnessStep(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch mm.String() {
	case "up", "down":
		stepCursor(&v.harnessCursor, len(userprefs.HarnessChoices), map[string]int{"up": -1, "down": 1}[mm.String()])
	case "enter":
		pick := userprefs.HarnessChoices[v.harnessCursor]
		prefs := userprefs.Load(v.paths)
		prefs.Harness = pick
		if err := userprefs.Save(v.paths, prefs); err != nil {
			v.err = "Save prefs: " + err.Error()
			return v, nil
		}
		v.flash = "joined · harness set to " + userprefs.HarnessLabel(pick)
		v.done = true
	}
	return v, nil
}

func (v *joinView) advance() (tea.Model, tea.Cmd) {
	need := func(t *textinput.Model, what string, n int) bool {
		switch {
		case strings.TrimSpace(t.Value()) == "":
			v.err = what + " is required"
		case len(t.Value()) < n:
			v.err = fmt.Sprintf("%s must be at least %d characters", what, n)
		default:
			return true
		}
		return false
	}
	switch v.step {
	case joinStepURL:
		if !need(&v.urlBuf, "Vault URL", 0) {
			return v, nil
		}
	case joinStepPIN:
		if !need(&v.pinBuf, "PIN", 0) {
			return v, nil
		}
	case joinStepIdentity:
		v.shareIdentity = v.identityCur == 1
	case joinStepAdminPass:
		if !need(&v.adminPass, "Passphrase", 0) {
			return v, nil
		}
	case joinStepNewAdmin:
		if !need(&v.newAdmin1, "Admin passphrase", 8) {
			return v, nil
		}
	case joinStepNewApproval:
		if !need(&v.newApproval, "Approval passphrase", 10) {
			return v, nil
		}
	}
	v.err = ""
	fl := v.flow()
	if i := stepPos(fl, v.step) + 1; i < len(fl) {
		v.step = fl[i]
	} else {
		v.step = joinStepReview
	}
	return v, nil
}

func (v *joinView) launch() tea.Cmd {
	return func() tea.Msg {
		self, err := os.Executable()
		if err != nil {
			return inviteDone{rc: 1, err: err.Error()}
		}
		v.cmd = exec.Command(self, "admin", "join",
			"--passphrase-stdin",
			strings.TrimSpace(v.urlBuf.Value()),
			strings.TrimSpace(v.pinBuf.Value()),
		)
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
		// Feed passphrases into stdin.
		//   - keyExists                  : one line — unwrap the local key.
		//   - fresh + shareIdentity=true : one line — confirm M1's admin pass.
		//   - fresh + shareIdentity=false: two lines — new admin, new approval.
		var lines []string
		switch {
		case v.keyExists:
			lines = []string{v.adminPass.Value()}
		case v.shareIdentity:
			lines = []string{v.adminPass.Value()}
		default:
			lines = []string{v.newAdmin1.Value(), v.newApproval.Value()}
		}
		for _, ln := range lines {
			_, _ = stdin.Write([]byte(ln + "\n"))
		}
		_ = stdin.Close()

		go func() {
			sc := bufio.NewScanner(stderr)
			sc.Buffer(make([]byte, 0, 4096), 64*1024)
			for sc.Scan() {
				v.lineCh <- inviteLine{line: sc.Text()}
			}
			err := v.cmd.Wait()
			rc := 0
			msg := ""
			if err != nil {
				rc = 1
				msg = err.Error()
			}
			v.finalRC = rc
			v.finalErr = msg
			v.lineCh <- inviteLine{line: "__DONE__"}
		}()
		return inviteLine{line: "… running: dop admin join"}
	}
}

func (v *joinView) waitForLine() tea.Cmd {
	return func() tea.Msg {
		ln, ok := <-v.lineCh
		if !ok || ln.line == "__DONE__" {
			return inviteDone{rc: v.finalRC, err: v.finalErr}
		}
		return ln
	}
}

// harnessScreen is the first-start harness picker shown after setup
// and join: the ✓ outcome as title, the question, one row per harness.
func harnessScreen(w wiz, title string, cur int, err string) string {
	var opts [][2]string
	for _, c := range userprefs.HarnessChoices {
		opts = append(opts, [2]string{userprefs.HarnessLabel(c), ""})
	}
	body := append([]string{mutedSt.Render("Which AI harness do you use most?")}, optRows(opts, cur)...)
	body = append(body, "", mutedSt.Render("It picks the session variable the approval cache reads."))
	return frame(w.width, w.height, "✓ "+title, nil, "", body, status{err: err}.String(),
		footer(w.width, hint("enter", "save"), keyBack))
}

func (v *joinView) View() string {
	const title = "Join vault"
	url := strings.TrimSpace(v.urlBuf.Value())
	switch v.step {
	case joinStepRunning:
		if v.help {
			body := append([]string{mutedSt.Render("Last output")}, outputTail(&v.linesMu, v.lines, 10)...)
			return frame(v.width, v.height, title, nil, "", body, "", footer(v.width, keyClose))
		}
		return frame(v.width, v.height, title, nil, "", []string{v.spin.View() + " " + mutedSt.Render("Joining "+url+", waiting for the inviting admin")},
			"", footer(v.width, hint("esc", "cancel"), keyMore))
	case joinStepHarness:
		return harnessScreen(v.wiz, "Joined", v.harnessCursor, v.err)
	case joinStepReview:
		if v.help && v.err != "" {
			body := append([]string{mutedSt.Render("Last output")}, outputTail(&v.linesMu, v.lines, 10)...)
			return frame(v.width, v.height, title, nil, "review", body, status{err: v.err}.String(), footer(v.width, keyClose))
		}
		rows := [][2]string{{"vault", url}, {"PIN", strings.TrimSpace(v.pinBuf.Value())}}
		if !v.keyExists {
			rows = append(rows, [2]string{"identity", identityOpts[v.identityCur][0]})
		}
		return v.review(title, "Join this vault?", rows, "join", false, v.err)
	}
	var prompt, helper string
	switch v.step {
	case joinStepURL:
		prompt, helper = "Vault URL", "From the admin who invited you."
	case joinStepPIN:
		prompt, helper = "Invite PIN", "Shown on the inviting machine."
	case joinStepIdentity:
		prompt = "Identity of this machine"
	case joinStepAdminPass:
		prompt = "Admin passphrase of this machine"
		if !v.keyExists {
			prompt, helper = "Admin passphrase of the inviting machine", "Same identity: no new key is created."
		}
	case joinStepNewAdmin:
		prompt, helper = "New admin passphrase", "At least 8 characters; typed at every login."
	case joinStepNewApproval:
		prompt, helper = "New approval passphrase", "At least 10 characters, different from the admin one."
	}
	input := optRows(identityOpts, v.identityCur)
	if in := v.curBuf(); in != nil {
		input = []string{inputRow(in)}
	}
	fl := v.flow()
	return v.screen(title, counter(stepPos(fl, v.step), len(fl)), prompt, input, helper, v.err, "", wizKeys("next"))
}
