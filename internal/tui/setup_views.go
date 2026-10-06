// First-run + admin/vault attach views.

package tui

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/userprefs"
)

// ---------- Setup admin (first-run admin init) ----------

// setupAdminView is the first-run wizard. It collects BOTH passphrases
// DOP requires — admin (wraps the key, typed on every dop admin login)
// AND approval (typed on the phone to approve agent claims) — before
// shelling out to dop admin init --passphrase-stdin, which reads them
// in the same order. Then it signs in and asks for the harness.
const (
	setupStepAdminPass    = 0
	setupStepAdminConfirm = 1
	setupStepApprovalPass = 2
	setupStepApprovalConf = 3
	setupStepReview       = 4
	setupStepRunning      = 5
	setupStepLoggingIn    = 6
	setupStepHarness      = 7 // first-start harness picker, persisted to userprefs.Harness
)

type setupAdminView struct {
	wiz
	paths         *config.Paths
	step          int
	bufs          [4]textinput.Model // admin, admin confirm, approval, approval confirm
	harnessCursor int                // cursor into userprefs.HarnessChoices
	err           string
	done          bool
	flash         string
}

func newSetupAdminView(paths *config.Paths) *setupAdminView {
	v := &setupAdminView{paths: paths}
	for i := range v.bufs {
		v.bufs[i] = newFormInput(true)
	}
	return v
}
func (v *setupAdminView) Init() tea.Cmd { return nil }
func (v *setupAdminView) Done() bool    { return v.done }
func (v *setupAdminView) Flash() string { return v.flash }

type setupInitDone struct {
	err  string
	pass string
}
type setupLoginDone struct{ err string }

func (v *setupAdminView) curBuf() *textinput.Model {
	if v.step < setupStepReview {
		return &v.bufs[v.step]
	}
	return nil
}

func (v *setupAdminView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	in := v.curBuf()
	if ok, cmd := v.wizMsg(msg, in != nil && in.Value() != ""); ok {
		return v, cmd
	}
	switch mm := msg.(type) {
	case setupInitDone:
		if mm.err != "" {
			v.err, v.step = "Setup failed: "+firstLine(mm.err), setupStepReview
			return v, nil
		}
		v.step = setupStepLoggingIn
		return v, v.login(mm.pass)
	case setupLoginDone:
		if mm.err != "" {
			v.done = true
			v.flash = "admin created but login failed · run dop admin login"
			return v, nil
		}
		v.step = setupStepHarness
		return v, nil
	case tea.KeyMsg:
		k := mm.String()
		if k != "enter" {
			v.err = ""
		}
		switch {
		case v.step == setupStepHarness:
			return v.updateHarnessStep(mm)
		case v.step > setupStepReview:
			return v, nil // running / logging in
		}
		switch k {
		case "ctrl+c":
			v.done = true
		case "enter":
			return v.advance()
		case "esc", "shift+tab":
			if wizBack(mm, &v.step) < 0 {
				v.done = true
			}
		default:
			if in != nil {
				edit(in, mm)
			}
		}
	}
	return v, nil
}

func (v *setupAdminView) advance() (tea.Model, tea.Cmd) {
	val := func(i int) string { return v.bufs[i].Value() }
	switch v.step {
	case setupStepAdminPass:
		if len(val(0)) < 8 {
			v.err = "Admin passphrase must be at least 8 characters"
			return v, nil
		}
	case setupStepAdminConfirm:
		if val(0) != val(1) {
			v.err = "Admin passphrases don't match"
			v.bufs[1].Reset()
			return v, nil
		}
	case setupStepApprovalPass:
		if len(val(2)) < 10 {
			v.err = "Approval passphrase must be at least 10 characters"
			return v, nil
		}
		if val(2) == val(0) {
			v.err = "The approval passphrase must differ from the admin passphrase"
			return v, nil
		}
	case setupStepApprovalConf:
		if val(2) != val(3) {
			v.err = "Approval passphrases don't match"
			v.bufs[3].Reset()
			return v, nil
		}
	case setupStepReview:
		v.err, v.step = "", setupStepRunning
		return v, tea.Batch(v.spinStart(), v.doInit())
	}
	v.err = ""
	v.step++
	return v, nil
}

// updateHarnessStep: up/down moves, enter saves the pick to userprefs
// and ends the setup, esc skips (set it later in Settings).
func (v *setupAdminView) updateHarnessStep(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch mm.String() {
	case "esc", "ctrl+c":
		v.flash = "admin ready · harness not set (Settings > Harness)"
		v.done = true
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
		v.flash = "admin ready · harness set to " + userprefs.HarnessLabel(pick)
		v.done = true
	}
	return v, nil
}

func (v *setupAdminView) doInit() tea.Cmd {
	adminPass := v.bufs[0].Value()
	approvPass := v.bufs[2].Value()
	return func() tea.Msg {
		self, _ := os.Executable()
		cmd := exec.Command(self, "admin", "init", "--passphrase-stdin")
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
		// CLI reads two lines when --passphrase-stdin is set:
		//   line 1 → admin passphrase
		//   line 2 → approval passphrase
		cmd.Stdin = strings.NewReader(adminPass + "\n" + approvPass + "\n")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return setupInitDone{err: strings.TrimSpace(stderr.String())}
		}
		return setupInitDone{pass: adminPass}
	}
}

func (v *setupAdminView) login(pass string) tea.Cmd {
	return func() tea.Msg {
		self, _ := os.Executable()
		cmd := exec.Command(self, "admin", "login", "--passphrase-stdin")
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
		cmd.Stdin = strings.NewReader(pass)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return setupLoginDone{err: strings.TrimSpace(stderr.String())}
		}
		return setupLoginDone{}
	}
}

func (v *setupAdminView) View() string {
	const title = "Setup admin"
	switch v.step {
	case setupStepRunning:
		return v.running(title, "Generating admin keys")
	case setupStepLoggingIn:
		return v.running(title, "Signing in")
	case setupStepHarness:
		return harnessScreen(v.wiz, "Admin ready", v.harnessCursor, v.err)
	case setupStepReview:
		set := func(i int) string { return fmt.Sprintf("set, %d characters", len(v.bufs[i].Value())) }
		return v.review(title, "Create the admin key?", [][2]string{{"admin passphrase", set(0)}, {"approval passphrase", set(2)}}, "create", false, v.err)
	}
	prompt := []string{"Admin passphrase", "Confirm the admin passphrase", "Approval passphrase", "Confirm the approval passphrase"}[v.step]
	helper := []string{"At least 8 characters. Wraps your admin key; typed at every login.", "",
		"At least 10 characters, different. Typed on your phone to approve claims.", ""}[v.step]
	km := wizKeys("next")
	km.notes = []string{"Two passphrases, two jobs: admin unlocks this machine,", "approval confirms agent claims from your phone."}
	return v.screen(title, counter(v.step, setupStepReview), prompt, []string{inputRow(&v.bufs[v.step])}, helper, v.err, "", km)
}

// ---------- Attach vault ----------

// attachVaultView: one question (vault URL/path), then dop init --vault
// (admin install) or dop init --cache (agent install).
type attachVaultView struct {
	wiz
	paths          *config.Paths
	adminIsPresent bool
	url            textinput.Model
	running        bool
	err            string
	done           bool
	flash          string
}

func newAttachVaultView(paths *config.Paths, adminPresent bool) *attachVaultView {
	v := &attachVaultView{paths: paths, adminIsPresent: adminPresent, url: newFormInput(false)}
	v.url.Placeholder = "git@github.com:you/dop-vault.git"
	return v
}
func (v *attachVaultView) Init() tea.Cmd { return nil }
func (v *attachVaultView) Done() bool    { return v.done }
func (v *attachVaultView) Flash() string { return v.flash }

type attachResultMsg struct{ err string }

func (v *attachVaultView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if ok, cmd := v.wizMsg(msg, v.url.Value() != ""); ok {
		return v, cmd
	}
	switch mm := msg.(type) {
	case attachResultMsg:
		v.running = false
		if mm.err != "" {
			v.err = "Attach failed: " + firstLine(mm.err)
			return v, nil
		}
		v.flash = "vault attached"
		v.done = true
	case tea.KeyMsg:
		if v.running {
			return v, nil
		}
		if mm.String() != "enter" {
			v.err = ""
		}
		switch mm.String() {
		case "esc", "ctrl+c":
			v.done = true
		case "enter":
			u := strings.TrimSpace(v.url.Value())
			if u == "" {
				v.err = "Vault URL is required"
				return v, nil
			}
			v.running = true
			return v, tea.Batch(v.spinStart(), v.attach(u))
		default:
			edit(&v.url, mm)
		}
	}
	return v, nil
}

func (v *attachVaultView) attach(u string) tea.Cmd {
	flag := "--vault"
	if !v.adminIsPresent {
		flag = "--cache"
	}
	return func() tea.Msg {
		self, _ := os.Executable()
		cmd := exec.Command(self, "init", flag, u)
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return attachResultMsg{err: strings.TrimSpace(stderr.String())}
		}
		return attachResultMsg{}
	}
}

func (v *attachVaultView) View() string {
	const title = "Attach vault"
	if v.running {
		return v.wiz.running(title, "Cloning "+strings.TrimSpace(v.url.Value()))
	}
	kind := "admin install"
	if !v.adminIsPresent {
		kind = "agent install"
	}
	km := wizKeys("attach")
	km.notes = []string{"An https or ssh git URL, or a local path (a bare repo is created there)."}
	return v.screen(title, kind, "Vault repo URL or local path", []string{inputRow(&v.url)},
		"A local path that does not exist yet is created.", v.err, "", km)
}
