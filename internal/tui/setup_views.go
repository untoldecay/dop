// First-run + admin/vault attach views.

package tui

import (
	"bytes"
	"os"
	"os/exec"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/fray/dop/internal/config"
)

// ---------- Setup admin (first-run admin init) ----------

// setupAdminView is the first-run TUI. It collects BOTH passphrases
// DOP requires — admin (wraps the key, typed on every `dop admin login`)
// AND approval (typed on the phone to approve agent claims) — before
// shelling out to `dop admin init --passphrase-stdin`, which reads them
// in the same order.
//
// v1.10.5 — previous version only asked for the admin passphrase and
// fed one line to the CLI. The CLI then failed with "approval passphrase
// must be at least 10 characters" after having already written the
// admin key to disk. Users were left in a half-installed state with a
// confusing error. Now every field is on-screen with hints explaining
// what each passphrase is for.
const (
	setupStepAdminPass    = 0
	setupStepAdminConfirm = 1
	setupStepApprovalPass = 2
	setupStepApprovalConf = 3
	setupStepRunning      = 4
	setupStepLoggingIn    = 5
)

type setupAdminView struct {
	paths       *config.Paths
	step        int
	adminPass1  strings.Builder
	adminPass2  strings.Builder
	approvPass1 strings.Builder
	approvPass2 strings.Builder
	err         string
	done        bool
	flash       string
}

func newSetupAdminView(paths *config.Paths) *setupAdminView {
	return &setupAdminView{paths: paths}
}
func (v *setupAdminView) Init() tea.Cmd { return nil }
func (v *setupAdminView) Done() bool    { return v.done }
func (v *setupAdminView) Flash() string { return v.flash }

type setupInitDone struct {
	err  string
	pass string
}
type setupLoginDone struct{ err string }

func (v *setupAdminView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch mm := msg.(type) {
	case setupInitDone:
		if mm.err != "" {
			v.err = mm.err
			// Restart from the first passphrase — buffers cleared so the
			// user can't accidentally re-submit a bad one.
			v.step = setupStepAdminPass
			v.adminPass1.Reset()
			v.adminPass2.Reset()
			v.approvPass1.Reset()
			v.approvPass2.Reset()
			return v, nil
		}
		v.step = setupStepLoggingIn
		return v, v.login(mm.pass)
	case setupLoginDone:
		if mm.err != "" {
			v.err = mm.err
			v.done = true
			v.flash = "admin created but login failed — try 'dop admin login' manually"
			return v, nil
		}
		v.flash = "admin ready — session unlocked"
		v.done = true
		return v, nil
	case tea.KeyMsg:
		if v.step >= setupStepRunning {
			return v, nil // running / logging in — ignore keys
		}
		switch mm.String() {
		case "esc", "ctrl+c":
			v.done = true
		case "enter":
			return v.advance()
		case "tab", "down":
			if v.step < setupStepApprovalConf {
				v.step++
			}
		case "shift+tab", "up":
			if v.step > setupStepAdminPass {
				v.step--
			}
		case "backspace":
			buf := v.currentBuf()
			s := buf.String()
			if len(s) > 0 {
				buf.Reset()
				buf.WriteString(s[:len(s)-1])
			}
		default:
			if len(mm.Runes) > 0 {
				v.currentBuf().WriteString(string(mm.Runes))
			}
		}
	}
	return v, nil
}

func (v *setupAdminView) advance() (tea.Model, tea.Cmd) {
	switch v.step {
	case setupStepAdminPass:
		if v.adminPass1.Len() < 8 {
			v.err = "admin passphrase must be at least 8 characters"
			return v, nil
		}
		v.err = ""
		v.step = setupStepAdminConfirm
	case setupStepAdminConfirm:
		if v.adminPass1.String() != v.adminPass2.String() {
			v.err = "admin passphrases don't match"
			v.adminPass2.Reset()
			return v, nil
		}
		v.err = ""
		v.step = setupStepApprovalPass
	case setupStepApprovalPass:
		if v.approvPass1.Len() < 10 {
			v.err = "approval passphrase must be at least 10 characters"
			return v, nil
		}
		if v.approvPass1.String() == v.adminPass1.String() {
			v.err = "the approval passphrase must be different from the admin passphrase"
			return v, nil
		}
		v.err = ""
		v.step = setupStepApprovalConf
	case setupStepApprovalConf:
		if v.approvPass1.String() != v.approvPass2.String() {
			v.err = "approval passphrases don't match"
			v.approvPass2.Reset()
			return v, nil
		}
		v.err = ""
		v.step = setupStepRunning
		return v, v.doInit()
	}
	return v, nil
}

func (v *setupAdminView) currentBuf() *strings.Builder {
	switch v.step {
	case setupStepAdminPass:
		return &v.adminPass1
	case setupStepAdminConfirm:
		return &v.adminPass2
	case setupStepApprovalPass:
		return &v.approvPass1
	case setupStepApprovalConf:
		return &v.approvPass2
	}
	var scratch strings.Builder
	return &scratch
}

func (v *setupAdminView) doInit() tea.Cmd {
	adminPass := v.adminPass1.String()
	approvPass := v.approvPass1.String()
	return func() tea.Msg {
		self, _ := os.Executable()
		cmd := exec.Command(self, "admin", "init", "--passphrase-stdin")
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1")
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
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1")
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
	var b strings.Builder
	b.WriteString(titleSt.Render("Setup admin") + "\n")
	b.WriteString(mutedSt.Render("First-run: choose TWO passphrases — they do different jobs.") + "\n\n")

	if v.step == setupStepRunning {
		b.WriteString("Generating admin keys…\n")
		return b.String()
	}
	if v.step == setupStepLoggingIn {
		b.WriteString("Signing in…\n")
		return b.String()
	}

	// Explanations, always visible.
	b.WriteString(mutedSt.Render("• admin passphrase (≥ 8 chars) — wraps your admin private key.") + "\n")
	b.WriteString(mutedSt.Render("  You'll type this at every `dop admin login`.") + "\n")
	b.WriteString(mutedSt.Render("• approval passphrase (≥ 10 chars, DIFFERENT) — separate secret.") + "\n")
	b.WriteString(mutedSt.Render("  You'll type this on your phone to approve agent claims.") + "\n\n")

	rows := []struct {
		label string
		val   string
	}{
		{"Admin passphrase", v.adminPass1.String()},
		{"Confirm admin passphrase", v.adminPass2.String()},
		{"Approval passphrase", v.approvPass1.String()},
		{"Confirm approval passphrase", v.approvPass2.String()},
	}
	for i, r := range rows {
		style := mutedSt
		if i == v.step {
			style = cursorSt
		}
		b.WriteString(style.Render(r.label) + ": ")
		b.WriteString(strings.Repeat("•", len(r.val)))
		if i == v.step {
			b.WriteString(cursorSt.Render("▎"))
		}
		b.WriteString("\n")
	}
	if v.err != "" {
		b.WriteString("\n" + failSt.Render(v.err) + "\n")
	}
	b.WriteString("\n" + helpSt.Render("enter next | tab/↑↓ jump between fields | esc cancel"))
	return b.String()
}

// ---------- Attach vault ----------

// attachVaultView: prompts for vault URL/path, decides admin-vs-cache
// based on presence of admin key, then shells to `dop init --vault`
// or `dop init --cache`.
type attachVaultView struct {
	paths   *config.Paths
	adminIsPresent bool
	url     strings.Builder
	running bool
	err     string
	done    bool
	flash   string
	output  strings.Builder
}

func newAttachVaultView(paths *config.Paths, adminPresent bool) *attachVaultView {
	return &attachVaultView{paths: paths, adminIsPresent: adminPresent}
}
func (v *attachVaultView) Init() tea.Cmd { return nil }
func (v *attachVaultView) Done() bool    { return v.done }
func (v *attachVaultView) Flash() string { return v.flash }

type attachResultMsg struct{ err string }

func (v *attachVaultView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch mm := msg.(type) {
	case attachResultMsg:
		v.running = false
		if mm.err != "" {
			v.err = mm.err
			return v, nil
		}
		v.flash = "vault attached"
		v.done = true
	case tea.KeyMsg:
		if v.running {
			return v, nil
		}
		switch mm.String() {
		case "esc", "ctrl+c":
			v.done = true
		case "enter":
			u := strings.TrimSpace(v.url.String())
			if u == "" {
				return v, nil
			}
			v.running = true
			v.err = ""
			return v, v.attach(u)
		case "backspace":
			s := v.url.String()
			if len(s) > 0 {
				v.url.Reset()
				v.url.WriteString(s[:len(s)-1])
			}
		default:
			if len(mm.Runes) > 0 {
				v.url.WriteString(string(mm.Runes))
			}
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
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return attachResultMsg{err: strings.TrimSpace(stderr.String())}
		}
		return attachResultMsg{}
	}
}

func (v *attachVaultView) View() string {
	var b strings.Builder
	b.WriteString(titleSt.Render("Attach vault") + "\n\n")
	kind := "admin install"
	if !v.adminIsPresent {
		kind = "agent install (no admin key)"
	}
	b.WriteString(mutedSt.Render("This machine: " + kind) + "\n\n")
	b.WriteString("Vault repo URL or local path:\n")
	b.WriteString("  " + v.url.String() + cursorSt.Render("▎") + "\n")
	b.WriteString(mutedSt.Render("examples:") + "\n")
	b.WriteString(mutedSt.Render("  https://github.com/you/dop-vault.git") + "\n")
	b.WriteString(mutedSt.Render("  git@github.com:you/dop-vault.git") + "\n")
	b.WriteString(mutedSt.Render("  /tmp/dop-vault-bare.git   (creates one)") + "\n")
	if v.running {
		b.WriteString("\n" + mutedSt.Render("cloning…") + "\n")
	}
	if v.err != "" {
		b.WriteString("\n" + failSt.Render(v.err) + "\n")
	}
	b.WriteString("\n" + helpSt.Render("enter attach | esc cancel"))
	return b.String()
}
