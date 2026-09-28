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

// setupAdminView prompts for a passphrase (twice), then shells to
// `dop admin init --passphrase-stdin`. On success it auto-triggers a
// login so the user lands in the unlocked menu.
type setupAdminView struct {
	paths   *config.Paths
	step    int    // 0 = passphrase, 1 = confirm, 2 = running, 3 = login
	pass1   strings.Builder
	pass2   strings.Builder
	err     string
	done    bool
	flash   string
}

func newSetupAdminView(paths *config.Paths) *setupAdminView {
	return &setupAdminView{paths: paths}
}
func (v *setupAdminView) Init() tea.Cmd { return nil }
func (v *setupAdminView) Done() bool    { return v.done }
func (v *setupAdminView) Flash() string { return v.flash }

type setupInitDone struct{ err string; pass string }
type setupLoginDone struct{ err string }

func (v *setupAdminView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch mm := msg.(type) {
	case setupInitDone:
		if mm.err != "" {
			v.err = mm.err
			v.step = 0
			v.pass1.Reset()
			v.pass2.Reset()
			return v, nil
		}
		v.step = 3
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
		if v.step == 2 || v.step == 3 {
			return v, nil // running
		}
		switch mm.String() {
		case "esc", "ctrl+c":
			v.done = true
		case "enter":
			switch v.step {
			case 0:
				if v.pass1.Len() < 8 {
					v.err = "passphrase must be at least 8 characters"
					return v, nil
				}
				v.err = ""
				v.step = 1
			case 1:
				if v.pass1.String() != v.pass2.String() {
					v.err = "passphrases don't match"
					v.pass2.Reset()
					return v, nil
				}
				v.step = 2
				return v, v.doInit()
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

func (v *setupAdminView) currentBuf() *strings.Builder {
	if v.step == 0 {
		return &v.pass1
	}
	return &v.pass2
}

func (v *setupAdminView) doInit() tea.Cmd {
	pass := v.pass1.String()
	return func() tea.Msg {
		self, _ := os.Executable()
		cmd := exec.Command(self, "admin", "init", "--passphrase-stdin")
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1")
		cmd.Stdin = strings.NewReader(pass)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return setupInitDone{err: strings.TrimSpace(stderr.String())}
		}
		return setupInitDone{pass: pass}
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
	b.WriteString(titleSt.Render("Setup admin") + "\n\n")
	if v.step == 2 || v.step == 3 {
		if v.step == 2 {
			b.WriteString("Generating admin keys…\n")
		} else {
			b.WriteString("Signing in…\n")
		}
		return b.String()
	}
	b.WriteString("This generates a passphrase-wrapped admin key on this machine.\n")
	b.WriteString(mutedSt.Render("The passphrase is never stored — you'll type it at each `dop admin login`.") + "\n\n")

	if v.step == 0 {
		b.WriteString(cursorSt.Render("Passphrase") + ": ")
		b.WriteString(strings.Repeat("•", v.pass1.Len()) + cursorSt.Render("▎") + "\n")
		b.WriteString(mutedSt.Render("Confirm") + ": " + mutedSt.Render("(next)") + "\n")
	} else {
		b.WriteString(mutedSt.Render("Passphrase") + ": " + strings.Repeat("•", v.pass1.Len()) + "\n")
		b.WriteString(cursorSt.Render("Confirm") + ": ")
		b.WriteString(strings.Repeat("•", v.pass2.Len()) + cursorSt.Render("▎") + "\n")
	}
	if v.err != "" {
		b.WriteString("\n" + failSt.Render(v.err) + "\n")
	}
	b.WriteString("\n" + helpSt.Render("enter next · esc cancel"))
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
	b.WriteString("\n" + helpSt.Render("enter attach · esc cancel"))
	return b.String()
}
