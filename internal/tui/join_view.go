// v1.9.1 — TUI wrapper for `dop admin join`. Shown in the pre-ready
// menu when this machine has no admin key yet (or has one but wants
// to attach to an invited vault).
//
// Collects vault URL + PIN + passphrases, spawns the CLI subprocess
// with stdin piped and stderr streamed, renders progress until done.

package tui

import (
	"bufio"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/config"
)

// Join steps. Identity is only shown when this machine has no admin
// key yet (fresh install). If keyExists, we always take the local key,
// so identity choice is moot.
const (
	joinStepURL         = 0
	joinStepPIN         = 1
	joinStepIdentity    = 2 // fresh-install only
	joinStepAdminPass   = 3 // used both for keyExists (unwrap) and shared-identity (confirm from M1)
	joinStepNewAdmin    = 4 // separate-identity fresh install
	joinStepNewApproval = 5 // separate-identity fresh install
	joinStepRunning     = 6
	joinStepDone        = 7
)

type joinView struct {
	paths *config.Paths

	// Whether this machine already has an admin key. Determines if we
	// need to also collect the *new* admin+approval passphrases.
	keyExists     bool
	shareIdentity bool // v1.9.8 — chosen at joinStepIdentity, only for fresh install

	step        int
	urlBuf      strings.Builder
	pinBuf      strings.Builder
	adminPass   strings.Builder
	newAdmin1   strings.Builder // if creating fresh + separate identity: admin passphrase
	newApproval strings.Builder // if creating fresh + separate identity: approval passphrase
	err         string
	done        bool
	flash       string

	cmd      *exec.Cmd
	lineCh   chan inviteLine
	linesMu  sync.Mutex
	lines    []string
	finalRC  int
	finalErr string
}

func newJoinView(paths *config.Paths) *joinView {
	v := &joinView{paths: paths, lineCh: make(chan inviteLine, 32)}
	v.keyExists = admin.KeyFileExists(paths)
	return v
}

func (v *joinView) Init() tea.Cmd { return nil }
func (v *joinView) Done() bool    { return v.done }
func (v *joinView) Flash() string { return v.flash }

func (v *joinView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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
		v.step = joinStepDone
		v.finalRC = mm.rc
		v.finalErr = mm.err
		if mm.rc == 0 {
			v.flash = "joined — this machine is now an admin · synced with team"
		}
		return v, nil
	case tea.KeyMsg:
		switch mm.String() {
		case "esc", "ctrl+c":
			if v.step == joinStepRunning && v.cmd != nil && v.cmd.Process != nil {
				_ = v.cmd.Process.Kill()
			}
			v.done = true
			return v, nil
		}
		if v.step == joinStepDone {
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
			if v.step == joinStepIdentity {
				v.shareIdentity = !v.shareIdentity
			}
		default:
			if len(mm.Runes) > 0 && v.step < joinStepRunning && v.step != joinStepIdentity {
				v.currentBuf().WriteString(string(mm.Runes))
			}
		}
	}
	return v, nil
}

func (v *joinView) currentBuf() *strings.Builder {
	switch v.step {
	case joinStepURL:
		return &v.urlBuf
	case joinStepPIN:
		return &v.pinBuf
	case joinStepAdminPass:
		return &v.adminPass
	case joinStepNewAdmin:
		return &v.newAdmin1
	case joinStepNewApproval:
		return &v.newApproval
	}
	return &strings.Builder{}
}

func (v *joinView) advance() (tea.Model, tea.Cmd) {
	switch v.step {
	case joinStepURL:
		if strings.TrimSpace(v.urlBuf.String()) == "" {
			v.err = "vault URL required"
			return v, nil
		}
		v.err = ""
		v.step = joinStepPIN
	case joinStepPIN:
		if strings.TrimSpace(v.pinBuf.String()) == "" {
			v.err = "PIN required"
			return v, nil
		}
		v.err = ""
		if v.keyExists {
			// Local key exists — just unwrap it.
			v.step = joinStepAdminPass
		} else {
			// Fresh install: user must tell us if this invite is
			// same-identity (Flavor Y, one confirm pass) or separate-
			// identity (Flavor X, two new passphrases).
			v.step = joinStepIdentity
		}
	case joinStepIdentity:
		v.err = ""
		if v.shareIdentity {
			// Shared identity: single confirm passphrase — the SAME one
			// used on the inviting machine. runAdminJoinShared will
			// install the encrypted blob then verify unwrap.
			v.step = joinStepAdminPass
		} else {
			// Separate identity: two new passphrases.
			v.step = joinStepNewAdmin
		}
	case joinStepAdminPass:
		if strings.TrimSpace(v.adminPass.String()) == "" {
			v.err = "passphrase required"
			return v, nil
		}
		v.err = ""
		v.step = joinStepRunning
		return v, tea.Batch(v.launch(), v.waitForLine())
	case joinStepNewAdmin:
		if len(v.newAdmin1.String()) < 8 {
			v.err = "admin passphrase must be at least 8 characters"
			return v, nil
		}
		v.err = ""
		v.step = joinStepNewApproval
	case joinStepNewApproval:
		if len(v.newApproval.String()) < 10 {
			v.err = "approval passphrase must be at least 10 characters"
			return v, nil
		}
		v.err = ""
		v.step = joinStepRunning
		return v, tea.Batch(v.launch(), v.waitForLine())
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
			strings.TrimSpace(v.urlBuf.String()),
			strings.TrimSpace(v.pinBuf.String()),
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
			lines = []string{v.adminPass.String()}
		case v.shareIdentity:
			lines = []string{v.adminPass.String()}
		default:
			lines = []string{v.newAdmin1.String(), v.newApproval.String()}
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

func (v *joinView) View() string {
	var b strings.Builder
	b.WriteString(titleSt.Render("Join an existing vault") + "\n\n")

	// Field 1: URL
	b.WriteString(rowStyle(v.step == joinStepURL).Render("Vault URL") + ": " + v.urlBuf.String())
	if v.step == joinStepURL {
		b.WriteString(cursorSt.Render("▎"))
	}
	b.WriteString("\n")

	// Field 2: PIN
	if v.step >= joinStepPIN {
		b.WriteString(rowStyle(v.step == joinStepPIN).Render("Invite PIN") + ": " + v.pinBuf.String())
		if v.step == joinStepPIN {
			b.WriteString(cursorSt.Render("▎"))
		}
		b.WriteString("\n")
	}

	// Field 3: Identity mode (fresh install only — with a key on disk we
	// just unwrap the local one).
	if !v.keyExists && v.step >= joinStepIdentity {
		b.WriteString(rowStyle(v.step == joinStepIdentity).Render("Identity") + ":   " +
			renderIdentityChoice(v.shareIdentity, v.step == joinStepIdentity) + "\n")
		if v.shareIdentity {
			b.WriteString("             " + mutedSt.Render("same admin as the inviting machine — no new key created; you'll confirm M1's passphrase") + "\n")
		} else {
			b.WriteString("             " + mutedSt.Render("brand-new admin key on this machine — set new admin + approval passphrases") + "\n")
		}
	}

	// Passphrase fields — shape depends on mode.
	switch {
	case v.keyExists:
		if v.step >= joinStepAdminPass {
			b.WriteString(rowStyle(v.step == joinStepAdminPass).Render("Admin passphrase (to unwrap local key)") + ": " +
				strings.Repeat("•", v.adminPass.Len()))
			if v.step == joinStepAdminPass {
				b.WriteString(cursorSt.Render("▎"))
			}
			b.WriteString("\n")
		}
	case v.shareIdentity:
		if v.step >= joinStepAdminPass {
			b.WriteString(rowStyle(v.step == joinStepAdminPass).Render("Confirm the admin passphrase from the inviting machine") + ": " +
				strings.Repeat("•", v.adminPass.Len()))
			if v.step == joinStepAdminPass {
				b.WriteString(cursorSt.Render("▎"))
			}
			b.WriteString("\n")
		}
	default:
		if v.step >= joinStepNewAdmin {
			b.WriteString(rowStyle(v.step == joinStepNewAdmin).Render("NEW admin passphrase (≥ 8 chars)") + ": " +
				strings.Repeat("•", v.newAdmin1.Len()))
			if v.step == joinStepNewAdmin {
				b.WriteString(cursorSt.Render("▎"))
			}
			b.WriteString("\n")
		}
		if v.step >= joinStepNewApproval {
			b.WriteString(rowStyle(v.step == joinStepNewApproval).Render("NEW approval passphrase (≥ 10 chars)") + ": " +
				strings.Repeat("•", v.newApproval.Len()))
			if v.step == joinStepNewApproval {
				b.WriteString(cursorSt.Render("▎"))
			}
			b.WriteString("\n")
		}
	}

	if v.step == joinStepRunning {
		b.WriteString("\n" + mutedSt.Render("Running… waiting for original admin to approve.") + "\n\n")
		b.WriteString(mutedSt.Render("Live output (tail):") + "\n")
		v.linesMu.Lock()
		start := 0
		if len(v.lines) > 10 {
			start = len(v.lines) - 10
		}
		for _, ln := range v.lines[start:] {
			b.WriteString("  " + mutedSt.Render(ln) + "\n")
		}
		v.linesMu.Unlock()
	}
	if v.step == joinStepDone {
		b.WriteString("\n")
		if v.finalRC == 0 {
			b.WriteString(okSt.Render("✓ joined — this machine is now an admin.") + "\n")
			b.WriteString(mutedSt.Render("  run `dop admin login` next time you need to admin the vault.") + "\n")
		} else {
			b.WriteString(failSt.Render("✗ join failed: "+v.finalErr) + "\n")
		}
	}
	if v.err != "" {
		b.WriteString("\n" + failSt.Render(v.err) + "\n")
	}

	switch v.step {
	case joinStepIdentity:
		b.WriteString("\n" + helpSt.Render("← → toggle | enter confirm | esc cancel"))
	case joinStepRunning:
		b.WriteString("\n" + helpSt.Render("esc kill | (auto-completes when admin approves)"))
	case joinStepDone:
		b.WriteString("\n" + helpSt.Render("any key to return to menu"))
	default:
		b.WriteString("\n" + helpSt.Render("enter next | esc cancel"))
	}
	return b.String()
}

func rowStyle(active bool) lipglossStyle {
	if active {
		return cursorSt
	}
	return mutedSt
}

// lipglossStyle is the local alias we need to keep imports tidy — the
// styles used here are all from tui/styles.go which is package-local.
type lipglossStyle = interface {
	Render(strs ...string) string
}
