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

type joinView struct {
	paths *config.Paths

	// Whether this machine already has an admin key. Determines if we
	// need to also collect the *new* admin+approval passphrases.
	keyExists bool

	step        int // 0=url, 1=pin, 2=admin-pass, 3=new-admin-pass, 4=new-approval-pass, 5=running, 6=done
	urlBuf      strings.Builder
	pinBuf      strings.Builder
	adminPass   strings.Builder
	newAdmin1   strings.Builder // if creating fresh: admin passphrase
	newApproval strings.Builder // if creating fresh: approval passphrase
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
		v.step = 6
		v.finalRC = mm.rc
		v.finalErr = mm.err
		if mm.rc == 0 {
			v.flash = "joined — this machine is now an admin"
		}
		return v, nil
	case tea.KeyMsg:
		switch mm.String() {
		case "esc", "ctrl+c":
			if v.step == 5 && v.cmd != nil && v.cmd.Process != nil {
				_ = v.cmd.Process.Kill()
			}
			v.done = true
			return v, nil
		}
		if v.step == 6 {
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
			if len(mm.Runes) > 0 && v.step < 5 {
				v.currentBuf().WriteString(string(mm.Runes))
			}
		}
	}
	return v, nil
}

func (v *joinView) currentBuf() *strings.Builder {
	switch v.step {
	case 0:
		return &v.urlBuf
	case 1:
		return &v.pinBuf
	case 2:
		return &v.adminPass
	case 3:
		return &v.newAdmin1
	case 4:
		return &v.newApproval
	}
	return &strings.Builder{}
}

func (v *joinView) advance() (tea.Model, tea.Cmd) {
	switch v.step {
	case 0:
		if strings.TrimSpace(v.urlBuf.String()) == "" {
			v.err = "vault URL required"
			return v, nil
		}
		v.err = ""
		v.step = 1
	case 1:
		if strings.TrimSpace(v.pinBuf.String()) == "" {
			v.err = "PIN required"
			return v, nil
		}
		v.err = ""
		if v.keyExists {
			// Only need admin passphrase (to unwrap existing key).
			v.step = 2
		} else {
			// Need admin passphrase to CREATE, then approval, then unwrap.
			// The CLI's inline init: pass1 (admin), pass2 (approval),
			// then a third read for the unwrap. We collect all three.
			v.step = 3
		}
	case 2:
		// keyExists path: single admin passphrase both prompts.
		if strings.TrimSpace(v.adminPass.String()) == "" {
			v.err = "passphrase required"
			return v, nil
		}
		v.err = ""
		v.step = 5
		return v, tea.Batch(v.launch(), v.waitForLine())
	case 3:
		if len(v.newAdmin1.String()) < 8 {
			v.err = "admin passphrase must be at least 8 characters"
			return v, nil
		}
		v.err = ""
		v.step = 4
	case 4:
		if len(v.newApproval.String()) < 10 {
			v.err = "approval passphrase must be at least 10 characters"
			return v, nil
		}
		v.err = ""
		v.step = 5
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
		// Feed passphrases into stdin.
		//   - If key exists: single admin-pass line (unwrap only).
		//   - If not: newAdmin1 + newApproval (v1.9.2: adminInitInline caches
		//     newAdmin1 and reuses it for the unwrap — no third read).
		var lines []string
		if v.keyExists {
			lines = []string{v.adminPass.String()}
		} else {
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
	b.WriteString(titleSt.Render("Join an existing vault") + "\n")
	if v.keyExists {
		b.WriteString(mutedSt.Render("this machine already has an admin key — will use it") + "\n\n")
	} else {
		b.WriteString(mutedSt.Render("no admin key yet — we'll create one now.") + "\n")
		b.WriteString(mutedSt.Render("you'll set TWO secrets (see hints inline).") + "\n")
		b.WriteString(mutedSt.Render("tip: reuse the passphrases from your other machine ") +
			mutedSt.Render("— identity is per-device but passphrases can be shared.") + "\n\n")
	}

	rows := []struct {
		label string
		val   string
		mask  bool
	}{
		{"Vault URL", v.urlBuf.String(), false},
		{"Invite PIN", v.pinBuf.String(), false},
	}
	if v.keyExists {
		rows = append(rows, struct {
			label string
			val   string
			mask  bool
		}{"Admin passphrase (to unwrap)", v.adminPass.String(), true})
	} else {
		rows = append(rows, struct {
			label string
			val   string
			mask  bool
		}{"NEW admin passphrase (≥ 8 chars) — unwraps your local keys", v.newAdmin1.String(), true})
		rows = append(rows, struct {
			label string
			val   string
			mask  bool
		}{"NEW approval passphrase (≥ 10 chars) — confirms phone approvals", v.newApproval.String(), true})
	}

	// v1.9.2: map v.step → row index. When keyExists=false we use steps
	// 0,1,3,4 (skipping 2 which is the keyExists-only unwrap prompt), so
	// treating step as the row index directly is off-by-one.
	activeRow := -1
	switch v.step {
	case 0:
		activeRow = 0
	case 1:
		activeRow = 1
	case 2:
		activeRow = 2 // keyExists: admin-unwrap
	case 3:
		activeRow = 2 // !keyExists: NEW admin passphrase
	case 4:
		activeRow = 3 // !keyExists: NEW approval passphrase
	}

	for i, r := range rows {
		style := mutedSt
		if i == activeRow {
			style = cursorSt
		}
		if activeRow >= 0 && i < activeRow {
			style = mutedSt // past step
		}
		if v.step == 5 || v.step == 6 {
			style = mutedSt
		}
		b.WriteString(style.Render(r.label) + ": ")
		v2 := r.val
		if r.mask {
			v2 = strings.Repeat("•", len(r.val))
		}
		b.WriteString(v2)
		if i == activeRow && v.step < 5 {
			b.WriteString(cursorSt.Render("▎"))
		}
		b.WriteString("\n")
	}

	if v.step == 5 {
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
	if v.step == 6 {
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
	case 5:
		b.WriteString("\n" + helpSt.Render("esc kill · (auto-completes when admin approves)"))
	case 6:
		b.WriteString("\n" + helpSt.Render("any key to return to menu"))
	default:
		b.WriteString("\n" + helpSt.Render("enter next · esc cancel"))
	}
	return b.String()
}
