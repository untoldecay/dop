// v1.7 — inline pending-claim approve panel. Surfaced from the root
// menu whenever a non-expired pending claim exists (banner + 'a' key).
// Lists local PIN claims (dop claim) and remote claims staged in the
// vault repo (dop claim --remote) in one picker; remote rows shell out
// to `dop approve-remote`.
//
// The view keeps the security model: approval still requires the
// admin passphrase. The TUI only saves the click-then-type dance.

package tui

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/pendingclaim"
	"github.com/fray/dop/internal/remoteclaim"
)

// pendingRow is one approvable entry: a local PIN claim (sas set) or a
// remote claim staged in the vault (host set).
type pendingRow struct {
	subject, pubkey, keyType string
	sas, host                string
	expiresAt                time.Time
}

func (r pendingRow) remote() bool { return r.host != "" }

// pendingRows merges non-expired local + remote claims, local first.
func pendingRows(paths *config.Paths) ([]pendingRow, error) {
	var rows []pendingRow
	now := time.Now()
	local, err := pendingclaim.List(paths)
	for _, r := range local {
		if !r.Expired(now) {
			rows = append(rows, pendingRow{subject: r.Subject, pubkey: r.Pubkey, sas: r.SAS, expiresAt: r.ExpiresAt})
		}
	}
	if remote, rerr := remoteclaim.List(paths); rerr == nil {
		for _, r := range remote {
			if now.Before(r.ExpiresAt) {
				rows = append(rows, pendingRow{subject: r.Subject, pubkey: r.Pubkey, keyType: r.EffectiveKeyType(), host: r.Host, expiresAt: r.ExpiresAt})
			}
		}
	} else if err == nil {
		err = rerr
	}
	return rows, err
}

type pendingView struct {
	wiz
	paths *config.Paths

	claims []pendingRow
	cursor int
	pass   textinput.Model
	step   int // pendingStep*
	err    string
	done   bool
	flash  string
}

const (
	pendingStepPick = iota
	pendingStepPass
	pendingStepReject // confirm
	pendingStepRun
	pendingStepDone
)

type pendingResultMsg struct {
	reject bool
	err    string
}

func (m *rootModel) openPendingApprove() (tea.Model, tea.Cmd) {
	v := &pendingView{paths: m.paths, pass: newFormInput(true)}
	rows, err := pendingRows(m.paths)
	if err != nil {
		v.err = err.Error()
	}
	v.claims = rows
	m.child = v
	m.screen = screenPending
	return m, v.Init()
}

func (v *pendingView) Init() tea.Cmd { return nil }
func (v *pendingView) Done() bool    { return v.done }
func (v *pendingView) Flash() string { return v.flash }

// run shells out in a Cmd, never inside Update.
func (v *pendingView) run(reject bool) tea.Cmd {
	row, pass := v.claims[v.cursor], v.pass.Value()
	return func() tea.Msg {
		if row.remote() {
			if reject {
				_, e := runDop("", "approve-remote", "--subject", row.subject, "--reject")
				return pendingResultMsg{reject: true, err: e}
			}
			_, e := runDop(pass, "approve-remote", "--subject", row.subject, "--passphrase-stdin")
			return pendingResultMsg{err: e}
		}
		sas := pendingclaim.NormalizeSAS(row.sas)
		if reject {
			return pendingResultMsg{reject: true, err: errStr(runDopReject(sas))}
		}
		return pendingResultMsg{err: errStr(runDopApprove(sas, pass))}
	}
}

func errStr(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}

func (v *pendingView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if ok, cmd := v.wizMsg(msg, v.step == pendingStepPass && v.pass.Value() != ""); ok {
		return v, cmd
	}
	switch mm := msg.(type) {
	case pendingResultMsg:
		if mm.err != "" {
			v.err = firstLine(mm.err)
			v.step = pendingStepPick
			if !mm.reject {
				v.step = pendingStepPass
				v.pass.Reset()
			}
			return v, nil
		}
		v.flash = "Claim approved"
		if mm.reject {
			v.flash = "Claim rejected"
		}
		v.step = pendingStepDone
		return v, nil
	case tea.KeyMsg:
		k := mm.String()
		if v.step == pendingStepRun {
			return v, nil
		}
		if v.step == pendingStepDone {
			v.done = true
			return v, nil
		}
		if k == "ctrl+c" {
			v.done = true
			return v, nil
		}
		if k != "enter" {
			v.err = ""
		}
		switch v.step {
		case pendingStepPick:
			switch k {
			case "esc":
				v.done = true
			case "up", "k":
				stepCursor(&v.cursor, len(v.claims), -1)
			case "down", "j":
				stepCursor(&v.cursor, len(v.claims), 1)
			case "r", "d":
				if len(v.claims) > 0 {
					v.step = pendingStepReject
				}
			case "enter", "a":
				if len(v.claims) > 0 {
					v.step = pendingStepPass
					v.pass.Reset()
				}
			}
		case pendingStepReject:
			switch k {
			case "enter", "y":
				if cmd := v.locked(mm, &v.err); cmd != nil {
					return v, cmd
				}
				v.step = pendingStepRun
				return v, tea.Batch(v.spinStart(), v.run(true))
			case "esc", "n":
				v.step = pendingStepPick
			}
		case pendingStepPass:
			switch k {
			case "esc":
				v.step = pendingStepPick
			case "enter":
				if v.pass.Value() == "" {
					v.err = "Approval passphrase is required"
					return v, nil
				}
				if cmd := v.locked(mm, &v.err); cmd != nil {
					return v, cmd
				}
				v.step = pendingStepRun
				return v, tea.Batch(v.spinStart(), v.run(false))
			default:
				edit(&v.pass, mm)
			}
		}
	}
	return v, nil
}

var pendingKeys = keyMap{
	short: []key.Binding{hint("enter", "approve"), keyBack},
	full:  [][]key.Binding{{hint("enter", "approve"), hint("r", "reject"), keyBack}, {keyMove}},
}

func (v *pendingView) View() string {
	title := "Pending claims"
	var sel pendingRow
	if len(v.claims) > 0 {
		sel = v.claims[v.cursor]
	}
	// Second column: PIN for local claims, host for remote ones.
	where := func(r pendingRow) string {
		if r.remote() {
			return "remote · " + r.host
		}
		return "PIN " + r.sas
	}
	switch v.step {
	case pendingStepRun:
		return v.running(title, "Working on "+sel.subject)
	case pendingStepDone:
		note := ""
		if sel.remote() && !strings.Contains(v.flash, "rejected") {
			note = "Pushed to the vault repo. The agent picks it up on its next dop pull / exec."
		}
		return v.doneScreen(v.flash, [][2]string{{"bearer", sel.subject}}, note, "")
	case pendingStepReject:
		body := strings.Split(strings.TrimRight(kv([2]string{"bearer", sel.subject}, [2]string{"from", where(sel)}), "\n"), "\n")
		return frame(v.width, v.height, "Reject "+sel.subject+"?", nil, "", body, status{err: v.err}.String(), confirmFoot("reject"))
	case pendingStepPass:
		return v.screen("Approve "+sel.subject, "", "Approval passphrase", []string{inputRow(&v.pass)}, "", v.err, where(sel), wizKeys("approve"))
	}
	if len(v.claims) == 0 {
		return frame(v.width, v.height, title, nil, "", []string{bodySt.Render("  No pending claims. A claim shows here when an agent runs dop claim (or dop claim --remote).")}, status{err: v.err}.String(), footer(v.width, keyBack))
	}
	body := []string{"  " + mutedSt.Render(padTrunc("subject", 24)+"  "+padTrunc("from", 22)+"  expires")}
	for i, r := range v.claims {
		cells := padTrunc(r.subject, 24) + "  " + padTrunc(where(r), 22)
		left := "in " + humanDuration(time.Until(r.expiresAt))
		if i == v.cursor {
			body = append(body, focusSt.Render("› "+cells+"  "+left))
		} else {
			body = append(body, "  "+bodySt.Render(cells)+"  "+mutedSt.Render(left))
		}
	}
	st := status{err: v.err}
	hint := "key " + midTrunc(sel.pubkey, 24)
	if sel.keyType != "" {
		hint = sel.keyType + " " + hint
	}
	st.setHint(hint)
	body = pendingKeys.overlay(body, v.width, frameRows(v.height), v.help)
	return frame(v.width, v.height, title, nil, fmt.Sprintf("%d waiting", len(v.claims)), body, st.String(), pendingKeys.footerLine(v.width, v.help))
}

// runDopApprove shells to the CLI `dop approve --passphrase-stdin <SAS>`
// so the TUI reuses the same crypto path and the flock-atomic counter.
func runDopApprove(sas, passphrase string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(self, "approve", "--passphrase-stdin", sas)
	cmd.Stdin = strings.NewReader(passphrase)
	cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// runDopReject shells to `dop reject <SAS>`.
func runDopReject(sas string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(self, "reject", sas)
	cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}
