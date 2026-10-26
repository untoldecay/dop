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

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/approvalcard"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/pendingclaim"
	"github.com/fray/dop/internal/remoteclaim"
	"github.com/fray/dop/internal/remoteuse"
)

// pendingRow is one approvable entry: a local PIN claim (sas set) or a
// remote claim staged in the vault (host set).
type pendingRow struct {
	subject, pubkey, keyType string
	sas, host                string
	expiresAt                time.Time
	// v1.21 — a `dop use --remote` lease request: reqID set, agent asks.
	reqID, agent string
	signed       bool // the lease request carried a valid agent signature
}

// card is the row as the operator's question (contract 27): every
// pending surface renders this and nothing else.
func (r pendingRow) card(touches string) approvalcard.Card {
	c := approvalcard.Card{Subject: r.subject, Where: r.host, Touches: touches, Expires: r.expiresAt}
	key := "agent key"
	if r.keyType != "" {
		key += " " + r.keyType
	}
	if r.pubkey != "" {
		key += " " + midTrunc(r.pubkey, 16)
	}
	switch {
	case r.lease():
		c.Kind, c.Options = approvalcard.KindLease, approvalcard.LeaseOptions()
		c.Who = r.agent + " (unsigned request)"
		if r.signed {
			c.Who = r.agent + " (signed by its agent key)"
		}
	case r.remote():
		c.Kind, c.Who = approvalcard.KindRemoteClaim, key
	default:
		c.Kind, c.Who, c.Code = approvalcard.KindClaim, key, r.sas
	}
	return c
}

// cardScreen is the passphrase step every pending surface shows: the
// card's effect and rows, the field, the footer.
func cardScreen(w wiz, title string, c approvalcard.Card, input []string, err, hint string, km keyMap) string {
	body := []string{"  " + bodySt.Render(c.Effect())}
	for _, r := range c.Rows() {
		body = append(body, "  "+mutedSt.Render(r[0]+": ")+bodySt.Render(r[1]))
	}
	body = append(body, "", "  "+mutedSt.Render(approvalcard.Passphrase), "")
	body = append(body, input...)
	return w.screen(title, "", "", body, c.Footer(), err, hint, km)
}

// grantsOf names the grants of a bearer for the card's "touches" row;
// empty when the vault can't be read (no session yet).
func grantsOf(paths *config.Paths, subject string) string {
	v, _, err := loadVaultForListing(admin.NewClient(admin.SockPath(paths)), paths)
	if err != nil {
		return ""
	}
	for _, c := range v.Capabilities {
		if c.Live() && c.Subject == subject {
			return strings.Join(c.Grants, ", ")
		}
	}
	return ""
}

func (r pendingRow) remote() bool { return r.host != "" }
func (r pendingRow) lease() bool  { return r.reqID != "" }

// where is the second column: PIN, remote host, or lease host.
func (r pendingRow) where() string {
	switch {
	case r.lease():
		return "lease · " + r.host
	case r.remote():
		return "remote · " + r.host
	}
	return "PIN " + r.sas
}

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
	if uses, uerr := remoteuse.ListRequests(paths); uerr == nil {
		for _, r := range uses {
			if _, answered := remoteuse.ReadLease(paths, r.RequestID); answered == nil || now.After(r.ExpiresAt) {
				continue
			}
			signed, verr := r.Verify()
			if verr != nil {
				continue // a bad signature never becomes a question
			}
			rows = append(rows, pendingRow{subject: r.Subject, pubkey: r.SignerPubkey, keyType: r.SignerKeyType, host: r.Host, expiresAt: r.ExpiresAt, reqID: r.RequestID, agent: r.AgentName, signed: signed})
		}
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
	lease  int // leasePresets index for a lease row
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
	pendingStepLease // v1.21 — duration picker before the passphrase
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
	return runPendingRow(v.claims[v.cursor], reject, v.pass.Value(), approvalcard.LeaseOptions()[v.lease].Value)
}

// runPendingRow approves (passphrase on stdin) or rejects one claim or
// lease request. Shared by the banner picker and Bearers › Pending.
// lease is the picked duration, used for lease rows only.
func runPendingRow(row pendingRow, reject bool, pass, lease string) tea.Cmd {
	return func() tea.Msg {
		if row.lease() {
			if reject {
				_, e := runDop("", "approve-remote", "--use", row.reqID, "--reject")
				return pendingResultMsg{reject: true, err: e}
			}
			_, e := runDop(pass, "approve-remote", "--use", row.reqID, "--lease", lease, "--passphrase-stdin")
			return pendingResultMsg{err: e}
		}
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
		if v.claims[v.cursor].lease() {
			v.flash = "Lease granted for " + approvalcard.LeaseOptions()[v.lease].Label
		}
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
					v.step, v.lease = pendingStepPass, 0
					if v.claims[v.cursor].lease() {
						v.step = pendingStepLease
					}
					v.pass.Reset()
				}
			}
		case pendingStepLease:
			switch k {
			case "esc":
				v.step = pendingStepPick
			case "up", "k":
				stepCursor(&v.lease, len(approvalcard.LeaseOptions()), -1)
			case "down", "j":
				stepCursor(&v.lease, len(approvalcard.LeaseOptions()), 1)
			case "enter":
				v.step = pendingStepPass
				v.pass.Reset()
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
	where := func(r pendingRow) string { return r.where() }
	switch v.step {
	case pendingStepRun:
		return v.running(title, "Working on "+sel.subject)
	case pendingStepDone:
		note := ""
		switch {
		case strings.Contains(v.flash, "rejected"):
		case sel.lease():
			note = "Pushed to the vault repo. The waiting server picks it up within seconds; the bearer dies when the lease ends."
		case sel.remote():
			note = "Pushed to the vault repo. The agent picks it up on its next dop pull / exec."
		}
		return v.doneScreen(v.flash, [][2]string{{"bearer", sel.subject}}, note, "")
	case pendingStepReject:
		c := sel.card("")
		body := strings.Split(strings.TrimRight(kv(append([][2]string{{"bearer", sel.subject}}, c.Rows()...)...), "\n"), "\n")
		return frame(v.width, v.height, "Reject "+sel.subject+"?", nil, "", body, status{err: v.err}.String(), confirmFoot("reject"))
	case pendingStepLease:
		c := sel.card("")
		var o [][2]string
		for _, p := range c.Options {
			o = append(o, [2]string{p.Label, ""})
		}
		return v.screen("Lease "+sel.subject+" to "+sel.agent, "", "For how long", optRows(o, v.lease),
			c.Footer(), v.err, where(sel), wizKeys("next"))
	case pendingStepPass:
		title := "Approve " + sel.subject
		if sel.lease() {
			title = "Lease " + sel.subject + " for " + approvalcard.LeaseOptions()[v.lease].Label
		}
		return cardScreen(v.wiz, title, sel.card(grantsOf(v.paths, sel.subject)), []string{inputRow(&v.pass)}, v.err, where(sel), wizKeys("approve"))
	}
	if len(v.claims) == 0 {
		return frame(v.width, v.height, title, nil, "", []string{bodySt.Render("  No pending claims. An agent's dop claim (local or --remote) shows up here.")}, status{err: v.err}.String(), footer(v.width, keyBack))
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
