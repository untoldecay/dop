// Team and revoke TUI views.

package tui

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/admininvite"
	"github.com/fray/dop/internal/capability"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

// ---------- Revoke token ----------

type revokeView struct {
	wiz
	client *admin.Client
	paths  *config.Paths

	step    int // 0 = list, 1 = confirm, 2 = running, 3 = done
	loaded  bool
	loadErr string
	items   []revokeItem
	cursor  int
	err     string
	flash   string
	done    bool
}

type revokeItem struct {
	subject string
	status  string
	capID   string
}

func newRevokeView(c *admin.Client, p *config.Paths) *revokeView {
	return &revokeView{client: c, paths: p}
}
func (v *revokeView) Init() tea.Cmd { return v.load }
func (v *revokeView) Done() bool    { return v.done }
func (v *revokeView) Flash() string { return v.flash }

type revokeLoadedMsg struct {
	items []revokeItem
	err   string
}
type revokeResultMsg struct{ err string }

func (v *revokeView) load() tea.Msg {
	vlt, _, err := loadVaultForListing(v.client, v.paths)
	if err != nil {
		if errors.Is(err, vault.ErrNotAttached) {
			return revokeLoadedMsg{err: renderNoVault("bearers")}
		}
		if errors.Is(err, vault.ErrSessionEnded) {
			return revokeLoadedMsg{err: renderSessionEnded()}
		}
		return revokeLoadedMsg{err: err.Error()}
	}
	items := []revokeItem{}
	for id, c := range vlt.Capabilities {
		if c.Status == capability.RecordStatusActive {
			items = append(items, revokeItem{subject: c.Subject, status: c.Status, capID: id})
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].subject < items[j].subject })
	return revokeLoadedMsg{items: items}
}

func (v *revokeView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if ok, cmd := v.wizMsg(msg, false); ok {
		return v, cmd
	}
	switch mm := msg.(type) {
	case revokeLoadedMsg:
		v.loaded = true
		v.items = mm.items
		v.loadErr = mm.err
	case revokeResultMsg:
		if mm.err != "" {
			v.err = "Revoke failed: " + firstLine(mm.err)
			v.step = 1
			return v, nil
		}
		v.flash = "Bearer revoked"
		v.step = 3
	case tea.KeyMsg:
		k := mm.String()
		switch {
		case k == "ctrl+c", v.step == 3:
			v.done = true
			return v, nil
		case !v.loaded, v.step == 2:
			return v, nil
		case k == "esc" && v.step == 1:
			v.step, v.err = 0, ""
			return v, nil
		case k == "esc":
			v.done = true
			return v, nil
		}
		switch v.step {
		case 0:
			switch k {
			case "up", "k":
				stepCursor(&v.cursor, len(v.items), -1)
			case "down", "j":
				stepCursor(&v.cursor, len(v.items), 1)
			case "enter":
				if len(v.items) > 0 {
					v.step = 1
				}
			}
		case 1:
			switch k {
			case "y", "Y", "enter":
				v.step = 2
				return v, tea.Batch(v.spinStart(), v.doRevoke())
			case "n", "N":
				v.step = 0
			}
		}
	}
	return v, nil
}

func (v *revokeView) doRevoke() tea.Cmd {
	// v1.13 — pass the cap-id prefix (unambiguous). The CLI's
	// `token revoke` accepts subject OR cap/lookup prefix, so the
	// TUI picks whichever form it has handy — in this view the
	// capID is the stable identifier even when subjects collide.
	target := v.items[v.cursor].capID[:12]
	return func() tea.Msg {
		self, _ := os.Executable()
		cmd := exec.Command(self, "token", "revoke", target)
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return revokeResultMsg{err: strings.TrimSpace(stderr.String())}
		}
		return revokeResultMsg{}
	}
}

func (v *revokeView) View() string {
	const title = "Revoke bearer"
	switch {
	case !v.loaded:
		return v.notice(title, "  loading…")
	case v.loadErr != "":
		return v.notice(title, v.loadErr)
	case len(v.items) == 0:
		return v.notice(title, mutedSt.Render("  No active bearers. Issue one from the menu: Issue."))
	}
	it := v.items[v.cursor]
	switch v.step {
	case 0:
		var opts [][2]string
		for _, it := range v.items {
			opts = append(opts, [2]string{ansi.Truncate(it.subject, 40, "…"), it.capID[:8]})
		}
		return v.pick(title, fmt.Sprintf("%d active", len(v.items)), opts, v.cursor, it.subject, "", pickKeys("revoke"))
	case 1:
		body := append(strings.Split(strings.TrimRight(kv([2]string{"bearer", it.subject}, [2]string{"id", it.capID[:8]}), "\n"), "\n"),
			"", mutedSt.Render("  The bundle is deleted and its generation bumped."))
		return v.confirmScreen("Revoke "+ansi.Truncate(it.subject, 50, "…")+"?", body, "revoke", v.err)
	case 2:
		return v.running(title, "Revoking "+it.subject)
	}
	return v.doneScreen("Bearer revoked", [][2]string{{"bearer", it.subject}}, "", "")
}

// ---------- Team member by key ----------

// teamAddView: name, age recipient, ed25519 key, note, then review,
// running and done.
const (
	teamAddStepReview = 4
	teamAddStepRun    = 5
	teamAddStepDone   = 6
)

type teamAddView struct {
	wiz
	client *admin.Client
	paths  *config.Paths

	step  int
	bufs  [4]textinput.Model // name, age recipient, ed25519, note
	err   string
	flash string
	done  bool
}

func newTeamAddView(c *admin.Client, p *config.Paths) *teamAddView {
	v := &teamAddView{client: c, paths: p}
	for i, ph := range []string{"bob", "age1…", "64 hex characters", "MacBook Pro"} {
		v.bufs[i] = newFormInput(false)
		v.bufs[i].Placeholder = ph
	}
	return v
}
func (v *teamAddView) Init() tea.Cmd { return nil }
func (v *teamAddView) Done() bool    { return v.done }
func (v *teamAddView) Flash() string { return v.flash }

type teamAddResultMsg struct{ err string }

func (v *teamAddView) val(i int) string { return strings.TrimSpace(v.bufs[i].Value()) }

func (v *teamAddView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var in *textinput.Model
	if v.step < teamAddStepReview {
		in = &v.bufs[v.step]
	}
	if ok, cmd := v.wizMsg(msg, in != nil && in.Value() != ""); ok {
		return v, cmd
	}
	switch mm := msg.(type) {
	case teamAddResultMsg:
		if mm.err != "" {
			v.err, v.step = "Add failed: "+firstLine(mm.err), teamAddStepReview
			return v, nil
		}
		v.step = teamAddStepDone
	case tea.KeyMsg:
		switch {
		case v.step == teamAddStepRun:
			return v, nil
		case v.step == teamAddStepDone || mm.String() == "ctrl+c":
			v.done = true
			v.flash = map[bool]string{true: "team member added · synced with team"}[v.step == teamAddStepDone]
			return v, nil
		}
		if mm.String() != "enter" {
			v.err = ""
		}
		switch mm.String() {
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

func (v *teamAddView) advance() (tea.Model, tea.Cmd) {
	switch v.step {
	case 0:
		if v.val(0) == "" {
			v.err = "Name is required"
			return v, nil
		}
	case 1:
		if !strings.HasPrefix(v.val(1), "age1") {
			v.err = "Not an age recipient: it starts with age1"
			return v, nil
		}
	case teamAddStepReview:
		v.err, v.step = "", teamAddStepRun
		return v, tea.Batch(v.spinStart(), v.save())
	}
	v.err = ""
	v.step++
	return v, nil
}

func (v *teamAddView) save() tea.Cmd {
	name, pub, ed, note := v.val(0), v.val(1), v.val(2), v.val(3)
	return func() tea.Msg {
		self, _ := os.Executable()
		args := []string{"team", "add-key", "--name", name, "--pubkey", pub}
		if ed != "" {
			args = append(args, "--ed25519", ed)
		}
		if note != "" {
			args = append(args, "--note", note)
		}
		cmd := exec.Command(self, args...)
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return teamAddResultMsg{err: strings.TrimSpace(stderr.String())}
		}
		return teamAddResultMsg{}
	}
}

func (v *teamAddView) View() string {
	const title = "Add team member"
	rows := [][2]string{{"name", v.val(0)}, {"age recipient", midTrunc(v.val(1), 40)},
		{"ed25519 key", midTrunc(displayOr(v.val(2), "none"), 40)}, {"note", displayOr(v.val(3), "none")}}
	switch v.step {
	case teamAddStepRun:
		return v.running(title, "Adding "+v.val(0))
	case teamAddStepDone:
		return v.doneScreen("Team member added", rows[:2], "The vault is synced with the team.", "")
	case teamAddStepReview:
		return v.review(title, "Add this team member?", rows, "add", false, v.err)
	}
	prompt := []string{"Name", "Age recipient of " + v.val(0), "Ed25519 key", "Note"}[v.step]
	helper := []string{"", "Their dop admin key prints it.", "Optional. Signs their vault changes.", "Optional, e.g. the machine."}[v.step]
	return v.screen(title, counter(v.step, teamAddStepReview), prompt, []string{inputRow(&v.bufs[v.step])}, helper, v.err, "", wizKeys("next"))
}

// ---------- Team list ----------

// Team list: Members / Pending tabs. Pending shows open admin invites
// with approve and delete (shells out to `dop team approve-invite` and
// `dop team cancel-invite`).
const (
	teamTabMembers = 0
	teamTabPending = 1
)

const (
	teamModeList        = 0
	teamModeConfirm     = 1 // confirm "delete pending invite?"
	teamModeRunning     = 2 // subprocess in flight
	teamModeApprovePass = 4 // approval passphrase for approve-invite
	teamModeApproveRun  = 5 // approve subprocess in flight
	teamModeApproveDone = 6 // ✓ Member approved
)

type teamListView struct {
	wiz
	client  *admin.Client
	paths   *config.Paths
	loaded  bool
	loadErr string
	admins  map[string]vault.Admin
	names   []string
	pending []admininvite.Invite
	tab     int
	mode    int
	cursor  int

	// confirm/run state
	pendingDeleteID string
	actionErr       string
	actionFlash     string

	// approve-invite state: pass collects the approval passphrase
	// (masked); pendingApproveID is the invite being approved.
	pendingApproveID string
	pass             textinput.Model

	done bool
}

func newTeamListView(c *admin.Client, p *config.Paths) *teamListView {
	return &teamListView{client: c, paths: p, pass: newFormInput(true)}
}
func (v *teamListView) Init() tea.Cmd { return v.load }
func (v *teamListView) Done() bool    { return v.done }

type teamListLoadedMsg struct {
	admins  map[string]vault.Admin
	pending []admininvite.Invite
	err     string
}

type teamCancelDoneMsg struct {
	id  string
	err string
}

func (v *teamListView) load() tea.Msg {
	vlt, _, err := loadVaultForListing(v.client, v.paths)
	if err != nil {
		if errors.Is(err, vault.ErrNotAttached) {
			return teamListLoadedMsg{err: renderNoVault("team members")}
		}
		if errors.Is(err, vault.ErrSessionEnded) {
			return teamListLoadedMsg{err: renderSessionEnded()}
		}
		return teamListLoadedMsg{err: err.Error()}
	}
	// Pending invites are best-effort: a missing / unreadable
	// pending-admin-invites dir is normal on fresh installs.
	var pending []admininvite.Invite
	if invs, err := admininvite.ListInvites(v.paths); err == nil {
		for _, inv := range invs {
			pending = append(pending, *inv)
		}
		sort.Slice(pending, func(i, j int) bool {
			return pending[i].CreatedAt.After(pending[j].CreatedAt)
		})
	}
	return teamListLoadedMsg{admins: vlt.Admins, pending: pending}
}

func (v *teamListView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if ok, cmd := v.wizMsg(msg, v.mode == teamModeApprovePass); ok {
		return v, cmd
	}
	switch mm := msg.(type) {
	case teamListLoadedMsg:
		v.loaded = true
		v.admins = mm.admins
		v.loadErr = mm.err
		v.pending = mm.pending
		v.names = v.names[:0]
		for n := range v.admins {
			v.names = append(v.names, n)
		}
		sort.Strings(v.names)
		v.cursor = min(v.cursor, max(v.rowCount()-1, 0))
	case teamCancelDoneMsg:
		v.mode = teamModeList
		if mm.err != "" {
			v.actionErr = "Delete failed: " + firstLine(mm.err)
			return v, nil
		}
		v.actionFlash = "Invite deleted"
		// Reload so the pending list reflects the deletion.
		v.loaded = false
		return v, v.load
	case teamApproveDoneMsg:
		if mm.err != "" {
			v.actionErr = "Approve failed: " + firstLine(mm.err)
			v.mode = teamModeApprovePass
			return v, nil
		}
		v.mode = teamModeApproveDone
	case tea.KeyMsg:
		return v.handleKey(mm)
	}
	return v, nil
}

func (v *teamListView) handleKey(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	if !v.loaded {
		return v, nil
	}
	if mm.String() != "enter" && v.mode != teamModeRunning && v.mode != teamModeApproveRun {
		v.actionErr = ""
	}
	v.actionFlash = ""
	switch v.mode {
	case teamModeConfirm:
		switch mm.String() {
		case "y", "enter":
			v.mode = teamModeRunning
			return v, tea.Batch(v.spinStart(), v.cancelInvite(v.pendingDeleteID))
		case "n", "esc":
			v.mode = teamModeList
			v.pendingDeleteID = ""
		}
		return v, nil
	case teamModeApprovePass:
		switch mm.String() {
		case "esc":
			v.mode = teamModeList
			v.pendingApproveID = ""
			v.pass.Reset()
		case "enter":
			if v.pass.Value() == "" {
				v.actionErr = "Approval passphrase is required"
				return v, nil
			}
			v.mode = teamModeApproveRun
			return v, tea.Batch(v.spinStart(), v.approveInvite(v.pendingApproveID, v.pass.Value()))
		default:
			edit(&v.pass, mm)
		}
		return v, nil
	case teamModeRunning, teamModeApproveRun:
		return v, nil
	case teamModeApproveDone:
		v.mode = teamModeList
		v.actionFlash = "Member approved"
		v.loaded = false
		return v, v.load
	}
	// list mode
	switch mm.String() {
	case "esc", "q", "ctrl+c", "backspace":
		v.done = true
	case "tab":
		v.tab = (v.tab + 1) % 2
		v.cursor = 0
	case "up", "k":
		stepCursor(&v.cursor, v.rowCount(), -1)
	case "down", "j":
		stepCursor(&v.cursor, v.rowCount(), 1)
	case "d":
		if v.tab == teamTabPending && v.cursor < len(v.pending) {
			v.pendingDeleteID = v.pending[v.cursor].InviteID
			v.mode = teamModeConfirm
		}
	case "a":
		// Opens the approval passphrase prompt; on enter, shells out
		// to `dop team approve-invite <id> --passphrase-stdin`.
		if v.tab == teamTabPending && v.cursor < len(v.pending) {
			inv := v.pending[v.cursor]
			if inv.ShareIdentity {
				v.actionErr = "Same-identity invite: nothing to approve here. The join completes on their machine."
				return v, nil
			}
			v.pendingApproveID = inv.InviteID
			v.pass.Reset()
			v.mode = teamModeApprovePass
		}
	}
	return v, nil
}

func (v *teamListView) rowCount() int {
	if v.tab == teamTabMembers {
		return len(v.names)
	}
	return len(v.pending)
}

type teamApproveDoneMsg struct {
	id  string
	err string
}

// approveInvite — rc7o. Pipes the approval passphrase on stdin and
// shells out to `dop team approve-invite <id> --passphrase-stdin`.
// Keeps the passphrase off the command line (same discipline as the
// token-issue protected-grant flow).
func (v *teamListView) approveInvite(id, pass string) tea.Cmd {
	return func() tea.Msg {
		self, err := os.Executable()
		if err != nil {
			return teamApproveDoneMsg{id: id, err: err.Error()}
		}
		cmd := exec.Command(self, "team", "approve-invite", "--passphrase-stdin", id)
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
		cmd.Stdin = strings.NewReader(pass + "\n")
		var stderr strings.Builder
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return teamApproveDoneMsg{id: id, err: strings.TrimSpace(stderr.String())}
		}
		return teamApproveDoneMsg{id: id}
	}
}

// cancelInvite shells out to `dop team cancel-invite <id>` and
// returns the result as a teamCancelDoneMsg.
func (v *teamListView) cancelInvite(id string) tea.Cmd {
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

// invite finds the pending invite with this id (it may have left the list).
func (v *teamListView) invite(id string) admininvite.Invite {
	for _, inv := range v.pending {
		if inv.InviteID == id {
			return inv
		}
	}
	return admininvite.Invite{InviteID: id}
}

var (
	teamMemberKeys  = keyMap{short: []key.Binding{hint("tab", "pending"), keyBack}, full: [][]key.Binding{{hint("tab", "switch tab"), keyBack}, {keyMove}}}
	teamPendingKeys = keyMap{short: []key.Binding{hint("tab", "members"), keyBack},
		full: [][]key.Binding{{hint("a", "approve"), hint("d", "delete"), hint("tab", "switch tab"), keyBack}, {keyMove}}}
)

func (v *teamListView) View() string {
	tabs := []tab{{"Members", len(v.names), v.tab == teamTabMembers}, {"Pending", len(v.pending), v.tab == teamTabPending}}
	if !v.loaded {
		return frame(v.width, v.height, "Team", tabs, "", []string{mutedSt.Render("  loading…")}, "", "")
	}
	if v.loadErr != "" {
		return frame(v.width, v.height, "Team", nil, "", strings.Split(v.loadErr, "\n"), "", footer(v.width, keyBack))
	}
	inv := v.invite(v.pendingApproveID)
	switch v.mode {
	case teamModeConfirm:
		inv = v.invite(v.pendingDeleteID)
		body := strings.Split(strings.TrimRight(kv([2]string{"label", inv.Name}, [2]string{"kind", inviteKindWord(inv)}, [2]string{"expires", inviteLeft(inv)}), "\n"), "\n")
		body = append(body, "", mutedSt.Render("  The invite file and its identity blob leave the vault."))
		return v.confirmScreen("Delete invite "+inv.Name+"?", body, "delete", v.actionErr)
	case teamModeRunning:
		return v.running("Team", "Deleting invite "+v.invite(v.pendingDeleteID).Name)
	case teamModeApprovePass:
		return v.screen("Approve "+inv.Name, "", "Approval passphrase", []string{inputRow(&v.pass)}, "", v.actionErr, "", wizKeys("approve"))
	case teamModeApproveRun:
		return v.running("Team", "Approving "+inv.Name)
	case teamModeApproveDone:
		return v.doneScreen("Member approved", [][2]string{{"member", inv.Name}}, "They are now an admin of the vault.", "")
	}
	km := teamMemberKeys
	st := status{err: v.actionErr, flash: v.actionFlash}
	var body []string
	if v.tab == teamTabMembers {
		if len(v.names) == 0 {
			body = []string{mutedSt.Render("  No team members yet. Add one from the menu: Add › Team member.")}
		} else {
			body = []string{"  " + mutedSt.Render(padTrunc("name", nameColW)+"  note")}
			for i, n := range v.names {
				note := v.admins[n].Note
				if i == v.cursor {
					body = append(body, focusSt.Render("› "+padTrunc(n, nameColW)+"  "+note))
				} else {
					body = append(body, "  "+bodySt.Render(padTrunc(n, nameColW))+"  "+mutedSt.Render(note))
				}
			}
			a := v.admins[v.names[v.cursor]]
			st.setHint("age " + midTrunc(a.AgeRecipient, 24) + " · ed25519 " + midTrunc(a.Ed25519Pubkey, 24))
		}
	} else {
		km = teamPendingKeys
		if len(v.pending) == 0 {
			body = []string{mutedSt.Render("  No pending invites. Open one from the menu: Add › Device or Team member.")}
			km.short = km.short[2:]
		} else {
			body = []string{"  " + mutedSt.Render(padTrunc("label", 24)+"  "+padTrunc("kind", 12)+"  expires")}
			for i, inv := range v.pending {
				cells := padTrunc(inv.Name, 24) + "  " + padTrunc(inviteKindWord(inv), 12)
				left := inviteLeft(inv)
				if _, err := admininvite.ReadResponse(v.paths, inv.InviteID); err == nil && !inv.ShareIdentity {
					left += "  ✓ ready"
				}
				if i == v.cursor {
					body = append(body, focusSt.Render("› "+cells+"  "+left))
				} else {
					body = append(body, "  "+bodySt.Render(cells)+"  "+mutedSt.Render(left))
				}
			}
			st.setHint("invite " + midTrunc(v.pending[v.cursor].InviteID, 16))
		}
	}
	body = km.overlay(body, v.width, frameRows(v.height), v.help)
	return frame(v.width, v.height, "Team", tabs, "", body, st.String(), km.footerLine(v.width, v.help))
}

func inviteKindWord(inv admininvite.Invite) string {
	kind := "device"
	if inv.Kind == "team_member" {
		kind = "team member"
	}
	if inv.ShareIdentity {
		kind += " (same)"
	}
	return kind
}

// inviteLeft is the relative expiry: in 6d, or expired.
func inviteLeft(inv admininvite.Invite) string {
	if d := inv.ExpiresAt.Sub(timeNow()); d > 0 {
		return "in " + humanDuration(d)
	}
	return "expired"
}

const timeFmt = "2006-01-02 15:04"

func timeNow() time.Time { return time.Now().UTC() }

func humanDuration(d time.Duration) string { return shortDuration(d) }

// ---------- Team remove ----------

type teamRemoveView struct {
	wiz
	client    *admin.Client
	paths     *config.Paths
	loaded    bool
	loadErr   string
	names     []string
	notes     map[string]string
	cursor    int
	step      int // 0 = pick, 1 = rotation checklist + confirm, 2 = running, 3 = done
	err       string
	flash     string
	done      bool
	checklist []string
}

func newTeamRemoveView(c *admin.Client, p *config.Paths) *teamRemoveView {
	return &teamRemoveView{client: c, paths: p}
}
func (v *teamRemoveView) Init() tea.Cmd { return v.load }
func (v *teamRemoveView) Done() bool    { return v.done }
func (v *teamRemoveView) Flash() string { return v.flash }

type teamRemoveLoadedMsg struct {
	names     []string
	notes     map[string]string
	checklist []string
	err       string
}
type teamRemoveResultMsg struct{ err string }

func (v *teamRemoveView) load() tea.Msg {
	vlt, _, err := loadVaultForListing(v.client, v.paths)
	if err != nil {
		if errors.Is(err, vault.ErrNotAttached) {
			return teamRemoveLoadedMsg{err: renderNoVault("team members")}
		}
		if errors.Is(err, vault.ErrSessionEnded) {
			return teamRemoveLoadedMsg{err: renderSessionEnded()}
		}
		return teamRemoveLoadedMsg{err: err.Error()}
	}
	names, notes := make([]string, 0, len(vlt.Admins)), map[string]string{}
	for n, a := range vlt.Admins {
		names = append(names, n)
		notes[n] = a.Note
	}
	sort.Strings(names)
	// Build the checklist once — same for any removal target.
	var cl []string
	for iname, integ := range vlt.Integrations {
		for tname, tok := range integ.Tokens {
			cl = append(cl, strings.TrimSpace(fmt.Sprintf("%s / %s  %s", iname, tname, tok.ScopeNote)))
		}
	}
	sort.Strings(cl)
	return teamRemoveLoadedMsg{names: names, notes: notes, checklist: cl}
}

func (v *teamRemoveView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if ok, cmd := v.wizMsg(msg, false); ok {
		return v, cmd
	}
	switch mm := msg.(type) {
	case teamRemoveLoadedMsg:
		v.loaded = true
		v.names = mm.names
		v.notes = mm.notes
		v.checklist = mm.checklist
		v.loadErr = mm.err
	case teamRemoveResultMsg:
		if mm.err != "" {
			v.err = "Remove failed: " + firstLine(mm.err)
			v.step = 1
			return v, nil
		}
		v.flash = "Team member removed"
		v.step = 3
	case tea.KeyMsg:
		k := mm.String()
		switch {
		case k == "ctrl+c", v.step == 3:
			v.done = true
			return v, nil
		case !v.loaded, v.step == 2:
			return v, nil
		case k == "esc" && v.step == 1:
			v.step, v.err = 0, ""
			return v, nil
		case k == "esc":
			v.done = true
			return v, nil
		}
		switch v.step {
		case 0:
			switch k {
			case "up", "k":
				stepCursor(&v.cursor, len(v.names), -1)
			case "down", "j":
				stepCursor(&v.cursor, len(v.names), 1)
			case "enter":
				if len(v.names) > 0 {
					v.step = 1
				}
			}
		case 1:
			switch k {
			case "y", "Y", "enter":
				v.step = 2
				return v, tea.Batch(v.spinStart(), v.doRemove())
			case "n", "N":
				v.step = 0
			}
		}
	}
	return v, nil
}

func (v *teamRemoveView) doRemove() tea.Cmd {
	name := v.names[v.cursor]
	return func() tea.Msg {
		self, _ := os.Executable()
		cmd := exec.Command(self, "team", "remove", "--name", name, "--force")
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return teamRemoveResultMsg{err: strings.TrimSpace(stderr.String())}
		}
		return teamRemoveResultMsg{}
	}
}

func (v *teamRemoveView) View() string {
	const title = "Remove team member"
	switch {
	case !v.loaded:
		return v.notice(title, "  loading…")
	case v.loadErr != "":
		return v.notice(title, v.loadErr)
	case len(v.names) == 0:
		return v.notice(title, mutedSt.Render("  No team members yet. Add one from the menu: Add › Team member."))
	}
	name := v.names[v.cursor]
	switch v.step {
	case 0:
		var opts [][2]string
		for _, n := range v.names {
			opts = append(opts, [2]string{n, v.notes[n]})
		}
		return v.pick(title, fmt.Sprintf("%d members", len(v.names)), opts, v.cursor, "", "", pickKeys("remove"))
	case 1:
		body := []string{dangerSt.Render("! Rotate these credentials now:") + mutedSt.Render(" their old vault copy still decrypts."), ""}
		if len(v.checklist) == 0 {
			body = []string{mutedSt.Render("  No credentials in the vault. Nothing to rotate.")}
		}
		for i, c := range v.checklist {
			if i == frameRows(v.height)-5 {
				body = append(body, mutedSt.Render(fmt.Sprintf("  and %d more", len(v.checklist)-i)))
				break
			}
			body = append(body, "  "+bodySt.Render(midTrunc(c, 76)))
		}
		return v.confirmScreen("Remove "+ansi.Truncate(name, 50, "…")+"?", body, "remove", v.err)
	case 2:
		return v.running(title, "Removing "+name)
	}
	return v.doneScreen("Team member removed", [][2]string{{"member", name}}, "Rotate their credentials at the source services.", "")
}
