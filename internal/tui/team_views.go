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

	tea "github.com/charmbracelet/bubbletea"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/admininvite"
	"github.com/fray/dop/internal/capability"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

// ---------- Revoke token ----------

type revokeView struct {
	client *admin.Client
	paths  *config.Paths

	step         int // 0 = list, 1 = confirm, 2 = running
	loaded       bool
	loadErr      string
	items        []revokeItem
	cursor       int
	err          string
	flash        string
	done         bool
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
			return revokeLoadedMsg{err: renderNoVault("tokens")}
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
	switch mm := msg.(type) {
	case revokeLoadedMsg:
		v.loaded = true
		v.items = mm.items
		v.loadErr = mm.err
	case revokeResultMsg:
		if mm.err != "" {
			v.err = mm.err
			v.step = 1
			return v, nil
		}
		v.flash = "revoked · synced with team"
		v.done = true
	case tea.KeyMsg:
		switch mm.String() {
		case "esc", "ctrl+c":
			v.done = true
			return v, nil
		}
		if !v.loaded {
			return v, nil
		}
		switch v.step {
		case 0:
			switch mm.String() {
			case "up", "k":
				if v.cursor > 0 {
					v.cursor--
				}
			case "down", "j":
				if v.cursor < len(v.items)-1 {
					v.cursor++
				}
			case "enter":
				if len(v.items) == 0 {
					return v, nil
				}
				v.step = 1
			}
		case 1:
			switch mm.String() {
			case "y", "Y", "enter":
				v.step = 2
				return v, v.doRevoke()
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
	var b strings.Builder
	b.WriteString(titleSt.Render("Revoke token") + "\n\n")
	if !v.loaded {
		b.WriteString("loading…")
		return b.String()
	}
	if v.loadErr != "" {
		b.WriteString(failSt.Render(v.loadErr))
		b.WriteString("\n\n" + helpSt.Render("any key to go back"))
		return b.String()
	}
	if len(v.items) == 0 {
		b.WriteString(mutedSt.Render("(no active capabilities to revoke)"))
		b.WriteString("\n\n" + helpSt.Render("esc back"))
		return b.String()
	}
	switch v.step {
	case 0:
		b.WriteString("Pick a capability to revoke:\n\n")
		for i, it := range v.items {
			prefix := "  "
			if i == v.cursor {
				prefix = cursorSt.Render("➤ ")
			}
			b.WriteString(prefix + it.subject + mutedSt.Render(" ("+it.capID[:12]+")") + "\n")
		}
		b.WriteString("\n" + helpSt.Render("↑↓ move | enter revoke | esc cancel"))
	case 1:
		it := v.items[v.cursor]
		b.WriteString(fmt.Sprintf("Revoke %q?\n", it.subject))
		b.WriteString(mutedSt.Render("This deletes the bundle and bumps its generation.") + "\n\n")
		if v.err != "" {
			b.WriteString(failSt.Render(v.err) + "\n\n")
		}
		b.WriteString(helpSt.Render("y/enter confirm | n/esc cancel"))
	case 2:
		b.WriteString("revoking…\n")
	}
	return b.String()
}

// ---------- Team add-key ----------

type teamAddView struct {
	client *admin.Client
	paths  *config.Paths

	step   int
	nameBuf strings.Builder
	pubBuf  strings.Builder
	edBuf   strings.Builder
	noteBuf strings.Builder
	err     string
	flash   string
	done    bool
}

func newTeamAddView(c *admin.Client, p *config.Paths) *teamAddView {
	return &teamAddView{client: c, paths: p}
}
func (v *teamAddView) Init() tea.Cmd { return nil }
func (v *teamAddView) Done() bool    { return v.done }
func (v *teamAddView) Flash() string { return v.flash }

type teamAddResultMsg struct{ err string }

func (v *teamAddView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch mm := msg.(type) {
	case teamAddResultMsg:
		if mm.err != "" {
			v.err = mm.err
			v.step = 3
			return v, nil
		}
		v.flash = "team member added · synced with team"
		v.done = true
	case tea.KeyMsg:
		switch mm.String() {
		case "esc", "ctrl+c":
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
			if len(mm.Runes) > 0 {
				v.currentBuf().WriteString(string(mm.Runes))
			}
		}
	}
	return v, nil
}

func (v *teamAddView) currentBuf() *strings.Builder {
	switch v.step {
	case 0:
		return &v.nameBuf
	case 1:
		return &v.pubBuf
	case 2:
		return &v.edBuf
	case 3:
		return &v.noteBuf
	}
	return &strings.Builder{}
}

func (v *teamAddView) advance() (tea.Model, tea.Cmd) {
	switch v.step {
	case 0:
		if strings.TrimSpace(v.nameBuf.String()) == "" {
			v.err = "name required"
			return v, nil
		}
		v.err = ""
		v.step = 1
	case 1:
		pk := strings.TrimSpace(v.pubBuf.String())
		if !strings.HasPrefix(pk, "age1") {
			v.err = "must be an age recipient (age1...)"
			return v, nil
		}
		v.err = ""
		v.step = 2
	case 2:
		v.step = 3
	case 3:
		return v, v.save()
	}
	return v, nil
}

func (v *teamAddView) save() tea.Cmd {
	name := strings.TrimSpace(v.nameBuf.String())
	pub := strings.TrimSpace(v.pubBuf.String())
	ed := strings.TrimSpace(v.edBuf.String())
	note := strings.TrimSpace(v.noteBuf.String())
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
	var b strings.Builder
	b.WriteString(titleSt.Render("Add team member") + "\n\n")
	labels := []string{"Name", "Age pubkey (age1...)", "Ed25519 pubkey (optional)", "Note (optional)"}
	values := []string{v.nameBuf.String(), v.pubBuf.String(), v.edBuf.String(), v.noteBuf.String()}
	for i, l := range labels {
		style := mutedSt
		if i == v.step {
			style = cursorSt
		}
		b.WriteString(style.Render(l) + ": ")
		b.WriteString(values[i])
		if i == v.step {
			b.WriteString(cursorSt.Render("▎"))
		}
		b.WriteString("\n")
	}
	if v.err != "" {
		b.WriteString("\n" + failSt.Render(v.err) + "\n")
	}
	b.WriteString("\n" + helpSt.Render("enter next | esc cancel"))
	return b.String()
}

// ---------- Team list ----------

// rc7m — Team list grows a Members / Pending tab toggle. Pending shows
// open admin invites with a delete action (shells out to the new
// `dop team cancel-invite <id>` subcommand).
const (
	teamTabMembers = 0
	teamTabPending = 1
)

const (
	teamModeList         = 0
	teamModeConfirm      = 1 // confirm "delete pending invite?" y/n
	teamModeRunning      = 2 // subprocess in flight
	teamModeDoneFlash    = 3
	teamModeApprovePass  = 4 // rc7o — approval passphrase input for approve-invite
	teamModeApproveRun   = 5 // rc7o — approve subprocess in flight
)

type teamListView struct {
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

	// rc7o — approve-invite state. passBuf collects the operator's
	// approval passphrase (masked); pendingApproveID tracks which
	// invite the running subprocess is approving.
	pendingApproveID string
	passBuf          strings.Builder

	done bool
}

func newTeamListView(c *admin.Client, p *config.Paths) *teamListView {
	return &teamListView{client: c, paths: p}
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
	// rc7m — also load pending invites. Best-effort: a missing /
	// unreadable pending-admin-invites dir is normal on fresh installs,
	// just means "no pending invites."
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
	case teamCancelDoneMsg:
		if mm.err != "" {
			v.actionErr = mm.err
			v.mode = teamModeDoneFlash
			return v, nil
		}
		v.actionFlash = "pending invite " + mm.id[:8] + " cancelled"
		v.mode = teamModeList
		// Reload so the pending list reflects the deletion.
		v.loaded = false
		return v, v.load
	case teamApproveDoneMsg:
		// rc7o — reply from approve-invite subprocess.
		if mm.err != "" {
			v.actionErr = mm.err
			v.mode = teamModeDoneFlash
			return v, nil
		}
		v.actionFlash = "invite " + mm.id[:8] + " approved — teammate is now an admin"
		v.mode = teamModeList
		v.loaded = false
		return v, v.load
	case tea.KeyMsg:
		return v.handleKey(mm)
	}
	return v, nil
}

func (v *teamListView) handleKey(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	if !v.loaded {
		return v, nil
	}
	switch v.mode {
	case teamModeConfirm:
		switch mm.String() {
		case "y", "enter":
			v.mode = teamModeRunning
			return v, v.cancelInvite(v.pendingDeleteID)
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
			v.passBuf.Reset()
			return v, nil
		case "enter":
			if v.passBuf.Len() == 0 {
				v.actionErr = "approval passphrase required"
				return v, nil
			}
			v.actionErr = ""
			v.mode = teamModeApproveRun
			return v, v.approveInvite(v.pendingApproveID, v.passBuf.String())
		case "backspace":
			s := v.passBuf.String()
			if len(s) > 0 {
				v.passBuf.Reset()
				v.passBuf.WriteString(s[:len(s)-1])
			}
		default:
			if len(mm.Runes) > 0 {
				v.passBuf.WriteString(string(mm.Runes))
			}
		}
		return v, nil
	case teamModeRunning, teamModeApproveRun:
		return v, nil
	case teamModeDoneFlash:
		if mm.String() != "" {
			v.mode = teamModeList
			v.actionErr = ""
			v.actionFlash = ""
		}
		return v, nil
	}
	// list mode
	switch mm.String() {
	case "esc", "q", "ctrl+c", "backspace":
		v.done = true
	case "tab":
		v.tab = (v.tab + 1) % 2
		v.cursor = 0
	case "1":
		v.tab = teamTabMembers
		v.cursor = 0
	case "2":
		v.tab = teamTabPending
		v.cursor = 0
	case "up", "k":
		if v.cursor > 0 {
			v.cursor--
		}
	case "down", "j":
		n := v.rowCount()
		if n > 0 && v.cursor < n-1 {
			v.cursor++
		}
	case "d":
		if v.tab == teamTabPending && v.cursor < len(v.pending) {
			v.pendingDeleteID = v.pending[v.cursor].InviteID
			v.mode = teamModeConfirm
		}
	case "a":
		// rc7o — approve a pending invite. Opens the approval
		// passphrase prompt; on enter, shells out to `dop team
		// approve-invite <id> --passphrase-stdin`.
		if v.tab == teamTabPending && v.cursor < len(v.pending) {
			inv := v.pending[v.cursor]
			if inv.ShareIdentity {
				// Shared-identity: nothing to approve on this side.
				v.actionFlash = "shared-identity invite — nothing to approve; join completes on teammate's machine"
				return v, nil
			}
			v.pendingApproveID = inv.InviteID
			v.passBuf.Reset()
			v.actionErr = ""
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

func (v *teamListView) View() string {
	var b strings.Builder
	// Tab bar.
	membersTab := fmt.Sprintf("[1] Members (%d)", len(v.names))
	pendingTab := fmt.Sprintf("[2] Pending (%d)", len(v.pending))
	if v.tab == teamTabMembers {
		membersTab = cursorSt.Render(membersTab)
		pendingTab = mutedSt.Render(pendingTab)
	} else {
		membersTab = mutedSt.Render(membersTab)
		pendingTab = cursorSt.Render(pendingTab)
	}
	b.WriteString(titleSt.Render("Team") + "   " + membersTab + "   " + pendingTab + "\n\n")

	if !v.loaded {
		b.WriteString("loading…")
		return b.String()
	}
	if v.loadErr != "" {
		b.WriteString(failSt.Render(v.loadErr) + "\n\n")
		b.WriteString(helpSt.Render("esc back"))
		return b.String()
	}
	if v.mode == teamModeConfirm {
		id := v.pendingDeleteID
		if len(id) >= 8 {
			id = id[:8]
		}
		b.WriteString(failSt.Render("Cancel pending invite "+id+"?") + "\n")
		b.WriteString(mutedSt.Render("  the invite file and identity-blob (if any) will be removed from the vault + pushed.") + "\n\n")
		b.WriteString(helpSt.Render("y/enter confirm · n/esc cancel"))
		return b.String()
	}
	if v.mode == teamModeApprovePass {
		id := v.pendingApproveID
		if len(id) >= 8 {
			id = id[:8]
		}
		b.WriteString(cursorSt.Render("Approve invite "+id) + "\n")
		b.WriteString(mutedSt.Render("  pulls vault, reads teammate's response, verifies, adds admin, pushes.") + "\n\n")
		b.WriteString("Approval passphrase: " + strings.Repeat("•", v.passBuf.Len()) + cursorSt.Render("▎") + "\n")
		if v.actionErr != "" {
			b.WriteString("\n" + failSt.Render(v.actionErr) + "\n")
		}
		b.WriteString("\n" + helpSt.Render("enter approve · esc cancel"))
		return b.String()
	}
	if v.mode == teamModeRunning {
		b.WriteString(mutedSt.Render("cancelling pending invite…"))
		return b.String()
	}
	if v.mode == teamModeApproveRun {
		b.WriteString(mutedSt.Render("approving invite… (pulling vault, verifying response, pushing)"))
		return b.String()
	}
	if v.mode == teamModeDoneFlash {
		if v.actionErr != "" {
			b.WriteString(failSt.Render("✗ cancel failed: "+v.actionErr) + "\n")
		}
		b.WriteString("\n" + helpSt.Render("any key to continue"))
		return b.String()
	}
	switch v.tab {
	case teamTabMembers:
		b.WriteString(v.viewMembers())
	case teamTabPending:
		b.WriteString(v.viewPending())
	}
	if v.actionFlash != "" {
		b.WriteString("\n" + okSt.Render(v.actionFlash) + "\n")
	}
	return b.String()
}

func (v *teamListView) viewMembers() string {
	var b strings.Builder
	if len(v.names) == 0 {
		b.WriteString(mutedSt.Render("(no admins yet)") + "\n")
	}
	for i, n := range v.names {
		a := v.admins[n]
		note := a.Note
		if note == "" {
			note = "-"
		}
		prefix := "    "
		nameSt := mutedSt
		if i == v.cursor {
			prefix = "  " + cursorSt.Render("➤ ")
			nameSt = cursorSt
		}
		b.WriteString(prefix + nameSt.Render(n) + "\n")
		b.WriteString("      age:     " + a.AgeRecipient + "\n")
		b.WriteString("      ed25519: " + a.Ed25519Pubkey + "\n")
		b.WriteString("      note:    " + note + "\n")
	}
	b.WriteString("\n" + mutedSt.Render("Distinct admin identities. Devices invited with 'same identity' share one entry.") + "\n")
	b.WriteString("\n" + helpSt.Render("tab switch · ↑↓ move · esc back"))
	return b.String()
}

func (v *teamListView) viewPending() string {
	var b strings.Builder
	if len(v.pending) == 0 {
		b.WriteString(mutedSt.Render("(no pending invites)") + "\n")
		b.WriteString(mutedSt.Render("Open one with Add → Device or Add → Team member.") + "\n")
		b.WriteString("\n" + helpSt.Render("tab switch · esc back"))
		return b.String()
	}
	now := timeNow()
	for i, inv := range v.pending {
		prefix := "    "
		idSt := mutedSt
		if i == v.cursor {
			prefix = "  " + cursorSt.Render("➤ ")
			idSt = cursorSt
		}
		// Status: expired / valid / invite kind
		status := "valid"
		remaining := inv.ExpiresAt.Sub(now)
		if remaining <= 0 {
			status = failSt.Render("EXPIRED")
		} else {
			status = mutedSt.Render(humanDuration(remaining) + " left")
		}
		kind := "device"
		if inv.Kind == "team_member" {
			kind = "team member"
		}
		if inv.ShareIdentity {
			kind += " · same-identity"
		}
		// rc7o — "response ready" marker when the teammate's response
		// file is present. Operator presses `a` on a ready row to
		// complete the invite.
		readyBadge := ""
		if !inv.ShareIdentity {
			if _, err := admininvite.ReadResponse(v.paths, inv.InviteID); err == nil {
				readyBadge = "  " + okSt.Render("✓ ready to approve")
			}
		}
		b.WriteString(prefix + idSt.Render(inv.InviteID[:8]) + "  " + inv.Name + "   " + status + readyBadge + "\n")
		b.WriteString("      kind:       " + kind + "\n")
		b.WriteString("      created:   " + inv.CreatedAt.Format(timeFmt) + "\n")
		b.WriteString("      expires:   " + inv.ExpiresAt.Format(timeFmt) + "\n")
	}
	b.WriteString("\n" + helpSt.Render("tab switch · ↑↓ move · a approve selected · d delete selected · esc back"))
	return b.String()
}

const timeFmt = "2006-01-02 15:04"

func timeNow() time.Time { return time.Now().UTC() }

func humanDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}

// ---------- Team remove ----------

type teamRemoveView struct {
	client  *admin.Client
	paths   *config.Paths
	loaded  bool
	loadErr string
	names   []string
	cursor  int
	step    int // 0 = pick, 1 = show rotation checklist + confirm, 2 = running
	err     string
	flash   string
	done    bool
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
	names := make([]string, 0, len(vlt.Admins))
	for n := range vlt.Admins {
		names = append(names, n)
	}
	sort.Strings(names)
	// Build the checklist once — same for any removal target.
	var cl []string
	for iname, integ := range vlt.Integrations {
		for tname, tok := range integ.Tokens {
			cl = append(cl, fmt.Sprintf("%s.tokens.%s (%s)", iname, tname, tok.ScopeNote))
		}
	}
	sort.Strings(cl)
	return teamRemoveLoadedMsg{names: names, checklist: cl}
}

func (v *teamRemoveView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch mm := msg.(type) {
	case teamRemoveLoadedMsg:
		v.loaded = true
		v.names = mm.names
		v.checklist = mm.checklist
		v.loadErr = mm.err
	case teamRemoveResultMsg:
		if mm.err != "" {
			v.err = mm.err
			v.step = 1
			return v, nil
		}
		v.flash = "team member removed · synced with team"
		v.done = true
	case tea.KeyMsg:
		switch mm.String() {
		case "esc", "ctrl+c":
			v.done = true
			return v, nil
		}
		if !v.loaded {
			return v, nil
		}
		switch v.step {
		case 0:
			switch mm.String() {
			case "up", "k":
				if v.cursor > 0 {
					v.cursor--
				}
			case "down", "j":
				if v.cursor < len(v.names)-1 {
					v.cursor++
				}
			case "enter":
				if len(v.names) == 0 {
					return v, nil
				}
				v.step = 1
			}
		case 1:
			// v1.13.0-rc6 — unified confirm keybindings.
			switch mm.String() {
			case "y", "Y", "enter":
				v.step = 2
				return v, v.doRemove()
			case "n", "N", "esc":
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
	var b strings.Builder
	b.WriteString(titleSt.Render("Remove team member") + "\n\n")
	if !v.loaded {
		b.WriteString("loading…")
		return b.String()
	}
	if v.loadErr != "" {
		b.WriteString(failSt.Render(v.loadErr) + "\n\n")
		b.WriteString(helpSt.Render("any key to go back"))
		return b.String()
	}
	if len(v.names) == 0 {
		b.WriteString(mutedSt.Render("(no admins to remove)") + "\n\n")
		b.WriteString(helpSt.Render("esc back"))
		return b.String()
	}
	switch v.step {
	case 0:
		b.WriteString("Pick admin to remove:\n\n")
		for i, n := range v.names {
			prefix := "  "
			if i == v.cursor {
				prefix = cursorSt.Render("➤ ")
			}
			b.WriteString(prefix + n + "\n")
		}
		b.WriteString("\n" + helpSt.Render("↑↓ move | enter next | esc cancel"))
	case 1:
		b.WriteString(failSt.Render("⚠  ROTATION REQUIRED") + "\n\n")
		b.WriteString(fmt.Sprintf("You're removing %s. Any cached copy of the vault they cloned before\n", v.names[v.cursor]))
		b.WriteString("removal is still decryptable with their old age key.\n\n")
		b.WriteString("Rotate these upstream tokens NOW at the source service, then update\n")
		b.WriteString("them via `dop integration add`:\n\n")
		if len(v.checklist) == 0 {
			b.WriteString(mutedSt.Render("  (no integrations yet — nothing to rotate)") + "\n")
		}
		for _, it := range v.checklist {
			b.WriteString("  - " + it + "\n")
		}
		if v.err != "" {
			b.WriteString("\n" + failSt.Render(v.err) + "\n")
		}
		b.WriteString("\n" + helpSt.Render("y/enter confirm removal | n/esc cancel"))
	case 2:
		b.WriteString("removing…\n")
	}
	return b.String()
}
