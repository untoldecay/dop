// Sub-views. Kept in one file to hold the surface area small.

package tui

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
	"gopkg.in/yaml.v3"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/capability"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

// ---------- Status ----------

type statusView struct {
	wiz
	client *admin.Client
	done   bool
}

func newStatusView(c *admin.Client) *statusView { return &statusView{client: c} }
func (v *statusView) Init() tea.Cmd             { return nil }
func (v *statusView) Done() bool                { return v.done }
func (v *statusView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if ok, cmd := v.wizMsg(msg, false); ok {
		return v, cmd
	}
	if _, ok := msg.(tea.KeyMsg); ok {
		v.done = true
	}
	return v, nil
}
func (v *statusView) View() string {
	var body []string
	st, err := v.client.Status()
	errLine := ""
	if err != nil {
		errLine = "No active session. Unlock from the menu: Login."
	} else {
		body = strings.Split(strings.TrimRight(kv(
			[2]string{"admin key", midTrunc(st.AdminPubkey, 20)},
			[2]string{"age recipient", midTrunc(st.AgeRecipient, 24)},
			[2]string{"idle left", remaining(st.IdleTTLSeconds, st.LastActivityUnix)},
			[2]string{"session left", remaining(st.AbsTTLSeconds, st.StartedAtUnix)}), "\n"), "\n")
	}
	return frame(v.width, v.height, "Status", nil, "", body, status{err: errLine}.String(), footer(v.width, keyBack))
}

// remaining is the time left as 30m / 7h50m / 45s.
func remaining(ttl int64, refUnix int64) string {
	return shortDuration(timeLeft(ttl, refUnix))
}

// expiresDisplay renders a token ExpiresAt for the TUI. The CLI uses the
// year-9999 sentinel to mean --expires=never (see tokenNeverSentinel in
// cmd/dop/tokencmd.go); render that as "never" instead of "9999-12-31".
func expiresDisplay(t time.Time, layout string) string {
	if t.Year() >= 9999 {
		return "never"
	}
	return t.Format(layout)
}

// ---------- Doctor ----------

type doctorView struct {
	wiz
	paths  *config.Paths
	client *admin.Client
	done   bool
}

func newDoctorView(p *config.Paths, c *admin.Client) *doctorView {
	return &doctorView{paths: p, client: c}
}
func (v *doctorView) Init() tea.Cmd { return nil }
func (v *doctorView) Done() bool    { return v.done }
func (v *doctorView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if ok, cmd := v.wizMsg(msg, false); ok {
		return v, cmd
	}
	if _, ok := msg.(tea.KeyMsg); ok {
		v.done = true
	}
	return v, nil
}
func (v *doctorView) View() string {
	var body []string
	fix := "" // the first failing check's fix, on the status line
	line := func(glyph, name, detail, hint string) {
		g := okSt.Render(glyph)
		if glyph == "!" {
			g = dangerSt.Render(glyph)
			if fix == "" {
				fix = hint
			}
		}
		body = append(body, "  "+g+" "+bodySt.Render(padTrunc(name, 16))+mutedSt.Render(detail))
	}
	check := func(bin, hint string) {
		if _, err := exec.LookPath(bin); err != nil {
			line("!", bin, "not found", hint)
		} else {
			line("✓", bin, "", "")
		}
	}
	check("sops", "Install sops: brew install sops")
	check("git", "Install git")
	if admin.KeyFileExists(v.paths) {
		line("✓", "admin key", "admin install", "")
	} else {
		line("!", "admin key", "server install (agents only), no admin key", "Pick New setup from the menu if this machine should manage the vault.")
	}
	vp := v.paths.Vault + "/vault.yaml"
	if _, err := os.Stat(vp); err == nil {
		line("✓", "vault", midTrunc(vp, 56), "")
	} else {
		line("!", "vault", "not attached", "Attach a vault from the menu.")
	}
	if v.client.SessionActive() {
		line("✓", "admin session", "unlocked", "")
	} else {
		line("○", "admin session", "locked", "")
	}
	return frame(v.width, v.height, "Doctor", nil, "", body, status{hint: fix}.String(), footer(v.width, keyBack))
}

// ---------- Login (in-place passphrase prompt) ----------

type loginView struct {
	wiz
	paths    *config.Paths
	buf      textinput.Model
	err      string
	loading  bool
	loggedIn bool
	done     bool
	flash    string
}

func newLoginView(p *config.Paths) *loginView { return &loginView{paths: p, buf: newFormInput(true)} }
func (v *loginView) Init() tea.Cmd            { return nil }
func (v *loginView) Done() bool               { return v.done }
func (v *loginView) Flash() string            { return v.flash }

type loginResultMsg struct {
	err string
}

func (v *loginView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if ok, cmd := v.wizMsg(msg, v.buf.Value() != ""); ok {
		return v, cmd
	}
	switch mm := msg.(type) {
	case loginResultMsg:
		v.loading = false
		if mm.err != "" {
			v.err = "Login failed: " + firstLine(mm.err)
			v.buf.Reset()
		} else {
			v.loggedIn = true
			v.flash = "login: session started"
			v.done = true
		}
		return v, nil
	case tea.KeyMsg:
		if v.loading {
			return v, nil
		}
		if mm.String() != "enter" {
			v.err = ""
		}
		switch mm.String() {
		case "esc", "ctrl+c":
			v.done = true
		case "enter":
			pass := v.buf.Value()
			if pass == "" {
				v.err = "Passphrase is required"
				return v, nil
			}
			v.loading = true
			return v, tea.Batch(v.spinStart(), v.login(pass))
		default:
			edit(&v.buf, mm)
		}
	}
	return v, nil
}

func (v *loginView) login(passphrase string) tea.Cmd {
	return func() tea.Msg {
		// Shell out to `dop admin login --passphrase-stdin` so the TUI
		// doesn't need to fork/exec the session daemon itself.
		self, err := os.Executable()
		if err != nil {
			return loginResultMsg{err: err.Error()}
		}
		cmd := exec.Command(self, "admin", "login", "--passphrase-stdin")
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
		cmd.Stdin = strings.NewReader(passphrase)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return loginResultMsg{err: strings.TrimSpace(stderr.String())}
		}
		return loginResultMsg{}
	}
}

func (v *loginView) View() string {
	if v.loading {
		return v.running("Login", "Unlocking the admin session")
	}
	return v.screen("Login", "", "Admin passphrase", []string{inputRow(&v.buf)}, "", v.err, "", wizKeys("unlock"))
}

// ---------- Issue bearer ----------

// issueView — a wizard: subject → grants → expiry (→ custom) →
// portable (→ runs on) (→ approval passphrase), then the review, the
// issuing spinner and the bearer handoff.
type issueView struct {
	wiz
	client *admin.Client
	paths  *config.Paths

	step       int // issueStep*
	subject    textinput.Model
	grantsCSV  textinput.Model // free-text fallback (vault has no grants)
	pick       multiPick
	expiryCur  int
	custom     textinput.Model
	portCur    int
	runsCur    int             // runsOnPresets index; only asked when not portable
	passphrase textinput.Model // approval passphrase, only for protected grants

	issuing bool
	err     string
	bearer  string
	pin     string
	done    bool
	flash   string

	grantList []string
	grantByID map[string]tuiGrantInfo

	// allow-file-keys prefs captured at construction: the handoff text
	// and the background-reseal watcher depend on it.
	prefs       Prefs
	copied      bool   // last clipboard attempt succeeded (on result, and on c)
	leaveArmed  bool   // first esc on the bearer screen; a second esc leaves
	resealFlash string // filled by the background auto-reseal watcher
	pollCount   int    // bounded loop for the auto-reseal poller
}

const (
	issueStepSubject = iota
	issueStepGrants
	issueStepExpiry
	issueStepCustom
	issueStepPortable
	issueStepRunsOn
	issueStepPass
	issueStepReview
)

// tuiGrantInfo carries just what the picker needs from a vault.Grant
// (avoids importing vault into the picker code and keeps the render
// path cheap).
type tuiGrantInfo struct {
	Integration string
	Token       string
	Prefix      string // resolved via EffectivePrefix()
	Tags        []string
	Projects    []string
	// rc6c — carried so the issue flow can detect protected grants and
	// insert a passphrase step before shelling out. CLI's issue path
	// uses promptProtectionPassphrase which reads from a tty; without
	// --passphrase-stdin + a piped passphrase, it errors on the TUI's
	// non-tty subprocess stdin. See rc3-smoke-retakes [S2].
	Protected bool
}

// expiryPresets lists the preset expiry choices. The last entry
// reveals the custom duration input.
var expiryPresets = []struct {
	label string
	value string
	hint  string
}{
	{"72h", "72h", "3 days (default)"},
	{"7d", "7d", "one week"},
	{"30d", "30d", "one month"},
	{"365d", "365d", "one year"},
	{"never", "never", "no expiry, revoke manually"},
	{"custom…", "custom", "type a duration"},
}

// portablePresets drives the Portable step. Yes stashes an age-wrapped
// bearer on the capability so the issuing admin can later dop use
// <subject> from any of their machines.
var portablePresets = []struct {
	label string
	value bool
	hint  string
}{
	{"no", false, "bearer shown once, you copy it yourself"},
	{"yes", true, "export it again later with dop use <subject>"},
}

// runsOnPresets drives the "Runs on" step. A server (the Server entry
// of the fresh-install menu) has no admin, so the agent claims with
// --remote and the approval lands in this TUI's pending banner.
var runsOnPresets = []struct {
	label string
	value bool // remote
	hint  string
}{
	{"this machine", false, "agent claims here, you approve in this TUI"},
	{"a server", true, "agent claims with --remote, approve from the pending banner"},
}

func newIssueView(c *admin.Client, p *config.Paths) *issueView {
	v := &issueView{client: c, paths: p, prefs: LoadPrefs(p)}
	v.subject, v.grantsCSV, v.custom, v.passphrase = newFormInput(false), newFormInput(false), newFormInput(false), newFormInput(true)
	v.subject.Placeholder, v.custom.Placeholder = "claude-code-laptop", "10d"
	v.grantList, v.grantByID = loadGrantsForList(c, p)
	v.pick.items = grantPickItems(v.grantList, v.grantByID)
	return v
}

// flow is the steps the current answers lead through (review after).
func (v *issueView) flow() []int {
	s := []int{issueStepSubject, issueStepGrants, issueStepExpiry}
	if expiryPresets[v.expiryCur].value == "custom" {
		s = append(s, issueStepCustom)
	}
	s = append(s, issueStepPortable)
	if !v.portable() {
		s = append(s, issueStepRunsOn)
	}
	if v.protectedCount() > 0 {
		s = append(s, issueStepPass)
	}
	return s
}

// selectedGrants — the grants the form currently holds (list or CSV).
func (v *issueView) selectedGrants() []string {
	if len(v.grantList) > 0 {
		return v.pick.picked()
	}
	var out []string
	for _, g := range strings.Split(v.grantsCSV.Value(), ",") {
		if g = strings.TrimSpace(g); g != "" {
			out = append(out, g)
		}
	}
	return out
}

func (v *issueView) expiryValue() string {
	if p := expiryPresets[v.expiryCur].value; p != "custom" {
		return p
	}
	return strings.TrimSpace(v.custom.Value())
}

func (v *issueView) portable() bool { return portablePresets[v.portCur].value }
func (v *issueView) remote() bool   { return !v.portable() && runsOnPresets[v.runsCur].value }

// collidingPrefixes returns prefix → grant-IDs when two or more of sel
// share the same env prefix.
func (v *issueView) collidingPrefixes(sel []string) map[string][]string {
	byPrefix := map[string][]string{}
	for _, gid := range sel {
		if info, ok := v.grantByID[gid]; ok {
			byPrefix[info.Prefix] = append(byPrefix[info.Prefix], gid)
		}
	}
	out := map[string][]string{}
	for p, ids := range byPrefix {
		if len(ids) > 1 {
			sort.Strings(ids)
			out[p] = ids
		}
	}
	return out
}

// collision is the status-line error for the selection's first env
// prefix collision, and the rows to mark with !.
func (v *issueView) collision() (string, map[string]bool) {
	c := v.collidingPrefixes(v.selectedGrants())
	if len(c) == 0 {
		return "", nil
	}
	var ps []string
	bad := map[string]bool{}
	for p, ids := range c {
		ps = append(ps, p+" is used by "+strings.Join(ids, ", "))
		for _, id := range ids {
			bad[id] = true
		}
	}
	sort.Strings(ps)
	return ps[0] + ": deselect one", bad
}

// rc6c — count protected grants in the current selection. Non-zero
// → the approval passphrase step is shown (rc3-smoke-retakes [S2]).
func (v *issueView) protectedCount() int {
	n := 0
	for _, id := range v.selectedGrants() {
		if v.grantByID[id].Protected {
			n++
		}
	}
	return n
}

// kv renders label/value rows with the add-integration form's column
// alignment.
func kv(rows ...[2]string) string {
	lw := 0
	for _, r := range rows {
		lw = max(lw, lipgloss.Width(r[0]))
	}
	var b strings.Builder
	for _, r := range rows {
		b.WriteString("  " + mutedSt.Render(r[0]) + strings.Repeat(" ", lw-lipgloss.Width(r[0])+2) + r[1] + "\n")
	}
	return b.String()
}

func (v *issueView) summaryRows() [][2]string {
	portable := "no"
	if v.portable() {
		portable = "yes"
	}
	rows := [][2]string{
		{"subject", strings.TrimSpace(v.subject.Value())},
		{"grants", strings.Join(v.selectedGrants(), ", ")},
		{"expires", v.expiryValue()},
		{"portable", portable},
	}
	if !v.portable() {
		rows = append(rows, [2]string{"runs on", runsOnPresets[v.runsCur].label})
	}
	return rows
}

func (v *issueView) Init() tea.Cmd { return nil }
func (v *issueView) Done() bool    { return v.done }
func (v *issueView) Flash() string { return v.flash }

type issueResultMsg struct {
	bearer string
	pin    string
	err    string
}

// input is the current step's text input (nil on pickers).
func (v *issueView) input() *textinput.Model {
	switch v.step {
	case issueStepSubject:
		return &v.subject
	case issueStepGrants:
		if len(v.grantList) == 0 {
			return &v.grantsCSV
		}
	case issueStepCustom:
		return &v.custom
	case issueStepPass:
		return &v.passphrase
	}
	return nil
}

func (v *issueView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if _, ok := msg.(spinner.TickMsg); ok && !v.issuing {
		return v, nil
	}
	in := v.input()
	if ok, cmd := v.wizMsg(msg, in != nil && in.Value() != "" && v.bearer == ""); ok {
		return v, cmd
	}
	switch mm := msg.(type) {
	case issueResultMsg:
		v.issuing = false
		if mm.err != "" {
			v.err, v.step = firstLine(mm.err), issueStepReview
			return v, nil
		}
		v.bearer, v.pin = mm.bearer, mm.pin
		// Copy once here, not in View (which repaints on every msg).
		v.copied = clipboardCopy(v.handoff())
		// allow-file-keys: watch the record for the claim, then reseal.
		// Not for a server: approve-remote seals at approval time.
		if v.prefs.AllowFileKeys && v.pin != "" && !v.remote() {
			return v, v.watchForClaimAndReseal()
		}
		return v, nil
	case autoResealTickMsg:
		if v.resealFlash != "" || v.done {
			return v, nil
		}
		return v, v.watchForClaimAndReseal()
	case autoResealDoneMsg:
		v.resealFlash = mm.msg
		return v, nil
	case tea.KeyMsg:
		k := mm.String()
		switch {
		case v.issuing:
			return v, nil
		case v.bearer != "":
			return v.bearerKey(k)
		case k == "ctrl+c":
			v.done = true
			return v, nil
		}
		if k != "enter" {
			v.err = ""
		}
		fl := v.flow()
		i := stepPos(fl, v.step)
		switch k {
		case "enter":
			return v.advance()
		case "esc", "shift+tab":
			if wizBack(mm, &i) < 0 {
				v.done = true
			} else {
				v.step = fl[i]
			}
			return v, nil
		}
		switch {
		case v.step == issueStepGrants && in == nil:
			v.pick.key(k)
		case v.step == issueStepExpiry && (k == "up" || k == "down"):
			stepCursor(&v.expiryCur, len(expiryPresets), map[string]int{"up": -1, "down": 1}[k])
		case v.step == issueStepPortable && (k == "up" || k == "down"):
			stepCursor(&v.portCur, len(portablePresets), map[string]int{"up": -1, "down": 1}[k])
		case v.step == issueStepRunsOn && (k == "up" || k == "down"):
			stepCursor(&v.runsCur, len(runsOnPresets), map[string]int{"up": -1, "down": 1}[k])
		case in != nil:
			edit(in, mm)
		}
	}
	return v, nil
}

// advance validates the current step, then moves on (or issues from
// the review).
func (v *issueView) advance() (tea.Model, tea.Cmd) {
	switch v.step {
	case issueStepReview:
		if cmd := v.locked(tea.KeyMsg{Type: tea.KeyEnter}, &v.err); cmd != nil {
			return v, cmd
		}
		v.issuing, v.err = true, ""
		return v, tea.Batch(v.spinStart(), v.issue())
	case issueStepGrants:
		if len(v.selectedGrants()) == 0 {
			v.err = "Select at least one grant (space toggles)"
			return v, nil
		}
		if e, _ := v.collision(); e != "" {
			v.err = e
			return v, nil
		}
	default:
		if in := v.input(); in != nil && strings.TrimSpace(in.Value()) == "" {
			v.err = map[int]string{issueStepSubject: "Subject", issueStepCustom: "Duration",
				issueStepPass: "Approval passphrase"}[v.step] + " is required"
			return v, nil
		}
	}
	v.err = ""
	fl := v.flow()
	if i := stepPos(fl, v.step) + 1; i < len(fl) {
		v.step = fl[i]
	} else {
		v.step = issueStepReview
	}
	return v, nil
}

// autoResealTickMsg triggers a vault re-read to check for a completed
// claim. Scheduled on a 2-second cadence after issue when the
// allow-file-keys toggle is on. Stops firing once the first reseal
// lands (resealFlash set) or the view is dismissed.
type autoResealTickMsg struct{}

// autoResealDoneMsg carries the final flash message once the auto-
// reseal finished (either successfully, or with a terminal error).
type autoResealDoneMsg struct{ msg string }

// watchForClaimAndReseal is scheduled from Update when the issue
// succeeds and allow-file-keys is on. It reads the vault once, and
// either (a) sees the agent's pubkey filled in on the just-issued
// binding — in which case it fires reseal and emits the success
// flash, or (b) doesn't yet — reschedules itself in 2 seconds.
//
// After ~90 seconds total (45 ticks) we give up quietly so the
// bubbletea runtime doesn't spin forever if the agent never claimed.
func (v *issueView) watchForClaimAndReseal() tea.Cmd {
	subject := strings.TrimSpace(v.subject.Value())
	paths := v.paths
	client := v.client
	// Give up after ~90s to bound the lifetime of the goroutine.
	if v.pollCount >= 45 {
		return func() tea.Msg {
			return autoResealDoneMsg{msg: "auto-reseal timed out — run `dop token reseal " + subject + "` manually after the agent claims"}
		}
	}
	v.pollCount++
	return tea.Tick(2*time.Second, func(_ time.Time) tea.Msg {
		vlt, _, err := loadVaultForListing(client, paths)
		if err != nil {
			// Transient — just reschedule.
			return autoResealTickMsg{}
		}
		// Find the capability we just issued (match by subject +
		// active status + pubkey filled). If none yet claimed, keep
		// polling.
		for _, c := range vlt.Capabilities {
			if c.Status != "active" || c.Subject != subject {
				continue
			}
			if c.Binding == nil || c.Binding.Pubkey == "" {
				continue
			}
			// Claim completed. Run reseal.
			self, _ := os.Executable()
			cmd := exec.Command(self, "token", "reseal", c.LookupID[:12])
			cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			if err := cmd.Run(); err != nil {
				return autoResealDoneMsg{msg: "auto-reseal failed: " + strings.TrimSpace(stderr.String())}
			}
			return autoResealDoneMsg{msg: "✓ auto-resealed — add-grant / remove-grant / rotate ready for `" + subject + "`"}
		}
		return autoResealTickMsg{}
	})
}

func (v *issueView) issue() tea.Cmd {
	name := strings.TrimSpace(v.subject.Value())
	grants := strings.Join(v.selectedGrants(), ",")
	expires := v.expiryValue()
	if expires == "" {
		expires = "72h"
	}
	prefs := v.prefs
	portable := v.portable()
	// rc6c — pipe protected-grant passphrase when any grant is protected.
	protectedPass := v.passphrase.Value()
	needsPass := v.protectedCount() > 0
	return func() tea.Msg {
		self, err := os.Executable()
		if err != nil {
			return issueResultMsg{err: err.Error()}
		}
		args := []string{"token", "issue", "--grants", grants, "--name", name, "--expires", expires}
		if portable {
			args = append(args, "--portable")
		}
		if needsPass {
			args = append(args, "--passphrase-stdin")
		}
		cmd := exec.Command(self, args...)
		cmdEnv := append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
		// v1.13 — when the prefs toggle is on, flow DOP_ALLOW_FILE_KEYS
		// through so the agent's claim can land a P-256 file-backed
		// key (prereq for `token reseal` + direct availability).
		if prefs.AllowFileKeys {
			cmdEnv = append(cmdEnv, "DOP_ALLOW_FILE_KEYS=1")
		}
		cmd.Env = cmdEnv
		if needsPass {
			cmd.Stdin = strings.NewReader(protectedPass + "\n")
		}
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return issueResultMsg{err: strings.TrimSpace(stderr.String())}
		}
		return parseIssueOut(stdout.String())
	}
}

// parseIssueOut reads dop token issue's stdout (also token portable --on
// for an unclaimed bearer): bearer on line 1, PIN on line 2 when PIN-bound.
func parseIssueOut(stdout string) issueResultMsg {
	var r issueResultMsg
	for _, ln := range strings.Split(strings.TrimSpace(stdout), "\n") {
		ln = strings.TrimSpace(ln)
		switch {
		case strings.HasPrefix(ln, "tok_"):
			r.bearer = ln
		case looksLikePIN(ln):
			r.pin = ln
		}
	}
	return r
}

// looksLikePIN matches the `XX-XX-XX` alpha PIN format.
func looksLikePIN(s string) bool {
	if len(s) != 8 || s[2] != '-' || s[5] != '-' {
		return false
	}
	for i, c := range s {
		if i == 2 || i == 5 {
			continue
		}
		if c < 'A' || c > 'Z' {
			return false
		}
	}
	return true
}

// handoff is the clipboard text for the agent (contract 13 shape).
func (v *issueView) handoff() string {
	return bearerHandoff(v.bearer, v.pin, v.prefs.AllowFileKeys, v.remote())
}

// bearerKey handles the one-time bearer screen: a stray key must not
// lose the bearer. enter leaves, esc needs a second press, c re-copies,
// anything else is ignored (and disarms esc).
func (v *issueView) bearerKey(k string) (tea.Model, tea.Cmd) {
	if !onceKey(k, &v.leaveArmed, &v.copied, v.handoff()) {
		return v, nil
	}
	v.done = true
	v.flash = "bearer issued · shown once, make sure it was copied"
	return v, nil
}

func (v *issueView) View() string {
	const title = "Issue bearer"
	subject := strings.TrimSpace(v.subject.Value())
	switch {
	case v.bearer != "":
		cmd := "export DOP_TOKEN=" + v.bearer
		if v.pin != "" {
			h := strings.Split(v.handoff(), "\n")
			cmd = "run " + strings.TrimSpace(h[len(h)-1])
		}
		after := useGuidance(v.prefs.Harness, subject, v.portable(), cmd)
		switch {
		case v.remote():
			after = append(after, "The claim lands in this TUI's pending banner; approve it there.")
		case v.prefs.AllowFileKeys && v.pin != "" && !v.portable():
			after = append(after, displayOr(v.resealFlash, "Auto-reseal runs once the agent claims."))
		}
		return onceScreen(v.width, v.height, "✓ Bearer issued", subject, v.bearer, v.pin, after, v.leaveArmed, v.copied)
	case v.issuing:
		return v.running(title, "Issuing a bearer for "+subject)
	case v.step == issueStepReview:
		return v.review(title, "Issue this bearer?", v.summaryRows(), "issue", false, v.err)
	}
	fl := v.flow()
	ctr := counter(stepPos(fl, v.step), len(fl))
	km := wizKeys("next")
	var prompt, helper, hintTxt string
	var input []string
	switch v.step {
	case issueStepSubject:
		prompt, input = "Subject", []string{inputRow(&v.subject)}
	case issueStepGrants:
		prompt = "Grants for " + subject
		if len(v.grantList) == 0 {
			input, helper = []string{inputRow(&v.grantsCSV)}, "No grants in the vault yet: type them comma-separated."
			break
		}
		km = wizKeys("next", keySpace, hint("ctrl+a", "all"), hint("n", "none"))
		km.short = []key.Binding{hint("space", "toggle"), hint("enter", "next"), keyBack}
		e, bad := v.collision()
		input = v.pick.rows(v.width, frameRows(v.height)-2, bad)
		hintTxt = fmt.Sprintf("%d selected", len(v.selectedGrants()))
		if v.err == "" && e != "" {
			return v.screen(title, ctr, prompt, input, "", e, "", km)
		}
	case issueStepExpiry:
		var o [][2]string
		for _, p := range expiryPresets {
			o = append(o, [2]string{p.label, p.hint})
		}
		prompt, input = "Expires", optRows(o, v.expiryCur)
	case issueStepCustom:
		prompt, input, helper = "Custom expiry", []string{inputRow(&v.custom)}, "A duration: 30m, 2h, 7d."
	case issueStepPortable:
		var o [][2]string
		for _, p := range portablePresets {
			o = append(o, [2]string{p.label, p.hint})
		}
		prompt, input = "Portable", optRows(o, v.portCur)
	case issueStepRunsOn:
		var o [][2]string
		for _, p := range runsOnPresets {
			o = append(o, [2]string{p.label, p.hint})
		}
		prompt, input = "Runs on", optRows(o, v.runsCur)
	case issueStepPass:
		prompt, input, helper = "Approval passphrase", []string{inputRow(&v.passphrase)}, "The selection includes protected grants."
	}
	return v.screen(title, ctr, prompt, input, helper, v.err, hintTxt, km)
}

func toGrantInfo(g vault.Grant) tuiGrantInfo {
	return tuiGrantInfo{Integration: g.Integration, Token: g.Token, Prefix: g.EffectivePrefix(),
		Tags: append([]string(nil), g.Tags...), Projects: append([]string(nil), g.Projects...), Protected: g.Protected}
}

// loadGrantsForList — best-effort read of the vault to surface grants.
// v1.8: also returns per-project rows and an info map keyed by grant ID.
func loadGrantsForList(client *admin.Client, paths *config.Paths) ([]string, map[string]tuiGrantInfo) {
	if vaultSyncDue(paths) {
		syncVault(paths)
	}
	vp := paths.Vault + "/vault.yaml"
	raw, err := os.ReadFile(vp)
	if err != nil {
		return nil, nil
	}
	if bytes.Contains(raw, []byte("\nsops:")) || bytes.HasPrefix(raw, []byte("sops:")) {
		plain, err := client.DecryptVault(vp)
		if err != nil {
			return nil, nil
		}
		raw = plain
	}
	var v vault.Vault
	if err := yaml.Unmarshal(raw, &v); err != nil {
		return nil, nil
	}
	// Flat list — kept for the "no grants" fallback callers.
	ids := make([]string, 0, len(v.Grants))
	info := make(map[string]tuiGrantInfo, len(v.Grants))
	for id, g := range v.Grants {
		ids = append(ids, id)
		info[id] = toGrantInfo(g)
	}
	sort.Strings(ids)
	return ids, info
}

// ---------- List ----------

type listView struct {
	sessionGuard
	client       *admin.Client
	paths        *config.Paths
	loaded       bool
	loadErr      string
	capabilities []vault.Capability
	capIDs       []string
	done         bool

	// v1.14.0-rc2 — the viewing admin's pubkey, so the row renderer
	// can draw 👤 for "mine" and 🔒 for "another admin's" based on
	// each capability's IssuedBy. Set from the daemon status at load.
	viewerPubkey string

	// v1.10.0 picker state
	mode          int             // listMode*
	cursor        int             // index into visible()
	actionCursor  int             // index into currentActions()
	pendingAction string          // revoke, reseal, add, remove, repin: the action in flight
	tab           int             // listTab*: Active, Revoked, Pending (claims awaiting approval)
	pending       []pendingRow    // Pending tab rows: local PIN claims + remote claims
	pendPass      textinput.Model // approval passphrase for a pending claim
	help          bool            // ? expanded help (list + detail)
	err           string
	flash         string

	// Detail tabs (Info / Grants) and the add-grant picker; a
	// protected pick asks the approval passphrase (rc6f).
	detailTab          int // 0 Info, 1 Grants
	grantCursor        int
	vgrants            map[string]vault.Grant
	grantPick          multiPick
	grantPickPassBuf   textField
	grantPickPassPhase bool // true once protected picks required a passphrase screen

	// Repin: PIN validity picker, then "Runs on" (this machine or a
	// server → --remote in the handoff), then the portable wizard below
	// (confirm, passphrase for protected grants, new bearer + PIN).
	repinTTLCursor int
	repinStep      int // 0 PIN validity, 1 runs on
	runsCur        int // runsOnPresets index
	// Re-issue of a claimed bearer: reissueCursor picks among
	// reissueOptions(); reclaim sends `repin --reclaim` (new claim).
	reissueCursor int
	reclaim       bool

	// Portable toggle (and repin): confirm (0), passphrase (1, off always,
	// on/repin only for protected grants). on and repin re-issue: an
	// unclaimed bearer comes back as a new bearer + PIN, shown once.
	portStep   int
	portPass   textField
	portNew    string
	portPin    string
	portArmed  bool // first esc on the shown-once screen
	portCopied bool

	adminNames map[string]string // ed25519 pubkey → admin name, for "by alex"
	doneSubj   string            // subject the done screen reports on
	doneNote   string            // CLI result line for the done screen

	tbl           *table.Model // list-mode renderer; v.cursor stays the source of truth
	width, height int
}

// repinTTLPresets — common PIN validity windows offered on repin.
// v1.13.0-rc11: reordered + default moved from 5m to 1h after
// ClaudeMini field report (5m was expiring during chat back-and-forth).
var repinTTLPresets = []struct {
	label string
	value string
}{
	{"default, fits a chat back-and-forth", "1h"},
	{"CLI handoff", "5m"},
	{"", "30m"},
	{"", "4h"},
	{"", "24h"},
}

// Bearers list modes:
//
//	listModeList    ↑↓ pick, enter → detail, tab Active/Revoked, r/s/p shortcuts
//	listModeAction  detail + action list, enter → run, esc back to list
//	listModeConfirm y/n confirm revoke
//	listModeRun     subprocess in flight
//	listModeDone    ✓ outcome, any key back to the list
const (
	listTabActive  = 0
	listTabRevoked = 1
	listTabPending = 2
)

const (
	listModeList      = 0
	listModeAction    = 1
	listModeConfirm   = 2
	listModeRun       = 3
	listModeGrantPick = 5  // add-grant / remove-grant picker
	listModeRepin     = 6  // PIN validity picker
	listModeDone      = 7  // ✓ outcome (revoke, reseal, grants, repin, portable)
	listModePortable  = 8  // portable copy on/off wizard
	listModeReissue   = 9  // claimed bearer: rotate (keep key) or new claim
	listModePendPass  = 10 // Pending tab: approval passphrase for a claim
	listModePendRejct = 11 // Pending tab: confirm reject
)

func newListView(c *admin.Client, p *config.Paths) *listView {
	return &listView{client: c, paths: p, pendPass: newFormInput(true)}
}

func (v *listView) revoked() bool { return v.tab == listTabRevoked }

// pendingRowAt is the Pending tab's cursor row (zero value if none).
func (v *listView) pendingRowAt() pendingRow {
	if v.tab == listTabPending && v.cursor < len(v.pending) {
		return v.pending[v.cursor]
	}
	return pendingRow{}
}
func (v *listView) Init() tea.Cmd { return v.load }
func (v *listView) Done() bool    { return v.done }
func (v *listView) Flash() string { return v.flash }

type listLoadedMsg struct {
	capabilities []vault.Capability
	capIDs       []string
	viewerPubkey string
	adminNames   map[string]string
	grants       map[string]vault.Grant
	pending      []pendingRow
	err          string
}
type listActionMsg struct {
	err   string
	flash string // v1.13 — surfaced in the list view for non-destructive actions
}

func (v *listView) load() tea.Msg {
	if vaultSyncDue(v.paths) {
		syncVault(v.paths) // same in-view pull as loadVaultForListing
	}
	vp := v.paths.Vault + "/vault.yaml"
	raw, err := os.ReadFile(vp)
	if err != nil {
		if os.IsNotExist(err) {
			return listLoadedMsg{err: renderNoVault("bearers")}
		}
		return listLoadedMsg{err: err.Error()}
	}
	if bytes.Contains(raw, []byte("\nsops:")) || bytes.HasPrefix(raw, []byte("sops:")) {
		plain, err := v.client.DecryptVault(vp)
		if err != nil {
			if isDaemonUnreachable(err) {
				return listLoadedMsg{err: renderSessionEnded()}
			}
			return listLoadedMsg{err: friendlyDecryptError(err).Error()}
		}
		raw = plain
	}
	var vv vault.Vault
	if err := yaml.Unmarshal(raw, &vv); err != nil {
		return listLoadedMsg{err: err.Error()}
	}
	// Sort by subject for a stable picker.
	type kv struct {
		id string
		c  vault.Capability
	}
	all := make([]kv, 0, len(vv.Capabilities))
	for id, c := range vv.Capabilities {
		all = append(all, kv{id: id, c: c})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].c.Subject < all[j].c.Subject })
	caps := make([]vault.Capability, len(all))
	ids := make([]string, len(all))
	for i, k := range all {
		caps[i] = k.c
		ids[i] = k.id
	}
	// v1.14.0-rc2 — fetch the viewer's admin pubkey so the row renderer
	// can draw ownership perspective (👤 mine vs 🔒 another admin's).
	// Best-effort — if status fails for any reason, we just render
	// without the icon.
	viewerPubkey := ""
	if st, serr := v.client.Status(); serr == nil {
		viewerPubkey = st.AdminPubkey
	}
	names := map[string]string{}
	for n, a := range vv.Admins {
		names[a.Ed25519Pubkey] = n
	}
	pend, _ := pendingRows(v.paths) // best-effort, like the root banner
	return listLoadedMsg{capabilities: caps, capIDs: ids, viewerPubkey: viewerPubkey, adminNames: names, grants: vv.Grants, pending: pend}
}

// visible returns the indexes into v.capabilities that should be shown
// under the current tab (Active, or Revoked = everything not active).
func (v *listView) visible() []int {
	out := []int{}
	if v.tab == listTabPending {
		return out
	}
	for i, c := range v.capabilities {
		if (c.Status == capability.RecordStatusActive) == !v.revoked() {
			out = append(out, i)
		}
	}
	return out
}

// rowCount is what the list cursor ranges over on the current tab.
func (v *listView) rowCount() int {
	if v.tab == listTabPending {
		return len(v.pending)
	}
	return len(v.visible())
}

func (v *listView) selectedIndex() int {
	vis := v.visible()
	if v.cursor < 0 || v.cursor >= len(vis) {
		return -1
	}
	return vis[v.cursor]
}

// currentActions returns the actions allowed for the cursor's row.
func (v *listView) currentActions() []listAction {
	idx := v.selectedIndex()
	if idx < 0 {
		return nil
	}
	c := v.capabilities[idx]
	// Order matches the approved detail mock. The CLI gatekeeps reseal
	// (claimed P-256 only) with an actionable error. Repin is for
	// PIN-bound bearers the agent has not claimed yet. Grant edits live
	// on the Grants tab.
	if c.Status != capability.RecordStatusActive {
		return nil
	}
	acts := []listAction{{label: "Reseal env", key: "s", desc: "push current credential values into this bearer's env"}}
	// Re-issue: one entry for every way to get a new bearer value.
	// Unclaimed → new PIN; claimed → rotate (keep the key) or new claim.
	if c.Binding != nil && c.Binding.Kind == "pin" && c.Binding.Pubkey == "" {
		acts = append(acts, listAction{label: "Re-issue", key: "p", desc: "new bearer + new PIN, the agent has not claimed it yet"})
	} else if len(reissueOptions(c)) > 0 {
		acts = append(acts, listAction{label: "Re-issue", key: "p", desc: "new bearer value: keep the agent's key, or start a new claim"})
	}
	if c.PortableWrapped == "" {
		acts = append(acts, listAction{label: "Portable: make portable", key: "o", desc: "re-issue it so dop use works from your shells"})
	} else {
		acts = append(acts, listAction{label: "Portable: remove copy", key: "o", desc: "dop use stops working for this bearer"})
	}
	return append(acts, listAction{label: "Revoke", key: "r", destructive: true, desc: "the bearer stops working on its next exec"})
}

type listAction struct {
	label       string
	key         string
	destructive bool
	desc        string // status-line hint when highlighted
}

func (v *listView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if ok, cmd := v.unlocked(msg); ok {
		return v, cmd
	}
	switch mm := msg.(type) {
	case tea.WindowSizeMsg:
		v.width, v.height = mm.Width, mm.Height
	case listLoadedMsg:
		v.loaded = true
		v.capabilities = mm.capabilities
		v.capIDs = mm.capIDs
		v.viewerPubkey = mm.viewerPubkey
		v.adminNames = mm.adminNames
		v.vgrants = mm.grants
		v.pending = mm.pending
		v.loadErr = mm.err
		v.cursor = max(min(v.cursor, v.rowCount()-1), 0)
	case pendingResultMsg:
		if mm.err != "" {
			v.err, v.mode = firstLine(mm.err), listModeList
			if !mm.reject {
				v.mode = listModePendPass
				v.pendPass.Reset()
			}
			return v, nil
		}
		v.mode, v.flash = listModeList, "Claim approved"
		if mm.reject {
			v.flash = "Claim rejected"
		}
		v.loaded = false
		return v, v.load
	case listActionMsg:
		if mm.err != "" && v.mode == listModeRun && v.pendingAction == "portable-off" {
			v.portableErr("Portable copy failed: " + cliErr(mm.err))
			return v, nil
		}
		if mm.err != "" {
			// Errors stay on the detail that caused them, in plain words.
			v.err = map[string]string{"revoke": "Revoke", "reseal": "Reseal", "rotate": "Rotate", "add": "Add grant",
				"remove": "Remove grant", "prune": "Prune"}[v.pendingAction] + " failed: " + cliErr(mm.err)
			v.mode = listModeAction
			if v.pendingAction == "prune" {
				v.mode = listModeList
			}
			v.pendingAction = ""
			return v, nil
		}
		v.doneNote = mm.flash
		v.mode = listModeDone
		return v, nil
	case issueResultMsg: // portable --on, repin
		if mm.err != "" {
			v.portableErr("Re-issue failed: " + cliErr(mm.err))
			return v, nil
		}
		v.portNew, v.portPin, v.portArmed = mm.bearer, mm.pin, false
		if v.portNew != "" {
			// Copy once here, not in View (which repaints on every msg).
			v.portCopied = clipboardCopy(v.portHandoff())
		}
		v.mode = listModeDone
		return v, nil
	case tea.KeyMsg:
		if !v.loaded || v.loadErr != "" {
			if mm.String() == "esc" || mm.String() == "ctrl+c" {
				v.done = true
			}
			return v, nil
		}
		v.flash = "" // one-shot: gone on the next key
		switch v.mode {
		case listModeList:
			if toggleHelp(&v.help, mm) {
				return v, nil
			}
			return v.updateListMode(mm)
		case listModeAction:
			if toggleHelp(&v.help, mm) {
				return v, nil
			}
			return v.updateActionMode(mm)
		case listModeConfirm:
			return v.updateConfirmMode(mm)
		case listModePendPass, listModePendRejct:
			return v.updatePendingMode(mm)
		case listModeGrantPick:
			return v.updateGrantPickMode(mm)
		case listModeRepin:
			return v.updateRepinMode(mm)
		case listModeReissue:
			return v.updateReissueMode(mm)
		case listModePortable:
			return v.updatePortableMode(mm)
		case listModeDone:
			if v.portNew != "" {
				if !onceKey(mm.String(), &v.portArmed, &v.portCopied, v.portHandoff()) {
					return v, nil
				}
			} else if mm.String() != "enter" {
				return v, nil // done screens leave on enter only
			}
			v.mode = listModeList // a re-issued bearer has a new record: back to the list
			if v.pendingAction == "portable-off" {
				v.mode = listModeAction // back to the Info tab, reloaded
			}
			v.pendingAction, v.doneNote, v.portNew, v.portPin = "", "", "", ""
			return v, v.load
		}
	}
	return v, nil
}

// cliErr drops the CLI's "[dop ]token|integration|grant <verb>: "
// prefix so the status line reads as the why, not the command.
func cliErr(e string) string {
	e = strings.TrimPrefix(e, "dop ")
	for _, p := range []string{"token ", "integration ", "grant "} {
		if i := strings.Index(e, ": "); i >= 0 && strings.HasPrefix(e, p) && !strings.Contains(e[len(p):i], " ") {
			return vocab(e[i+2:])
		}
	}
	return e
}

func (v *listView) updateListMode(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	vis := v.visible()
	v.err = ""
	if v.tab == listTabPending {
		switch k := mm.String(); k {
		case "enter", "a":
			if len(v.pending) > 0 {
				v.mode, v.doneSubj = listModePendPass, v.pending[v.cursor].subject
				v.pendPass.Reset()
			}
			return v, nil
		case "r", "d":
			if len(v.pending) > 0 {
				v.mode, v.doneSubj = listModePendRejct, v.pending[v.cursor].subject
			}
			return v, nil
		case "x", "s", "p":
			return v, nil
		}
	}
	switch k := mm.String(); k {
	case "x":
		if !v.revoked() {
			break
		}
		if v.pruneCount() == 0 {
			v.flash = "nothing to prune"
			break
		}
		v.mode, v.pendingAction, v.help = listModeConfirm, "prune", false
	case "esc", "ctrl+c", "q":
		v.done = true
	case "up", "k":
		if v.cursor > 0 {
			v.cursor--
		}
	case "down", "j":
		if v.cursor < v.rowCount()-1 {
			v.cursor++
		}
	case "tab":
		v.tab, v.cursor = (v.tab+1)%3, 0
	case "shift+tab":
		v.tab, v.cursor = (v.tab+2)%3, 0
	case "enter":
		if len(vis) == 0 {
			return v, nil
		}
		v.mode = listModeAction
		v.actionCursor, v.detailTab, v.grantCursor = 0, 0, 0
		v.help = false
	case "r", "s", "p":
		// Direct actions on the cursor row (only those its detail offers).
		for _, a := range v.currentActions() {
			if a.key == k {
				v.help = false
				return v.runAction(a)
			}
		}
	}
	return v, nil
}

// updatePendingMode drives approve (passphrase) / reject (confirm) of
// the Pending tab's cursor row; the shell-outs are the banner picker's.
func (v *listView) updatePendingMode(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	k := mm.String()
	if k != "enter" {
		v.err = ""
	}
	switch {
	case k == "esc" || k == "ctrl+c":
		v.mode = listModeList
		v.pendPass.Reset()
	case v.mode == listModePendRejct && (k == "enter" || k == "y"):
		if cmd := v.locked(mm, &v.err); cmd != nil {
			return v, cmd
		}
		v.mode, v.pendingAction = listModeRun, "reject-claim"
		return v, runPendingRow(v.pendingRowAt(), true, "")
	case v.mode == listModePendRejct && k == "n":
		v.mode = listModeList
	case v.mode == listModePendPass && k == "enter":
		if v.pendPass.Value() == "" {
			v.err = "Approval passphrase is required"
			return v, nil
		}
		if cmd := v.locked(mm, &v.err); cmd != nil {
			return v, cmd
		}
		v.mode, v.pendingAction = listModeRun, "approve-claim"
		return v, runPendingRow(v.pendingRowAt(), false, v.pendPass.Value())
	case v.mode == listModePendPass:
		edit(&v.pendPass, mm)
	}
	return v, nil
}

// viewPending renders the approve / reject screens of the Pending tab.
func (v *listView) viewPending(width, height int) string {
	w := wiz{width: width, height: height, help: v.help}
	row := v.pendingRowAt()
	from := "PIN " + row.sas
	if row.remote() {
		from = "remote · " + row.host
	}
	if v.mode == listModePendRejct {
		lines := []string{mutedSt.Render("  " + from), mutedSt.Render("  The agent has to claim again if this was a mistake.")}
		return w.confirmScreen("Reject "+row.subject+"?", lines, "reject", v.err)
	}
	return w.screen("Approve "+row.subject, "", "Approval passphrase", []string{inputRow(&v.pendPass)}, "", v.err, from, wizKeys("approve"))
}

func (v *listView) updateActionMode(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	acts := v.currentActions()
	v.err = ""
	k := mm.String()
	switch k {
	case "esc", "backspace":
		v.mode = listModeList
		return v, nil
	case "q", "ctrl+c":
		v.done = true
		return v, nil
	case "tab", "shift+tab":
		v.detailTab = 1 - v.detailTab
		return v, nil
	}
	if v.detailTab == 1 {
		grants := v.bearerGrants()
		switch k {
		case "up", "down":
			stepCursor(&v.grantCursor, len(grants), map[string]int{"up": -1, "down": 1}[k])
		case "a":
			if len(acts) > 0 {
				return v.runAction(listAction{key: "+"})
			}
		case "r":
			if len(acts) > 0 && len(grants) > 0 {
				return v.runAction(listAction{key: "-"})
			}
		}
		return v, nil
	}
	switch k {
	case "up", "k":
		stepCursor(&v.actionCursor, len(acts), -1)
	case "down", "j":
		stepCursor(&v.actionCursor, len(acts), 1)
	case "enter":
		if v.actionCursor < 0 || v.actionCursor >= len(acts) {
			return v, nil
		}
		return v.runAction(acts[v.actionCursor])
	default:
		// Shortcut keys.
		for _, a := range acts {
			if a.key == k {
				return v.runAction(a)
			}
		}
	}
	return v, nil
}

func (v *listView) runAction(a listAction) (tea.Model, tea.Cmd) {
	if idx := v.selectedIndex(); idx >= 0 {
		v.doneSubj = v.capabilities[idx].Subject
	}
	v.err, v.help = "", false
	v.grantPickPassBuf.Reset()
	v.grantPickPassPhase = false
	switch a.key {
	case "r":
		v.mode = listModeConfirm
		v.pendingAction = "revoke"
	case "s":
		// reseal doesn't need confirmation (non-destructive).
		if cmd := v.locked(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("s")}, &v.err); cmd != nil {
			return v, cmd
		}
		v.mode = listModeRun
		v.pendingAction = "reseal"
		return v, v.doReseal()
	case "p":
		v.reclaim = false
		if c := v.capabilities[v.selectedIndex()]; c.Binding != nil && c.Binding.Pubkey != "" {
			v.mode, v.reissueCursor, v.err = listModeReissue, 0, ""
			return v, nil
		}
		v.mode, v.pendingAction, v.repinTTLCursor, v.repinStep, v.runsCur = listModeRepin, "repin", 0, 0, 0
		v.portPass.Reset()
	case "o":
		v.mode, v.portStep, v.pendingAction = listModePortable, 0, "portable-on"
		if c := v.capabilities[v.selectedIndex()]; c.PortableWrapped != "" {
			v.pendingAction = "portable-off"
		}
		v.portPass.Reset()
	case "+":
		// vault grants minus the ones already on this bearer.
		if !v.prepareGrantPicker() {
			v.err = "No grants left to add. Add one first: Add › Grant."
			return v, nil
		}
		v.pendingAction, v.mode = "add", listModeGrantPick
	case "-":
		// the grant under the Grants-tab cursor, behind a confirm.
		gid := v.bearerGrants()[min(v.grantCursor, len(v.bearerGrants())-1)]
		v.grantPick = multiPick{items: grantPickItems([]string{gid}, v.grantInfo()), sel: map[string]bool{gid: true}}
		v.pendingAction, v.mode = "remove", listModeConfirm
	}
	return v, nil
}

// prepareGrantPicker fills the add-grant picker with the vault grants
// not on the cursor bearer; false when there are none.
func (v *listView) prepareGrantPicker() bool {
	have := map[string]bool{}
	for _, g := range v.bearerGrants() {
		have[g] = true
	}
	var ids []string
	for gid := range v.vgrants {
		if !have[gid] {
			ids = append(ids, gid)
		}
	}
	sort.Strings(ids)
	v.grantPick = multiPick{items: grantPickItems(ids, v.grantInfo())}
	return len(ids) > 0
}

// grantPickProtectedCount is the number of picked protected grants;
// non-zero means the approval passphrase is asked before shelling out.
func (v *listView) grantPickProtectedCount() int {
	n := 0
	for _, gid := range v.grantPick.picked() {
		if v.vgrants[gid].Protected {
			n++
		}
	}
	return n
}

// doGrantMutation shells out to `dop token add-grant` or `remove-grant`
// once per selected grant. v1.13.0-rc5 — multi-select: all picked
// grants are applied as one batch; first error short-circuits with the
// partial-progress message surfaced to the user.
func (v *listView) doGrantMutation() tea.Cmd {
	idx := v.selectedIndex()
	if idx < 0 {
		return func() tea.Msg { return listActionMsg{err: "no selection"} }
	}
	target := v.capIDs[idx][:12]
	op := v.pendingAction
	picked := v.grantPick.picked()
	// rc6f — pipe passphrase per-call when the picked set includes a
	// protected grant (shadow of [S2]: CLI's promptProtectionPassphrase
	// reads from the terminal; TUI subprocesses have no tty on stdin).
	protectedSet := map[string]bool{}
	for _, gid := range picked {
		if v.vgrants[gid].Protected {
			protectedSet[gid] = true
		}
	}
	passphrase := v.grantPickPassBuf.String()
	return func() tea.Msg {
		self, _ := os.Executable()
		applied := []string{}
		for _, gid := range picked {
			args := []string{"token", op + "-grant"}
			if protectedSet[gid] {
				args = append(args, "--passphrase-stdin")
			}
			args = append(args, target, gid)
			cmd := exec.Command(self, args...)
			cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
			if protectedSet[gid] {
				cmd.Stdin = strings.NewReader(passphrase + "\n")
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Run(); err != nil {
				msg := strings.TrimSpace(stderr.String())
				if len(applied) > 0 {
					msg = fmt.Sprintf("%s · partial: %s applied: %v", msg, op+"-grant", applied)
				}
				return listActionMsg{err: msg}
			}
			applied = append(applied, gid)
		}
		return listActionMsg{flash: strings.Join(applied, ", ")}
	}
}

// doReseal spawns `dop token reseal <capID-prefix>` for the selected
// row. Only meaningful on claimed P-256 bearers; the CLI rejects
// others with a clear message that the TUI surfaces as a flash.
func (v *listView) doReseal() tea.Cmd { return v.doTokenCmd("reseal") }

// doTokenCmd spawns `dop token <verb> <capID-prefix>` (reseal, rotate)
// for the selected row; the CLI's stderr becomes the flash or error.
func (v *listView) doTokenCmd(verb string) tea.Cmd {
	idx := v.selectedIndex()
	if idx < 0 {
		return func() tea.Msg { return listActionMsg{err: "no selection"} }
	}
	target := v.capIDs[idx][:12]
	return func() tea.Msg {
		self, _ := os.Executable()
		cmd := exec.Command(self, "token", verb, target)
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return listActionMsg{err: strings.TrimSpace(stderr.String())}
		}
		return listActionMsg{flash: strings.TrimSpace(stderr.String() + stdout.String())}
	}
}

// updateGrantPickMode drives the add-grant picker (space toggles,
// enter applies, esc back to the Grants tab), then the approval
// passphrase when a protected grant is picked (esc back to the picker).
func (v *listView) updateGrantPickMode(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	k := mm.String()
	if v.grantPickPassPhase {
		switch k {
		case "enter":
			if v.grantPickPassBuf.Len() == 0 {
				v.err = "The approval passphrase is required for protected grants."
				return v, nil
			}
			if cmd := v.locked(mm, &v.err); cmd != nil {
				return v, cmd
			}
			v.err = ""
			v.mode = listModeRun
			return v, v.doGrantMutation()
		case "esc":
			v.grantPickPassPhase, v.err = false, ""
		default:
			passKey(&v.grantPickPassBuf, mm)
		}
		return v, nil
	}
	if v.grantPick.key(k) {
		v.err = ""
		return v, nil
	}
	switch k {
	case "enter":
		if len(v.grantPick.picked()) == 0 {
			v.err = "Select at least one grant (space toggles)."
			return v, nil
		}
		v.err = ""
		if v.grantPickProtectedCount() > 0 {
			v.grantPickPassPhase = true
			v.grantPickPassBuf.Reset()
			return v, nil
		}
		if cmd := v.locked(mm, &v.err); cmd != nil {
			return v, cmd
		}
		v.mode = listModeRun
		return v, v.doGrantMutation()
	case "esc":
		v.mode, v.pendingAction, v.err = listModeAction, "", ""
	}
	return v, nil
}

// updateRepinMode is the PIN validity picker; enter goes on to the
// portable wizard's confirm, esc back to the detail.
// reissueOption is one way to re-issue a claimed bearer.
type reissueOption struct {
	key, label, desc string
}

// reissueOptions lists what a claimed bearer allows: rotate needs a
// P-256 key (the new bearer is sealed to it); a new claim works for any
// claimed bearer — a rotated one is pubkey-bound, still claimable anew.
// Empty for unclaimed / unbound bearers.
func reissueOptions(c vault.Capability) []reissueOption {
	if c.Binding == nil || c.Binding.Pubkey == "" {
		return nil
	}
	var o []reissueOption
	if c.Binding.KeyType == vault.KeyTypeP256 {
		o = append(o, reissueOption{"rotate", "Keep the agent's key", "no new claim, picked up on its next exec"})
	}
	return append(o, reissueOption{"reclaim", "New claim", "new PIN, the agent claims again"})
}

// updateReissueMode picks how to re-issue a claimed bearer: rotate runs
// at once (no confirmation — the agent switches on its own); a new claim
// continues to the PIN validity picker with --reclaim.
func (v *listView) updateReissueMode(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	opts := reissueOptions(v.capabilities[v.selectedIndex()])
	if toggleHelp(&v.help, mm) {
		return v, nil
	}
	switch mm.String() {
	case "esc":
		v.mode, v.err = listModeAction, ""
	case "up", "k":
		stepCursor(&v.reissueCursor, len(opts), -1)
	case "down", "j":
		stepCursor(&v.reissueCursor, len(opts), 1)
	case "enter":
		if v.reissueCursor >= len(opts) {
			return v, nil
		}
		switch opts[v.reissueCursor].key {
		case "rotate":
			if cmd := v.locked(mm, &v.err); cmd != nil {
				return v, cmd
			}
			v.mode, v.pendingAction = listModeRun, "rotate"
			return v, v.doTokenCmd("rotate")
		case "reclaim":
			v.reclaim = true
			v.mode, v.pendingAction, v.repinTTLCursor, v.repinStep, v.runsCur = listModeRepin, "repin", 0, 0, 0
			v.portPass.Reset()
		}
	}
	return v, nil
}

// viewReissue is a single-choice question (contract 14: wiz.screen +
// optRows, description on the option's row).
func (v *listView) viewReissue(width, height int) string {
	var opts [][2]string
	for _, o := range reissueOptions(v.capabilities[v.selectedIndex()]) {
		opts = append(opts, [2]string{o.label, o.desc})
	}
	w := wiz{width: width, height: height, help: v.help}
	km := keyMap{short: []key.Binding{hint("enter", "next"), keyBack},
		full: [][]key.Binding{{hint("enter", "next"), keyBack}, {keyMove}}}
	return w.screen("Re-issue "+v.doneSubj, "", "How should "+v.doneSubj+" get its new bearer?",
		optRows(opts, v.reissueCursor), "", v.err, "", km)
}

func (v *listView) updateRepinMode(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	cur, n := &v.repinTTLCursor, len(repinTTLPresets)
	if v.repinStep == 1 {
		cur, n = &v.runsCur, len(runsOnPresets)
	}
	switch mm.String() {
	case "esc":
		if v.repinStep == 1 {
			v.repinStep = 0
			return v, nil
		}
		if v.reclaim {
			v.mode, v.pendingAction, v.err = listModeReissue, "", ""
			return v, nil
		}
		v.mode, v.pendingAction, v.err = listModeAction, "", ""
	case "up", "k":
		stepCursor(cur, n, -1)
	case "down", "j":
		stepCursor(cur, n, 1)
	case "enter":
		if v.repinStep == 0 {
			v.repinStep = 1
			return v, nil
		}
		v.mode, v.portStep, v.err = listModePortable, 0, ""
	}
	return v, nil
}

// repinRemote: the re-issued bearer's agent runs on a Server install,
// so the handoff carries --remote.
func (v *listView) repinRemote() bool {
	return v.pendingAction == "repin" && runsOnPresets[v.runsCur].value
}

// updatePortableMode drives the portable wizard; esc steps back, then
// to the detail.
func (v *listView) updatePortableMode(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	k := mm.String()
	if k == "esc" {
		v.err = ""
		if v.portStep == 0 && v.pendingAction == "repin" {
			v.mode, v.repinStep = listModeRepin, 1 // back to the runs-on picker
		} else if v.portStep == 0 {
			v.mode, v.pendingAction = listModeAction, ""
			v.portPass.Reset()
		}
		v.portStep = max(v.portStep-1, 0)
		return v, nil
	}
	if v.portStep == 0 && (k == "y" || k == "Y") {
		k = "enter"
	}
	if k != "enter" {
		if v.portStep == 1 {
			passKey(&v.portPass, mm)
		}
		v.err = ""
		return v, nil
	}
	switch {
	case v.portStep == 0 && v.portNeedsPass():
		v.portStep, v.err = 1, ""
		return v, nil
	case v.portStep == 1 && v.portPass.Len() == 0:
		v.err = "The approval passphrase is required."
		return v, nil
	}
	if cmd := v.locked(mm, &v.err); cmd != nil {
		return v, cmd
	}
	v.mode, v.err = listModeRun, ""
	return v, v.doPortable()
}

// portableErr puts a failed portable run back in the wizard, on the
// passphrase when there is one.
func (v *listView) portableErr(e string) {
	v.mode, v.portStep, v.err = listModePortable, 0, e
	if v.portNeedsPass() {
		v.portStep = 1
	}
	v.portPass.Reset()
}

// portClaimed: the cursor bearer is bound to the agent's key, so make
// portable rotates it in place (no new PIN).
func (v *listView) portClaimed() bool {
	i := v.selectedIndex()
	return i >= 0 && v.capabilities[i].Binding != nil && v.capabilities[i].Binding.Pubkey != ""
}

// portNeedsPass: remove always asks the approval passphrase; make
// portable only when the bearer holds a protected grant.
func (v *listView) portNeedsPass() bool {
	if v.pendingAction == "portable-off" {
		return true
	}
	for _, g := range v.bearerGrants() {
		if v.vgrants[g].Protected {
			return true
		}
	}
	return false
}

func (v *listView) portHandoff() string {
	return bearerHandoff(v.portNew, v.portPin, LoadPrefs(v.paths).AllowFileKeys, v.repinRemote())
}

// doPortable shells out to dop token portable (or repin); the passphrase
// goes on stdin, never in argv. --on and repin answer with an
// issueResultMsg (bearer and PIN when the bearer was re-issued unclaimed).
func (v *listView) doPortable() tea.Cmd {
	subject, on := v.doneSubj, v.pendingAction != "portable-off"
	args := []string{"token", "portable", "--subject", subject, "--off"}
	switch v.pendingAction {
	case "portable-on":
		args[4] = "--on"
	case "repin":
		args = []string{"token", "repin", "--subject", subject, "--pin-ttl", repinTTLPresets[v.repinTTLCursor].value}
		if v.reclaim {
			args = append(args, "--reclaim")
		}
	}
	stdin := ""
	if v.portNeedsPass() {
		args = append(args, "--passphrase-stdin")
		stdin = v.portPass.String() + "\n"
	}
	v.portPass.Reset()
	return func() tea.Msg {
		self, _ := os.Executable()
		cmd := exec.Command(self, args...)
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
		cmd.Stdin = strings.NewReader(stdin)
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		err := cmd.Run()
		switch {
		case !on && err != nil:
			return listActionMsg{err: strings.TrimSpace(stderr.String())}
		case !on:
			return listActionMsg{}
		case err != nil:
			return issueResultMsg{err: strings.TrimSpace(stderr.String())}
		}
		return parseIssueOut(stdout.String())
	}
}

func (v *listView) updateConfirmMode(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	k := mm.String()
	needPass := v.pendingAction == "remove" && v.grantPickProtectedCount() > 0
	switch {
	case k == "enter" || (!needPass && (k == "y" || k == "Y")):
		if needPass && v.grantPickPassBuf.Len() == 0 {
			v.err = "The approval passphrase is required for protected grants."
			return v, nil
		}
		if cmd := v.locked(mm, &v.err); cmd != nil {
			return v, cmd
		}
		v.mode, v.err = listModeRun, ""
		if v.pendingAction == "revoke" {
			return v, v.doRevoke()
		}
		if v.pendingAction == "prune" {
			return v, v.doPrune()
		}
		return v, v.doGrantMutation()
	case k == "esc" || (!needPass && (k == "n" || k == "N")):
		if v.pendingAction == "prune" {
			v.mode = listModeList
		} else {
			v.mode = listModeAction
		}
		v.pendingAction, v.err = "", ""
	case needPass:
		v.err = ""
		passKey(&v.grantPickPassBuf, mm)
	}
	return v, nil
}

// pruneCount is how many bearers dop token prune --older-than 30d removes.
func (v *listView) pruneCount() int {
	n := 0
	for _, c := range v.capabilities {
		if (c.Status == capability.RecordStatusRevoked || c.Status == capability.RecordStatusRotated) &&
			time.Since(c.TouchedAt()) > 30*24*time.Hour {
			n++
		}
	}
	return n
}

func (v *listView) doPrune() tea.Cmd {
	return func() tea.Msg {
		self, _ := os.Executable()
		cmd := exec.Command(self, "token", "prune", "--older-than", "30d", "--yes")
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return listActionMsg{err: strings.TrimSpace(stderr.String())}
		}
		return listActionMsg{}
	}
}

func (v *listView) doRevoke() tea.Cmd {
	idx := v.selectedIndex()
	if idx < 0 {
		return func() tea.Msg { return listActionMsg{err: "no selection"} }
	}
	// v1.13 — pass the cap-id prefix (unambiguous) rather than the
	// subject. Two tokens sharing a subject would otherwise fail with
	// "matches multiple" and be unrevokeable from the TUI.
	target := v.capIDs[idx][:12]
	return func() tea.Msg {
		self, _ := os.Executable()
		cmd := exec.Command(self, "token", "revoke", target)
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return listActionMsg{err: strings.TrimSpace(stderr.String())}
		}
		return listActionMsg{}
	}
}

func (v *listView) View() string {
	width, height := v.width, v.height
	if width == 0 || height == 0 {
		width, height = 80, 24
	}
	switch {
	case !v.loaded:
		return frame(width, height, "Bearers", nil, "", []string{mutedSt.Render("  loading…")}, "", "")
	case v.loadErr != "":
		return frame(width, height, "Bearers", nil, "", []string{v.loadErr}, "", footer(width, keyBack))
	}
	switch v.mode {
	case listModeAction:
		return v.viewDetail(width, height)
	case listModeConfirm:
		return v.viewConfirm(width, height)
	case listModeRun:
		return v.viewRun(width, height)
	case listModeGrantPick:
		return v.viewGrantPick(width, height)
	case listModeRepin:
		return v.viewRepin(width, height)
	case listModeReissue:
		return v.viewReissue(width, height)
	case listModePortable:
		return v.viewPortable(width, height)
	case listModeDone:
		return v.viewDone(width, height)
	case listModePendPass, listModePendRejct:
		return v.viewPending(width, height)
	}

	vis := v.visible()
	nAct := 0
	for _, c := range v.capabilities {
		if c.Status == capability.RecordStatusActive {
			nAct++
		}
	}
	tabs := []tab{{"Active", nAct, v.tab == listTabActive}, {"Revoked", len(v.capabilities) - nAct, v.tab == listTabRevoked}, {"Pending", len(v.pending), v.tab == listTabPending}}
	other := [3]string{"revoked", "pending", "active"}[v.tab]
	km := bearerListKeys
	km.short = []key.Binding{keyOpen, hint("tab", other), keyBack}
	switch v.tab {
	case listTabRevoked:
		km.short = []key.Binding{keyOpen, hint("x", "prune"), hint("tab", other), keyBack}
	case listTabPending:
		km.short = []key.Binding{hint("enter", "approve"), hint("r", "reject"), hint("tab", other), keyBack}
	}
	st := status{err: v.err, flash: v.flash}
	var body []string
	switch {
	case v.tab == listTabPending && len(v.pending) > 0:
		body = v.renderPending()
		row := v.pending[v.cursor]
		h := "key " + midTrunc(row.pubkey, 24)
		if row.keyType != "" {
			h = row.keyType + " " + h
		}
		st.setHint(h)
	case v.tab == listTabPending:
		body = append(body, bodySt.Render("  No pending claims. An agent's dop claim (local or --remote) shows up here."))
	case len(vis) > 0:
		// The table gets the body rows the open help leaves, so 16+
		// bearers scroll inside it while status and footer stay put.
		rows := frameRows(height)
		if v.help {
			rows -= len(km.helpLines(width)) + 1
		}
		body = append(body, v.renderTable(vis, width, rows))
		st.setHint(v.rowHint(vis[v.cursor]))
	case v.revoked():
		body = append(body, bodySt.Render("  No revoked bearers."))
	case len(v.capabilities) == 0:
		body = append(body, bodySt.Render("  No bearers yet. Issue one from the menu: Issue."))
	default:
		body = append(body, bodySt.Render("  No active bearers. Issue one from the menu: Issue."))
	}
	if v.rowCount() == 0 {
		km.short = km.short[1:] // nothing to open / approve
		if v.tab == listTabPending {
			km.short = km.short[1:] // nor reject
		}
	}
	body = km.overlay(body, width, frameRows(height), v.help)
	return frame(width, height, "Bearers", tabs, "", body, st.String(), km.footerLine(width, v.help))
}

// renderPending is the Pending tab body: subject, where the claim came
// from (PIN or remote host), and how long it stays approvable.
func (v *listView) renderPending() []string {
	body := []string{"  " + mutedSt.Render(padTrunc("subject", 24)+"  "+padTrunc("from", 22)+"  expires")}
	for i, r := range v.pending {
		from := "PIN " + r.sas
		if r.remote() {
			from = "remote · " + r.host
		}
		cells := padTrunc(r.subject, 24) + "  " + padTrunc(from, 22)
		left := "in " + humanDuration(time.Until(r.expiresAt))
		if i == v.cursor {
			body = append(body, focusSt.Render("› "+cells+"  "+left))
		} else {
			body = append(body, "  "+bodySt.Render(cells)+"  "+mutedSt.Render(left))
		}
	}
	return body
}

// bearerListKeys is the bearers list's expanded help (short is per tab).
var bearerListKeys = keyMap{
	full: [][]key.Binding{
		{keyMove, hint("enter", "open bearer"), hint("tab", "active / revoked / pending"), keyBack},
		{hint("r", "revoke"), hint("s", "reseal env"), hint("p", "repin (unclaimed only)"), keyQuit},
		{hint("x", "prune revoked older than 30d (Revoked tab)"), hint("enter / r", "approve / reject a claim (Pending tab)")},
	},
	notes: []string{
		"The status line shows id, generation, binding, portable and owner",
		"of the bearer under the cursor; not yours shows as by <admin>.",
	},
}

// bearerDetailKeys is the bearer detail's footer + expanded help.
var bearerDetailKeys = keyMap{
	short: []key.Binding{hint("enter", "run"), keyBack},
	full:  [][]key.Binding{{keyMove, hint("enter", "run action")}, {keyBack, keyQuit}},
	notes: []string{"Add and remove grant reseal the env; the agent picks it up on its next exec."},
}

// relDate renders a list date relative to now: in 2d, 97d ago, never.
func relDate(t time.Time) string {
	if t.Year() >= 9999 {
		return "never"
	}
	d, f := time.Until(t), "in %s"
	if d < 0 {
		d, f = -d, "%s ago"
	}
	switch {
	case d >= 24*time.Hour:
		return fmt.Sprintf(f, fmt.Sprintf("%dd", (d+12*time.Hour)/(24*time.Hour)))
	case d >= time.Hour:
		return fmt.Sprintf(f, fmt.Sprintf("%dh", d/time.Hour))
	}
	return fmt.Sprintf(f, fmt.Sprintf("%dm", d/time.Minute))
}

// absDate renders a detail date: 2026-10-08 10:00 UTC, or never.
func absDate(t time.Time) string {
	if t.Year() >= 9999 {
		return "never"
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

// owner names who issued c: you, an admin name, or a short pubkey.
func (v *listView) owner(c vault.Capability) string {
	switch {
	case c.IssuedBy == "":
		return ""
	case c.IssuedBy == v.viewerPubkey:
		return "you"
	case v.adminNames[c.IssuedBy] != "":
		return v.adminNames[c.IssuedBy]
	}
	return c.IssuedBy[:min(8, len(c.IssuedBy))] + "…"
}

// binding is "PIN, unclaimed" / "P-256, claimed", or "" when unbound.
func binding(b *vault.Binding) string {
	if b == nil || b.Kind == "" || b.Kind == vault.BindingKindNone {
		return ""
	}
	kind := "PIN"
	if b.Kind != vault.BindingKindPIN {
		kind = map[string]string{"p256": "P-256", "ed25519": "Ed25519"}[b.KeyType]
		if kind == "" {
			kind = "key"
		}
	}
	if b.Pubkey == "" {
		return kind + ", unclaimed"
	}
	return kind + ", claimed"
}

// rowHint is the status line for list row i: id · gen · binding ·
// portable · by <admin>, absent parts omitted.
func (v *listView) rowHint(i int) string {
	c := v.capabilities[i]
	parts := []string{v.capIDs[i][:min(8, len(v.capIDs[i]))]}
	if c.Status != capability.RecordStatusActive {
		return strings.Join(append(parts, c.Status), " · ")
	}
	parts = append(parts, fmt.Sprintf("gen %d", c.Generation))
	if b := binding(c.Binding); b != "" {
		parts = append(parts, b)
	}
	if c.PortableWrapped != "" {
		parts = append(parts, "portable")
	}
	if o := v.owner(c); o != "" && o != "you" {
		parts = append(parts, "by "+o)
	}
	return strings.Join(parts, " · ")
}

// renderTable lays the visible bearers out with bubbles/table: subject
// (24, … truncated), expires (relative), grants (rest). v.cursor stays
// the source of truth; the table is only the renderer.
func (v *listView) renderTable(vis []int, width, avail int) string {
	rows := make([]table.Row, 0, len(vis))
	for _, i := range vis {
		c := v.capabilities[i]
		rows = append(rows, table.Row{c.Subject, relDate(c.ExpiresAt), strings.Join(c.Grants, ", ")})
	}
	if v.tbl == nil {
		t := table.New()
		v.tbl = &t
	}
	t := v.tbl
	t.SetStyles(table.Styles{Header: mutedSt.PaddingRight(2), Cell: lipgloss.NewStyle().PaddingRight(2), Selected: focusSt})
	exp := "expires"
	if v.revoked() {
		exp = "expired"
	}
	t.SetColumns([]table.Column{{Title: "subject", Width: 24}, {Title: exp, Width: 10}, {Title: "grants", Width: max(width-42, 6)}})
	t.SetRows(rows)
	t.SetHeight(min(len(rows)+1, max(avail, 2))) // +1 = header
	// Step one row at a time: MoveUp/MoveDown keep the viewport offset
	// in sync, SetCursor does not.
	for n := len(rows); n > 0 && t.Cursor() < v.cursor; n-- {
		t.MoveDown(1)
	}
	for n := len(rows); n > 0 && t.Cursor() > v.cursor; n-- {
		t.MoveUp(1)
	}
	lines := strings.Split(t.View(), "\n")
	for i, ln := range lines {
		// ponytail: the only styled body row is the selected one.
		if i > 0 && strings.Contains(ln, "\x1b") {
			lines[i] = focusSt.Render("› ") + ln
		} else {
			lines[i] = strings.TrimRight("  "+ln, " ")
		}
	}
	return strings.Join(lines, "\n")
}

// viewDetail is the bearer detail, tabs Info / Grants n. Info: primary
// fields, secondary fields muted, then the action list. Grants: one row
// per grant, a adds, r removes.
func (v *listView) viewDetail(width, height int) string {
	idx := v.selectedIndex()
	if idx < 0 {
		return frame(width, height, "Bearers", nil, "", nil, "", footer(width, keyBack))
	}
	c, id := v.capabilities[idx], v.capIDs[idx]
	grants := v.bearerGrants()
	tabs := []tab{{"Info", -1, v.detailTab == 0}, {"Grants", len(grants), v.detailTab == 1}}
	km := bearerDetailKeys
	st := status{err: v.err, flash: v.flash}
	acts := v.currentActions()
	var body []string
	if v.detailTab == 1 {
		km.short = []key.Binding{hint("a", "add"), hint("r", "remove"), hint("tab", "info"), keyBack}
		if len(acts) == 0 {
			km.short = km.short[2:]
		}
		if len(grants) == 0 {
			body = []string{bodySt.Render("  No grants. Press a to add one.")}
			if len(acts) == 0 {
				body = []string{bodySt.Render("  No grants.")}
			}
		} else {
			v.grantCursor = min(v.grantCursor, len(grants)-1)
			body = []string{"  " + mutedSt.Render(padTrunc("name", nameColW)+"  "+padTrunc("integration", 16)+"  env prefix")}
			for i, gid := range grants {
				g := v.vgrants[gid]
				rest := padTrunc(g.Integration, 16) + "  " + g.EffectivePrefix()
				if i == v.grantCursor {
					body = append(body, focusSt.Render("› "+padTrunc(gid, nameColW))+"  "+mutedSt.Render(rest))
					st.setHint(grantHint(gid, g))
				} else {
					body = append(body, "  "+bodySt.Render(padTrunc(gid, nameColW))+"  "+mutedSt.Render(rest))
				}
			}
		}
		body = km.overlay(body, width, frameRows(height), v.help)
		return frame(width, height, ansi.Truncate(c.Subject, max(width-40, 12), "…"), tabs, c.Status, body, st.String(), km.footerLine(width, v.help))
	}
	exp := absDate(c.ExpiresAt)
	if exp != "never" {
		exp = relDate(c.ExpiresAt) + " · " + exp
	}
	// A portable bearer skips the binding check in its issuing admin's
	// shells (skipBindingAsPortableOwner); it can still be PIN-bound for
	// an agent.
	bind, portableNote := "none", c.PortableWrapped != ""
	if portableNote {
		bind = "none · portable bearer, no PIN or claim needed"
	}
	if c.Binding != nil && c.Binding.Kind == vault.BindingKindPIN && c.Binding.Pubkey == "" {
		bind = "PIN · unclaimed, the agent has not run dop claim"
		if portableNote {
			bind = "PIN · unclaimed · portable, its issuer needs no claim"
		}
	} else if b := binding(c.Binding); b != "" {
		bind = strings.Replace(b, ", ", " · ", 1)
		if !c.Binding.ClaimedAt.IsZero() {
			bind += " " + absDate(c.Binding.ClaimedAt)
		}
	}
	portable := "no"
	if c.PortableWrapped != "" {
		portable = "yes"
	}
	by := v.owner(c)
	if pk := c.IssuedBy; len(pk) > 20 {
		by += " · " + pk[:8] + "…" + pk[len(pk)-11:]
	}
	gl := strings.Join(grants, ", ")
	if gl == "" {
		gl = "none"
	}
	lines := strings.Split(strings.TrimRight(kv(
		[2]string{"expires", exp}, [2]string{"grants", gl},
		[2]string{"binding", bind}, [2]string{"portable", portable},
		[2]string{"id", mutedSt.Render(id)}, [2]string{"created", mutedSt.Render(absDate(c.CreatedAt))},
		[2]string{"issued by", mutedSt.Render(by)}, [2]string{"generation", mutedSt.Render(fmt.Sprint(c.Generation))},
	), "\n"), "\n")
	body = append(append(append([]string{}, lines[:4]...), ""), lines[4:]...)
	km.short = []key.Binding{hint("enter", "run"), hint("tab", "grants"), keyBack}
	if len(acts) > 0 {
		body = append(body, "")
	} else {
		km.short = km.short[1:]
		st.setHint("A revoked bearer has no actions left.")
	}
	body = append(body, actionRows(acts, v.actionCursor, &st)...)
	body = km.overlay(body, width, frameRows(height), v.help)
	return frame(width, height, ansi.Truncate(c.Subject, max(width-40, 12), "…"), tabs, c.Status, body, st.String(), km.footerLine(width, v.help))
}

func (v *listView) viewConfirm(width, height int) string {
	if v.pendingAction == "prune" {
		return frame(width, height, "Prune "+plural(v.pruneCount(), "bearer")+" revoked or rotated more than 30d ago?", nil, "",
			[]string{mutedSt.Render("  Their records and files are deleted; the audit log keeps the history.")}, "", confirmFoot("prune"))
	}
	idx := v.selectedIndex()
	if idx < 0 {
		return frame(width, height, "Bearers", nil, "", nil, "", footer(width, keyBack))
	}
	c := v.capabilities[idx]
	if v.pendingAction == "remove" {
		gid := v.grantPick.picked()[0]
		g := v.vgrants[gid]
		body := strings.Split(kv([2]string{"integration", g.Integration}, [2]string{"credential", g.Token},
			[2]string{"env prefix", g.EffectivePrefix()}), "\n")
		body = append(body, mutedSt.Render("  The env is resealed; the agent picks it up on its next exec."))
		if v.grantPickProtectedCount() > 0 {
			before, after := v.grantPickPassBuf.SplitMasked("•")
			body = append(body, "", focusSt.Render("› ")+bodySt.Render("approval passphrase")+"  "+before+focusSt.Render("▎")+after)
		}
		title := ansi.Truncate("Remove "+gid, max(width-30, 20), "…") + " from " + c.Subject + "?"
		return frame(width, height, title, nil, "", body, status{err: v.err}.String(), confirmFoot("remove"))
	}
	body := strings.Split(kv(
		[2]string{"grants", strings.Join(c.Grants, ", ")},
		[2]string{"expires", relDate(c.ExpiresAt)},
		[2]string{"issued by", v.owner(c)},
	), "\n")
	body = append(body, mutedSt.Render("  Takes effect at once: the bearer fails on its next exec."))
	return frame(width, height, "Revoke "+c.Subject+"?", nil, "", body, "", confirmFoot("revoke"))
}

// viewRun is the in-flight screen: one present-tense title, no footer
// (the subprocess can't be cancelled).
func (v *listView) viewRun(width, height int) string {
	verb := map[string]string{"revoke": "Revoking %s…", "reseal": "Resealing the env of %s…", "rotate": "Rotating %s…",
		"add": "Adding grants to %s…", "remove": "Removing grants from %s…", "repin": "Re-issuing %s…",
		"portable-on": "Re-issuing %s…", "portable-off": "Removing portable copy…", "prune": "Pruning…"}[v.pendingAction]
	if verb == "" {
		verb = "Working on %s…"
	}
	if strings.Contains(verb, "%s") {
		verb = fmt.Sprintf(verb, v.doneSubj)
	}
	return frame(width, height, verb, nil, "", nil, "", "")
}

// viewDone is the ✓ outcome of a bearer action; any key returns to the list.
func (v *listView) viewDone(width, height int) string {
	rows := [][2]string{{"bearer", v.doneSubj}}
	var title, note string
	st := status{}
	switch v.pendingAction {
	case "revoke":
		title, note = "✓ Bearer revoked", "It fails on its next exec. The vault is synced with the team."
	case "reseal":
		title, note = "✓ Env resealed", v.doneNote
	case "rotate":
		title, note = "✓ Bearer rotated", "The agent picks up the new bearer on its next exec, no new claim."
	case "add", "remove":
		n := "Grant"
		if strings.Contains(v.doneNote, ",") {
			n = "Grants"
		}
		title = fmt.Sprintf("✓ %s %sed", n, map[string]string{"add": "add", "remove": "remov"}[v.pendingAction])
		rows = append(rows, [2]string{"grants", v.doneNote})
		note = "Env resealed; the agent picks it up on its next exec."
	case "portable-on":
		g := useGuidance(LoadPrefs(v.paths).Harness, v.doneSubj, true, "")
		if v.portNew != "" {
			return onceScreen(width, height, "✓ Bearer re-issued", v.doneSubj, v.portNew, v.portPin, g, v.portArmed, v.portCopied)
		}
		title, note = "✓ Bearer is portable", strings.Join(g, "\n")
	case "repin":
		h := strings.Split(v.portHandoff(), "\n")
		portable := v.capabilities[v.selectedIndex()].PortableWrapped != "" // still the old record until the reload
		g := useGuidance(LoadPrefs(v.paths).Harness, v.doneSubj, portable, "run "+strings.TrimSpace(h[len(h)-1]))
		if v.repinRemote() {
			g = append(g, "The claim lands in this TUI's pending banner; approve it there.")
		}
		return onceScreen(width, height, "✓ Bearer re-issued", v.doneSubj, v.portNew, v.portPin, g, v.portArmed, v.portCopied)
	case "portable-off":
		title, note = "✓ Portable copy removed", "dop use no longer works for this bearer."
	case "prune":
		rows = nil
		title, note = "✓ Pruned "+plural(v.pruneCount(), "bearer"), "The audit log keeps the history."
	}
	body := strings.Split(kv(rows...), "\n")
	for _, l := range strings.Split(note, "\n") {
		body = append(body, mutedSt.Render("  "+l))
	}
	return frame(width, height, title, nil, "", body, st.String(), footer(width, hint("enter", "done")))
}

// viewRepin is the PIN validity picker of a repin.
func (v *listView) viewRepin(width, height int) string {
	title := "New PIN for " + v.doneSubj
	if v.reclaim {
		title = "New claim for " + v.doneSubj
	}
	foot := footer(width, hint("enter", "next"), keyBack)
	if v.repinStep == 1 {
		var o [][2]string
		for _, p := range runsOnPresets {
			o = append(o, [2]string{p.label, p.hint})
		}
		body := append([]string{"  " + mutedSt.Render("Runs on"), ""}, optRows(o, v.runsCur)...)
		return frame(width, height, title, nil, "", body, status{err: v.err}.String(), foot)
	}
	body := []string{"  " + mutedSt.Render("New PIN valid for"), ""}
	for i, p := range repinTTLPresets {
		row := fmt.Sprintf("%-4s", p.value)
		if p.label == "" {
			row = p.value
		}
		if i == v.repinTTLCursor {
			row = focusSt.Render("› " + row)
		} else {
			row = "  " + bodySt.Render(row)
		}
		if p.label != "" {
			row += "  " + mutedSt.Render(p.label)
		}
		body = append(body, row)
	}
	return frame(width, height, title, nil, "", body, status{err: v.err}.String(), foot)
}

// viewPortable is the portable wizard: confirm, then the approval
// passphrase when one is needed.
func (v *listView) viewPortable(width, height int) string {
	w := wiz{width: width, height: height, help: v.help}
	title, verb := "Remove the portable copy of "+v.doneSubj+"?", "remove"
	lines := []string{"dop use will stop working for this bearer"}
	if v.pendingAction == "portable-on" {
		title, verb = "Re-issue "+v.doneSubj+" as portable?", "re-issue"
		lines = []string{"a new bearer and PIN are shown once, the old ones stop working"}
		if v.portClaimed() {
			lines = []string{"the agent keeps working, it picks up the new bearer on its next run"}
		}
		lines = append(lines, "same grants and expiry; dop use then works from your shells")
	}
	if v.pendingAction == "repin" {
		title, verb = "Re-issue "+v.doneSubj+" with a new PIN?", "re-issue"
		lines = []string{"the old bearer and PIN stop working", "the agent gets the new bearer and PIN from you"}
		if v.repinRemote() {
			lines = append(lines, "on a server: the handoff carries --remote, approve from the pending banner")
		}
	}
	if v.portStep == 0 {
		for i, l := range lines {
			lines[i] = mutedSt.Render("  " + l)
		}
		return w.confirmScreen(title, lines, verb, v.err)
	}
	helper := ""
	if v.pendingAction != "portable-off" {
		helper = "The bearer holds protected grants."
	}
	before, after := v.portPass.SplitMasked("•")
	return w.screen(title, "", "Approval passphrase", []string{focusSt.Render("› ") + before + focusSt.Render("▎") + after},
		helper, v.err, "", wizKeys(verb))
}

// viewGrantPick is the add-grant multi-select picker, plus the approval
// passphrase row when a protected grant is picked.
func (v *listView) viewGrantPick(width, height int) string {
	title := "Add grants to " + v.doneSubj
	body := append([]string{"  " + mutedSt.Render("Grants to add"), ""}, v.grantPick.rows(width, frameRows(height)-4, nil)...)
	st := status{err: v.err}
	st.setHint(fmt.Sprintf("%d selected", len(v.grantPick.picked())))
	foot := footer(width, hint("space", "toggle"), hint("enter", "add"), keyBack)
	if v.grantPickPassPhase {
		before, after := v.grantPickPassBuf.SplitMasked("•")
		body = append(body, "", focusSt.Render("› ")+bodySt.Render("approval passphrase")+"  "+before+focusSt.Render("▎")+after)
		st.setHint(fmt.Sprintf("%s need the approval passphrase", plural(v.grantPickProtectedCount(), "protected grant")))
		foot = footer(width, hint("enter", "add"), keyBack)
	}
	return frame(width, height, title, nil, "", body, st.String(), foot)
}

// silence unused imports pinned to future views
var _ = hex.EncodeToString
var _ = io.Discard

// bearerGrants is the cursor bearer's grants, sorted.
func (v *listView) bearerGrants() []string {
	idx := v.selectedIndex()
	if idx < 0 {
		return nil
	}
	g := append([]string{}, v.capabilities[idx].Grants...)
	sort.Strings(g)
	return g
}

// grantInfo is the picker / Grants-tab view of the vault's grants.
func (v *listView) grantInfo() map[string]tuiGrantInfo {
	info := map[string]tuiGrantInfo{}
	for id, g := range v.vgrants {
		info[id] = toGrantInfo(g)
	}
	return info
}

// passKey edits a masked passphrase field.
func passKey(f *textField, mm tea.KeyMsg) {
	switch k := mm.String(); {
	case k == "backspace":
		f.Backspace()
	case len(mm.Runes) > 0:
		f.InsertRunes(mm.Runes)
	default:
		f.handleKey(k, mm.Runes)
	}
}
