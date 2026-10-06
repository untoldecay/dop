// Sub-views. Kept in one file to hold the surface area small.

package tui

import (
	"bytes"
	"encoding/hex"
	"errors"
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
	"github.com/charmbracelet/huh"
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
	return shortDuration(max(time.Until(time.Unix(refUnix, 0).Add(time.Duration(ttl)*time.Second)), 0))
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
		line("!", "admin key", "agent install, no admin key", "Set up an admin key from the menu to manage the vault.")
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

// issueView — one huh.Form: subject → grants → expiry (→ custom) →
// portable (→ approval passphrase), then the review, the issuing
// spinner and the bearer handoff.
type issueView struct {
	wiz
	client *admin.Client
	paths  *config.Paths
	form   *huh.Form
	steps  []huh.Field // form fields in order, for the "n of m" counter

	// form-bound values
	subject      string
	grants       []string // multi-select (vault has grants)
	grantsCSV    string   // free-text fallback (vault has none)
	expiry       string   // preset value or "custom"
	customExpiry string
	portable     bool
	passphrase   string // approval passphrase, only for protected grants

	review   bool // form completed: the review step
	issuing  bool
	errField huh.Field // field the last enter was refused on; its error shows until another key
	err      string
	bearer   string
	pin      string
	done     bool
	flash    string

	grantList []string
	grantRows []grantRow
	grantByID map[string]tuiGrantInfo

	// allow-file-keys prefs captured at construction: the handoff text
	// and the background-reseal watcher depend on it.
	prefs       Prefs
	copied      bool   // last clipboard attempt succeeded (on result, and on c)
	leaveArmed  bool   // first esc on the bearer screen; a second esc leaves
	resealFlash string // filled by the background auto-reseal watcher
	pollCount   int    // bounded loop for the auto-reseal poller
}

type grantRow struct {
	project  string // empty for the "(ungrouped)" section
	grantID  string // empty when this row is a section header
	isHeader bool
}

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

func newIssueView(c *admin.Client, p *config.Paths) *issueView {
	v := &issueView{client: c, paths: p, prefs: LoadPrefs(p), expiry: "72h"}
	v.grantList, v.grantRows, v.grantByID = loadGrantsForList(c, p)
	v.form = v.buildForm()
	return v
}

func required(what string) func(string) error {
	return func(s string) error {
		if strings.TrimSpace(s) == "" {
			return errors.New(what + " is required")
		}
		return nil
	}
}

// optLabel is a picker option: label in fg, padded to w, the hint muted.
func optLabel(label string, w int, hint string) string {
	return bodySt.Render(padTrunc(label, w)) + "  " + mutedSt.Render(hint)
}

func (v *issueView) buildForm() *huh.Form {
	var grants huh.Field
	if len(v.grantList) > 0 {
		// ponytail: huh options have no section headers, so the project
		// rides muted in the label; a grant in several projects is listed
		// once, under its first project.
		pw := 0
		for _, r := range v.grantRows {
			pw = max(pw, lipgloss.Width(r.project))
		}
		var opts []huh.Option[string]
		seen := map[string]bool{}
		for _, r := range v.grantRows {
			if r.isHeader || seen[r.grantID] {
				continue
			}
			seen[r.grantID] = true
			label := mutedSt.Render(padTrunc(strings.Trim(r.project, "()"), pw)) + "  " + optLabel(r.grantID, 28, ansi.Truncate(v.grantByID[r.grantID].Prefix+"_TOKEN", 30, "…"))
			opts = append(opts, huh.NewOption(label, r.grantID))
		}
		grants = huh.NewMultiSelect[string]().TitleFunc(func() string { return "Grants for " + v.subject }, &v.subject).
			Options(opts...).Value(&v.grants).Filterable(false).Validate(v.validateGrants)
	} else {
		grants = huh.NewInput().Title("Grants").Prompt("› ").
			Description("No grants in the vault yet: type them comma-separated.").
			Value(&v.grantsCSV).Validate(required("Grants"))
	}
	var expiry []huh.Option[string]
	for _, p := range expiryPresets {
		expiry = append(expiry, huh.NewOption(optLabel(p.label, 7, p.hint), p.value))
	}
	var portable []huh.Option[bool]
	for _, p := range portablePresets {
		portable = append(portable, huh.NewOption(optLabel(p.label, 3, p.hint), p.value))
	}
	pick := issueTheme()
	pick.Focused.SelectedOption = focusSt // the cursor row of a single choice is the brand row
	v.steps = []huh.Field{
		huh.NewInput().Title("Subject").Prompt("› ").Placeholder("claude-code-laptop").
			Value(&v.subject).Validate(required("Subject")),
		grants,
		huh.NewSelect[string]().Title("Expires").
			Options(expiry...).Value(&v.expiry).WithTheme(pick),
		huh.NewInput().Title("Custom expiry").Prompt("› ").Placeholder("10d").Description("A duration: 30m, 2h, 7d.").
			Value(&v.customExpiry).Validate(required("Duration")),
		huh.NewSelect[bool]().Title("Portable").Options(portable...).Value(&v.portable).WithTheme(pick),
		huh.NewInput().Title("Approval passphrase").Prompt("› ").
			Description("The selection includes protected grants.").
			EchoMode(huh.EchoModePassword).Value(&v.passphrase).Validate(required("Approval passphrase")),
	}
	s := v.steps
	return huh.NewForm(
		huh.NewGroup(s[0]), huh.NewGroup(s[1]), huh.NewGroup(s[2]),
		huh.NewGroup(s[3]).WithHideFunc(func() bool { return v.expiry != "custom" }),
		huh.NewGroup(s[4]),
		huh.NewGroup(s[5]).WithHideFunc(func() bool { return v.protectedCount() == 0 }),
	).WithTheme(issueTheme()).WithShowHelp(false).WithShowErrors(false).WithWidth(80)
}

// visibleSteps are the steps the current answers lead through.
func (v *issueView) visibleSteps() []huh.Field {
	out := []huh.Field{v.steps[0], v.steps[1], v.steps[2]}
	if v.expiry == "custom" {
		out = append(out, v.steps[3])
	}
	out = append(out, v.steps[4])
	if v.protectedCount() > 0 {
		out = append(out, v.steps[5])
	}
	return out
}

// issueTheme — huh theme from the TUI palette: muted prompts, › brand
// cursor, fg options, danger errors, no bold, no borders.
func issueTheme() *huh.Theme {
	t := huh.ThemeBase()
	f := &t.Focused
	f.Base, f.Card = lipgloss.NewStyle(), lipgloss.NewStyle()
	f.Title, f.NoteTitle, f.Description = mutedSt, mutedSt, mutedSt
	f.ErrorIndicator = lipgloss.NewStyle() // errors render on the status line instead
	f.ErrorMessage = dangerSt
	f.SelectSelector = focusSt.SetString("› ")
	f.MultiSelectSelector = focusSt.SetString("› ")
	f.NextIndicator, f.PrevIndicator = lipgloss.NewStyle(), lipgloss.NewStyle()
	f.Option, f.SelectedOption, f.UnselectedOption = bodySt, bodySt, bodySt
	f.SelectedPrefix = bodySt.SetString("● ")
	f.UnselectedPrefix = mutedSt.SetString("○ ")
	f.TextInput.Cursor, f.TextInput.Prompt = focusSt, focusSt
	f.TextInput.Placeholder, f.TextInput.Text = placeholderSt, bodySt
	t.Blurred = t.Focused
	t.Blurred.SelectSelector = lipgloss.NewStyle().SetString("  ")
	t.Blurred.MultiSelectSelector = lipgloss.NewStyle().SetString("  ")
	t.Group.Title, t.Group.Description = mutedSt, mutedSt
	return t
}

// selectedGrants — the grants the form currently holds (list or CSV).
func (v *issueView) selectedGrants() []string {
	if len(v.grantList) > 0 {
		return v.grants
	}
	var out []string
	for _, g := range strings.Split(v.grantsCSV, ",") {
		if g = strings.TrimSpace(g); g != "" {
			out = append(out, g)
		}
	}
	return out
}

func (v *issueView) expiryValue() string {
	if v.expiry == "custom" {
		return strings.TrimSpace(v.customExpiry)
	}
	return v.expiry
}

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

func (v *issueView) validateGrants(sel []string) error {
	if len(sel) == 0 {
		return errors.New("select at least one grant (space to toggle)")
	}
	if c := v.collidingPrefixes(sel); len(c) > 0 {
		return errors.New("env prefix collision — last wins silently; deselect one")
	}
	return nil
}

// rc6c — count protected grants in the current selection. Non-zero
// → the approval passphrase group is shown (rc3-smoke-retakes [S2]).
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
	if v.portable {
		portable = "yes"
	}
	return [][2]string{
		{"subject", v.subject},
		{"grants", strings.Join(v.selectedGrants(), ", ")},
		{"expires", v.expiryValue()},
		{"portable", portable},
	}
}

func (v *issueView) Init() tea.Cmd { return v.form.Init() }
func (v *issueView) Done() bool    { return v.done }
func (v *issueView) Flash() string { return v.flash }

type issueResultMsg struct {
	bearer string
	pin    string
	err    string
}

// typing: the focused step is a text input holding text (? types).
func (v *issueView) typing() bool {
	in, ok := v.form.GetFocusedField().(*huh.Input)
	return ok && !v.review && v.bearer == "" && in.GetValue() != ""
}

func (v *issueView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if _, ok := msg.(spinner.TickMsg); ok && !v.issuing {
		return v, nil
	}
	if ok, cmd := v.wizMsg(msg, v.typing()); ok {
		return v, cmd
	}
	switch mm := msg.(type) {
	case issueResultMsg:
		v.issuing = false
		if mm.err != "" {
			v.err, v.review = firstLine(mm.err), true
			return v, nil
		}
		v.bearer, v.pin = mm.bearer, mm.pin
		// Copy once here, not in View (which repaints on every msg).
		v.copied = clipboardCopy(v.handoff())
		// allow-file-keys: watch the record for the claim, then reseal.
		if v.prefs.AllowFileKeys && v.pin != "" {
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
	case tea.WindowSizeMsg:
		v.form = v.form.WithWidth(mm.Width)
		mm.Height = frameRows(mm.Height) - 1 // status line is the frame's
		msg = mm
	case tea.KeyMsg:
		switch {
		case v.issuing:
			return v, nil
		case v.bearer != "":
			return v.bearerKey(mm.String())
		case mm.String() == "ctrl+c":
			v.done = true
			return v, nil
		case v.review:
			switch mm.String() {
			case "enter":
				v.review, v.issuing, v.err = false, true, ""
				return v, tea.Batch(v.spinStart(), v.issue())
			case "esc", "shift+tab":
				v.review, v.err = false, ""
				return v, v.reopen()
			}
			return v, nil
		case mm.String() == "esc":
			if v.form.GetFocusedField() == v.steps[0] {
				v.done = true
				return v, nil
			}
			return v, v.form.PrevGroup()
		}
		// huh validates on focus; only surface the error once enter is refused.
		v.errField = nil
		if mm.String() == "enter" {
			v.errField = v.form.GetFocusedField()
		}
	}
	if v.form.State != huh.StateNormal {
		return v, nil
	}
	m, cmd := v.form.Update(msg)
	v.form = m.(*huh.Form)
	if v.form.State == huh.StateCompleted {
		v.review = true
		return v, nil
	}
	return v, cmd
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
	subject := strings.TrimSpace(v.subject)
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
	name := strings.TrimSpace(v.subject)
	grants := strings.Join(v.selectedGrants(), ",")
	expires := v.expiryValue()
	if expires == "" {
		expires = "72h"
	}
	prefs := v.prefs
	portable := v.portable
	// rc6c — pipe protected-grant passphrase when any grant is protected.
	protectedPass := v.passphrase
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
		// stdout: bearer on line 1, PIN on line 2 (when --bind is default).
		bearer, pin := "", ""
		for _, ln := range strings.Split(strings.TrimSpace(stdout.String()), "\n") {
			ln = strings.TrimSpace(ln)
			switch {
			case strings.HasPrefix(ln, "tok_"):
				bearer = ln
			case looksLikePIN(ln):
				pin = ln
			}
		}
		return issueResultMsg{bearer: bearer, pin: pin}
	}
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

// reopen rebuilds the completed form on its last step (huh can't
// resume a completed form; the values live in v, so nothing is lost).
func (v *issueView) reopen() tea.Cmd {
	v.form = v.buildForm()
	cmds := []tea.Cmd{v.form.Init()}
	if v.width > 0 {
		v.form = v.form.WithWidth(v.width)
		v.form.Update(tea.WindowSizeMsg{Width: v.width, Height: frameRows(v.height) - 1})
	}
	for range v.visibleSteps()[1:] {
		cmds = append(cmds, v.form.NextGroup())
	}
	return tea.Batch(cmds...)
}

// handoff is the clipboard text for the agent (contract 13 shape).
func (v *issueView) handoff() string {
	if v.pin == "" {
		return v.bearer
	}
	return buildHandoffText(v.bearer, v.pin, v.prefs.AllowFileKeys)
}

// bearerKey handles the one-time bearer screen: a stray key must not
// lose the bearer. enter leaves, esc needs a second press, c re-copies,
// anything else is ignored (and disarms esc).
func (v *issueView) bearerKey(k string) (tea.Model, tea.Cmd) {
	switch k {
	case "enter":
		v.done = true
	case "esc", "ctrl+c":
		if !v.leaveArmed {
			v.leaveArmed = true
			return v, nil
		}
		v.done = true
	case "c":
		v.copied = clipboardCopy(v.handoff())
		fallthrough
	default:
		v.leaveArmed = false
		return v, nil
	}
	v.flash = "bearer issued · shown once, make sure it was copied"
	return v, nil
}

func (v *issueView) View() string {
	const title = "Issue bearer"
	switch {
	case v.bearer != "":
		rows := [][2]string{{"subject", v.subject}, {"bearer", v.bearer}}
		cmd := "export DOP_TOKEN=" + v.bearer
		if v.pin != "" {
			rows = append(rows, [2]string{"PIN", v.pin})
			h := strings.Split(v.handoff(), "\n")
			cmd = "run " + strings.TrimSpace(h[len(h)-1])
		}
		body := append(strings.Split(strings.TrimRight(kv(rows...), "\n"), "\n"), "", mutedSt.Render("  "+cmd))
		if v.prefs.AllowFileKeys && v.pin != "" {
			body = append(body, mutedSt.Render("  "+displayOr(v.resealFlash, "Auto-reseal runs once the agent claims.")))
		}
		st := status{}
		switch {
		case v.leaveArmed:
			st.setHint("press esc again to leave, the bearer will not be shown again")
		case v.copied:
			st.setFlash("copied to clipboard")
		}
		return frame(v.width, v.height, "✓ Bearer issued", nil, "shown once, c copies again", body, st.String(),
			footer(v.width, hint("enter", "done"), hint("c", "copy")))
	case v.issuing:
		return v.running(title, "Issuing a bearer for "+v.subject)
	case v.review:
		return v.wiz.review(title, "Issue this bearer?", v.summaryRows(), "issue", false, v.err)
	}
	steps := v.visibleSteps()
	i := 0
	for j, f := range steps {
		if f == v.form.GetFocusedField() {
			i = j
		}
	}
	st := status{}
	if errs := v.form.Errors(); len(errs) > 0 && v.errField == v.form.GetFocusedField() {
		st.setError(errs[0].Error())
	}
	km := wizKeys("next")
	if _, ok := v.form.GetFocusedField().(*huh.MultiSelect[string]); ok {
		km = wizKeys("next", keySpace)
		km.full[1] = append(km.full[1], hint("ctrl+a", "all/none"))
		st.setHint(fmt.Sprintf("%d selected", len(v.grants)))
		if c := v.collidingPrefixes(v.grants); len(c) > 0 {
			var ps []string
			for p, ids := range c {
				ps = append(ps, p+"_TOKEN used by "+strings.Join(ids, ", "))
			}
			sort.Strings(ps)
			st.setError(ps[0] + ": deselect one")
		}
	}
	body := km.overlay(strings.Split(strings.TrimRight(v.form.View(), "\n"), "\n"), v.width, frameRows(v.height), v.help)
	return frame(v.width, v.height, title, nil, counter(i, len(steps)), body, st.String(), km.footerLine(v.width, v.help))
}

// loadGrantsForList — best-effort read of the vault to surface grants.
// v1.8: also returns per-project rows and an info map keyed by grant ID.
func loadGrantsForList(client *admin.Client, paths *config.Paths) ([]string, []grantRow, map[string]tuiGrantInfo) {
	vp := paths.Vault + "/vault.yaml"
	raw, err := os.ReadFile(vp)
	if err != nil {
		return nil, nil, nil
	}
	if bytes.Contains(raw, []byte("\nsops:")) || bytes.HasPrefix(raw, []byte("sops:")) {
		plain, err := client.DecryptVault(vp)
		if err != nil {
			return nil, nil, nil
		}
		raw = plain
	}
	var v vault.Vault
	if err := yaml.Unmarshal(raw, &v); err != nil {
		return nil, nil, nil
	}
	// Flat list — kept for the "no grants" fallback callers.
	ids := make([]string, 0, len(v.Grants))
	info := make(map[string]tuiGrantInfo, len(v.Grants))
	for id, g := range v.Grants {
		ids = append(ids, id)
		info[id] = tuiGrantInfo{
			Integration: g.Integration,
			Token:       g.Token,
			Prefix:      g.EffectivePrefix(),
			Tags:        append([]string(nil), g.Tags...),
			Projects:    append([]string(nil), g.Projects...),
			Protected:   g.Protected,
		}
	}
	sort.Strings(ids)
	// Build project → grantIDs, deduped inside each project.
	byProj := map[string][]string{}
	for _, id := range ids {
		g := info[id]
		if len(g.Projects) == 0 {
			byProj[""] = append(byProj[""], id)
			continue
		}
		for _, p := range g.Projects {
			byProj[p] = append(byProj[p], id)
		}
	}
	// Emit rows: project sections (sorted), then ungrouped last.
	projs := make([]string, 0, len(byProj))
	hasUngrouped := false
	for p := range byProj {
		if p == "" {
			hasUngrouped = true
			continue
		}
		projs = append(projs, p)
	}
	sort.Strings(projs)
	rows := []grantRow{}
	appendSection := func(header string, gids []string) {
		if len(gids) == 0 {
			return
		}
		sort.Strings(gids)
		rows = append(rows, grantRow{project: header, isHeader: true})
		for _, id := range gids {
			rows = append(rows, grantRow{project: header, grantID: id})
		}
	}
	for _, p := range projs {
		appendSection(p, byProj[p])
	}
	if hasUngrouped {
		appendSection("(ungrouped)", byProj[""])
	}
	return ids, rows, info
}

// ---------- List ----------

type listView struct {
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
	mode          int    // listMode*
	cursor        int    // index into visible()
	actionCursor  int    // index into currentActions()
	pendingAction string // revoke, reseal, add, remove, repin: the action in flight
	revoked       bool   // Revoked tab (false → Active)
	help          bool   // ? expanded help (list + detail)
	err           string
	flash         string

	// v1.13.0-rc3 — grant-picker state for in-TUI add-grant / remove-grant
	// on an existing token's detail. grantPickList is the list of candidate
	// grant IDs; pendingAction is "add" or "remove".
	// v1.13.0-rc5: grantPickSelected tracks the multi-select set
	// (space toggles, enter applies all). Previous releases were
	// single-select — picking one grant per round.
	grantPickList     []string
	grantPickCursor   int
	grantPickSelected map[string]bool
	// rc6f — passphrase sub-step for add-grant / remove-grant when the
	// picker's selection includes a protected grant. Mirrors the issue
	// path's protectedPassBuf (rc6c [S2] fix). grantPickProtectedMap
	// tells the picker which grant IDs are protected without re-reading
	// the vault; populated at prepareGrantPicker time.
	grantPickProtectedMap map[string]bool
	grantPickPassBuf      textField
	grantPickPassPhase    bool // true once protected picks required a passphrase screen

	// v1.13.0-rc9 — repin form state. Two fields: bearer paste +
	// PIN TTL (preset picker). pinResult is set once the CLI returns.
	repinBearerBuf  strings.Builder
	repinTTLCursor  int
	repinField      int // 0 = bearer, 1 = TTL picker
	repinNewPin     string
	repinNewExpires string

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
	listModeList      = 0
	listModeAction    = 1
	listModeConfirm   = 2
	listModeRun       = 3
	listModeGrantPick = 5 // add-grant / remove-grant picker
	listModeRepin     = 6 // bearer + PIN TTL form
	listModeDone      = 7 // ✓ outcome (revoke, reseal, grants, repin)
)

func newListView(c *admin.Client, p *config.Paths) *listView {
	return &listView{client: c, paths: p}
}
func (v *listView) Init() tea.Cmd { return v.load }
func (v *listView) Done() bool    { return v.done }
func (v *listView) Flash() string { return v.flash }

type listLoadedMsg struct {
	capabilities []vault.Capability
	capIDs       []string
	viewerPubkey string
	adminNames   map[string]string
	err          string
}
type listActionMsg struct {
	err   string
	flash string // v1.13 — surfaced in the list view for non-destructive actions
}

func (v *listView) load() tea.Msg {
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
	return listLoadedMsg{capabilities: caps, capIDs: ids, viewerPubkey: viewerPubkey, adminNames: names}
}

// visible returns the indexes into v.capabilities that should be shown
// under the current tab (Active, or Revoked = everything not active).
func (v *listView) visible() []int {
	out := []int{}
	for i, c := range v.capabilities {
		if (c.Status == capability.RecordStatusActive) == !v.revoked {
			out = append(out, i)
		}
	}
	return out
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
	// Order matches the approved detail mock. The CLI gatekeeps reseal and
	// grant edits (claimed P-256 only) with an actionable error. Repin is
	// for PIN-bound bearers the agent has not claimed yet.
	if c.Status != capability.RecordStatusActive {
		return nil
	}
	acts := append([]listAction{},
		listAction{label: "Reseal env", key: "s", desc: "push current credential values into this bearer's env"},
		listAction{label: "Add grant", key: "+", desc: "give this bearer more grants; its env is resealed"},
		listAction{label: "Remove grant", key: "-", desc: "take grants away from this bearer; its env is resealed"})
	if c.Binding != nil && c.Binding.Kind == "pin" && c.Binding.Pubkey == "" {
		acts = append(acts, listAction{label: "Repin", key: "p", desc: "new PIN for a bearer the agent has not claimed yet"})
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
	switch mm := msg.(type) {
	case tea.WindowSizeMsg:
		v.width, v.height = mm.Width, mm.Height
	case listLoadedMsg:
		v.loaded = true
		v.capabilities = mm.capabilities
		v.capIDs = mm.capIDs
		v.viewerPubkey = mm.viewerPubkey
		v.adminNames = mm.adminNames
		v.loadErr = mm.err
		v.cursor = max(min(v.cursor, len(v.visible())-1), 0)
	case listActionMsg:
		if mm.err != "" {
			// Errors stay on the detail that caused them, in plain words.
			v.err = map[string]string{"revoke": "Revoke", "reseal": "Reseal", "add": "Add grant",
				"remove": "Remove grant", "repin": "Repin"}[v.pendingAction] + " failed: " + cliErr(mm.err)
			v.mode = listModeAction
			v.pendingAction = ""
			return v, nil
		}
		v.doneNote = mm.flash
		v.mode = listModeDone
		return v, nil
	case repinSuccessMsg:
		v.repinNewPin = mm.pin
		v.repinNewExpires = mm.expires
		v.repinBearerBuf.Reset() // scrub bearer from memory
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
		case listModeGrantPick:
			return v.updateGrantPickMode(mm)
		case listModeRepin:
			return v.updateRepinMode(mm)
		case listModeDone:
			if mm.String() == "c" && v.pendingAction == "repin" {
				copyToClipboard(v.repinNewPin)
				v.flash = "PIN copied to clipboard"
				return v, nil
			}
			// Any other key dismisses — back to a freshly loaded list.
			v.mode = listModeList
			v.pendingAction, v.doneNote, v.repinNewPin = "", "", ""
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
	switch k := mm.String(); k {
	case "esc", "ctrl+c", "q":
		v.done = true
	case "up", "k":
		if v.cursor > 0 {
			v.cursor--
		}
	case "down", "j":
		if v.cursor < len(vis)-1 {
			v.cursor++
		}
	case "tab", "shift+tab":
		v.revoked = !v.revoked
		v.cursor = 0
	case "enter":
		if len(vis) == 0 {
			return v, nil
		}
		v.mode = listModeAction
		v.actionCursor = 0
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

func (v *listView) updateActionMode(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	acts := v.currentActions()
	v.err = ""
	switch mm.String() {
	case "esc", "backspace":
		v.mode = listModeList
	case "q", "ctrl+c":
		v.done = true
	case "up", "k":
		if v.actionCursor > 0 {
			v.actionCursor--
		}
	case "down", "j":
		if v.actionCursor < len(acts)-1 {
			v.actionCursor++
		}
	case "enter":
		if v.actionCursor < 0 || v.actionCursor >= len(acts) {
			return v, nil
		}
		return v.runAction(acts[v.actionCursor])
	default:
		// Shortcut keys.
		for _, a := range acts {
			if a.key == mm.String() {
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
	v.err = ""
	switch a.key {
	case "r":
		v.mode = listModeConfirm
		v.pendingAction = "revoke"
	case "s":
		// reseal doesn't need confirmation (non-destructive).
		v.mode = listModeRun
		v.pendingAction = "reseal"
		return v, v.doReseal()
	case "p":
		v.mode = listModeRepin
		v.pendingAction = "repin"
		v.repinField = 0
		v.repinBearerBuf.Reset()
		v.repinTTLCursor = 0
	case "+":
		// vault grants minus the ones already on this bearer.
		if !v.prepareGrantPicker("add") {
			v.err = "No grants left to add. Add one first: Vault > Add grant."
			v.mode, v.pendingAction = listModeAction, ""
			return v, nil
		}
		v.mode = listModeGrantPick
	case "-":
		if !v.prepareGrantPicker("remove") {
			v.err = "This bearer has no grants to remove."
			v.mode, v.pendingAction = listModeAction, ""
			return v, nil
		}
		v.mode = listModeGrantPick
	}
	return v, nil
}

// prepareGrantPicker loads the candidate grant IDs for the current
// token given the op ("add" or "remove"). Returns false when there's
// nothing meaningful to show (vault has no grants / token has none).
//
// v1.13.0-rc5: multi-select — grantPickSelected starts empty, user
// toggles with space, applies the whole set with enter.
func (v *listView) prepareGrantPicker(op string) bool {
	idx := v.selectedIndex()
	if idx < 0 {
		return false
	}
	cap := v.capabilities[idx]
	v.pendingAction = op
	v.grantPickCursor = 0
	v.grantPickList = nil
	v.grantPickSelected = map[string]bool{}
	// rc6f — reset passphrase state so a prior session doesn't bleed in.
	v.grantPickProtectedMap = map[string]bool{}
	v.grantPickPassBuf.Reset()
	v.grantPickPassPhase = false

	// Vault lookup serves two purposes: enumerate add-candidates (op=add)
	// AND seed the protected-flag map for both ops.
	vlt, _, verr := loadVaultForListing(v.client, v.paths)
	if verr == nil && vlt != nil {
		for gid, g := range vlt.Grants {
			if g.Protected {
				v.grantPickProtectedMap[gid] = true
			}
		}
	}
	if op == "remove" {
		v.grantPickList = append(v.grantPickList, cap.Grants...)
		sort.Strings(v.grantPickList)
		return len(v.grantPickList) > 0
	}
	// op == "add": vault grants NOT already on this token.
	if verr != nil || vlt == nil {
		return false
	}
	have := map[string]bool{}
	for _, g := range cap.Grants {
		have[g] = true
	}
	for gid := range vlt.Grants {
		if !have[gid] {
			v.grantPickList = append(v.grantPickList, gid)
		}
	}
	sort.Strings(v.grantPickList)
	return len(v.grantPickList) > 0
}

// grantPickProtectedCount returns the number of currently-selected
// grants that carry Protected=true. Non-zero on enter means the
// picker drops into the passphrase sub-step before shelling out.
func (v *listView) grantPickProtectedCount() int {
	n := 0
	for gid, sel := range v.grantPickSelected {
		if sel && v.grantPickProtectedMap[gid] {
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
	picked := []string{}
	for _, gid := range v.grantPickList {
		if v.grantPickSelected[gid] {
			picked = append(picked, gid)
		}
	}
	// rc6f — pipe passphrase per-call when the picked set includes a
	// protected grant (shadow of [S2]: CLI's promptProtectionPassphrase
	// reads from the terminal; TUI subprocesses have no tty on stdin).
	protectedSet := map[string]bool{}
	for _, gid := range picked {
		if v.grantPickProtectedMap[gid] {
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
func (v *listView) doReseal() tea.Cmd {
	idx := v.selectedIndex()
	if idx < 0 {
		return func() tea.Msg { return listActionMsg{err: "no selection"} }
	}
	target := v.capIDs[idx][:12]
	return func() tea.Msg {
		self, _ := os.Executable()
		cmd := exec.Command(self, "token", "reseal", target)
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

// updateGrantPickMode drives the add-grant / remove-grant picker.
// v1.13.0-rc5: multi-select — ↑↓ to move, space to toggle, enter to
// apply the whole selection, esc to cancel.
func (v *listView) updateGrantPickMode(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	// rc6f — passphrase sub-step: entered when the picker's selection
	// contains at least one protected grant. All other keys are routed
	// through the field for in-line caret editing.
	if v.grantPickPassPhase {
		key := mm.String()
		switch key {
		case "left", "right", "home", "end", "ctrl+a", "ctrl+e", "delete", "ctrl+d":
			v.grantPickPassBuf.handleKey(key, mm.Runes)
			return v, nil
		case "enter":
			if v.grantPickPassBuf.Len() == 0 {
				v.err = "The approval passphrase is required for protected grants."
				return v, nil
			}
			v.err = ""
			v.mode = listModeRun
			return v, v.doGrantMutation()
		case "backspace":
			if v.grantPickPassBuf.Len() > 0 {
				v.grantPickPassBuf.Backspace()
			} else {
				// Empty + backspace → return to picker.
				v.grantPickPassPhase = false
			}
			return v, nil
		case "esc":
			// Back to the multi-select picker; keep selection + buffer.
			v.grantPickPassPhase = false
			v.err = ""
			return v, nil
		default:
			if len(mm.Runes) > 0 {
				v.grantPickPassBuf.InsertRunes(mm.Runes)
			}
			return v, nil
		}
	}
	switch mm.String() {
	case "up", "k":
		if v.grantPickCursor > 0 {
			v.grantPickCursor--
		}
	case "down", "j":
		if v.grantPickCursor < len(v.grantPickList)-1 {
			v.grantPickCursor++
		}
	case " ":
		if v.grantPickCursor >= 0 && v.grantPickCursor < len(v.grantPickList) {
			gid := v.grantPickList[v.grantPickCursor]
			v.grantPickSelected[gid] = !v.grantPickSelected[gid]
		}
	case "a":
		// bulk select-all
		for _, gid := range v.grantPickList {
			v.grantPickSelected[gid] = true
		}
	case "n":
		// bulk clear
		for gid := range v.grantPickSelected {
			delete(v.grantPickSelected, gid)
		}
	case "enter":
		if len(v.grantPickList) == 0 {
			return v, nil
		}
		if v.selectedGrantCount() == 0 {
			v.err = "Select at least one grant (space toggles)."
			return v, nil
		}
		v.err = ""
		// rc6f — if any protected grants are in the selection, require
		// the admin's approval passphrase before shelling out.
		if v.grantPickProtectedCount() > 0 {
			v.grantPickPassPhase = true
			v.grantPickPassBuf.Reset()
			return v, nil
		}
		v.mode = listModeRun
		return v, v.doGrantMutation()
	case "esc", "q":
		v.mode = listModeAction
		v.grantPickList = nil
		v.grantPickSelected = nil
		v.pendingAction = ""
		v.grantPickProtectedMap = nil
		v.grantPickPassBuf.Reset()
		v.grantPickPassPhase = false
		v.err = ""
	}
	return v, nil
}

// updateRepinMode drives the two-field repin form: bearer paste
// (field 0) + PIN TTL preset picker (field 1). On enter at field 1
// shells out to `dop token repin`.
func (v *listView) updateRepinMode(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch mm.String() {
	case "esc":
		v.mode = listModeAction
		v.pendingAction = ""
		v.repinBearerBuf.Reset()
		v.err = ""
		return v, nil
	case "tab":
		v.repinField = (v.repinField + 1) % 2
		return v, nil
	case "shift+tab":
		v.repinField = (v.repinField + 1) % 2
		return v, nil
	}
	if v.repinField == 0 {
		switch mm.String() {
		case "enter":
			if strings.TrimSpace(v.repinBearerBuf.String()) == "" {
				v.err = "Paste the bearer the agent holds."
				return v, nil
			}
			v.err = ""
			v.repinField = 1
			return v, nil
		case "backspace":
			s := v.repinBearerBuf.String()
			if len(s) > 0 {
				v.repinBearerBuf.Reset()
				v.repinBearerBuf.WriteString(s[:len(s)-1])
			}
		default:
			if len(mm.Runes) > 0 {
				v.repinBearerBuf.WriteString(string(mm.Runes))
			}
		}
		return v, nil
	}
	// Field 1 — TTL picker.
	switch mm.String() {
	case "up", "k":
		if v.repinTTLCursor > 0 {
			v.repinTTLCursor--
		}
	case "down", "j":
		if v.repinTTLCursor < len(repinTTLPresets)-1 {
			v.repinTTLCursor++
		}
	case "enter":
		v.mode = listModeRun
		return v, v.doRepin()
	}
	return v, nil
}

// doRepin shells out to `dop token repin` with the pasted bearer in
// a temp token-file so it never shows up in the process list.
func (v *listView) doRepin() tea.Cmd {
	idx := v.selectedIndex()
	if idx < 0 {
		return func() tea.Msg { return listActionMsg{err: "no selection"} }
	}
	subject := v.capabilities[idx].Subject
	bearer := strings.TrimSpace(v.repinBearerBuf.String())
	ttl := repinTTLPresets[v.repinTTLCursor].value
	return func() tea.Msg {
		// Write bearer to a short-lived file so it's not visible in
		// `ps aux` as a CLI arg. Mode 0600; removed in defer.
		tmp, err := os.CreateTemp("", "dop-repin-*.tok")
		if err != nil {
			return listActionMsg{err: fmt.Sprintf("temp file: %v", err)}
		}
		defer os.Remove(tmp.Name())
		_, _ = tmp.WriteString(bearer)
		tmp.Close()
		_ = os.Chmod(tmp.Name(), 0o600)

		self, _ := os.Executable()
		cmd := exec.Command(self, "token", "repin",
			"--subject", subject,
			"--token-file", tmp.Name(),
			"--pin-ttl", ttl)
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return listActionMsg{err: strings.TrimSpace(stderr.String())}
		}
		// Parse the new PIN out of stdout. The CLI prints a block
		// like: "new PIN: XX-XX-XX (expires 2026-10-02T...)"
		combined := stdout.String() + stderr.String()
		pin, exp := extractRepinPin(combined)
		return repinSuccessMsg{pin: pin, expires: exp}
	}
}

// extractRepinPin pulls the new PIN + validity window out of the
// `dop token repin` output. The CLI prints:
//
//	dop token repin: reissued PIN for X (valid 5m0s)
//	  new PIN (shown ONCE):
//	XX-XX-XX
func extractRepinPin(s string) (pin, expires string) {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if looksLikePIN(line) {
			pin = line
			continue
		}
		// Match "(valid N)" where N is a duration string.
		if i := strings.Index(line, "(valid "); i >= 0 {
			rest := line[i+len("(valid "):]
			if j := strings.Index(rest, ")"); j >= 0 {
				expires = strings.TrimSpace(rest[:j])
				if d, err := time.ParseDuration(expires); err == nil {
					expires = shortDuration(d)
				}
			}
		}
	}
	return
}

// repinSuccessMsg is emitted by doRepin when the CLI succeeds, so
// the Update loop can transition to listModeRepinDone with the PIN
// surfaced for display + clipboard copy.
type repinSuccessMsg struct {
	pin     string
	expires string
}

// selectedGrantCount is the current size of the multi-select set.
func (v *listView) selectedGrantCount() int {
	n := 0
	for _, picked := range v.grantPickSelected {
		if picked {
			n++
		}
	}
	return n
}

func (v *listView) updateConfirmMode(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch mm.String() {
	case "y", "Y", "enter":
		if v.pendingAction == "revoke" {
			v.mode = listModeRun
			return v, v.doRevoke()
		}
	case "n", "N", "esc":
		v.mode = listModeAction
		v.pendingAction = ""
	}
	return v, nil
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
	case listModeDone:
		return v.viewDone(width, height)
	}

	vis := v.visible()
	nAct := 0
	for _, c := range v.capabilities {
		if c.Status == capability.RecordStatusActive {
			nAct++
		}
	}
	tabs := []tab{{"Active", nAct, !v.revoked}, {"Revoked", len(v.capabilities) - nAct, v.revoked}}
	other := "revoked"
	if v.revoked {
		other = "active"
	}
	km := bearerListKeys
	km.short = []key.Binding{keyOpen, hint("tab", other), keyBack}
	st := status{err: v.err, flash: v.flash}
	var body []string
	switch {
	case len(vis) > 0:
		// The table gets the body rows the open help leaves, so 16+
		// bearers scroll inside it while status and footer stay put.
		rows := frameRows(height)
		if v.help {
			rows -= len(km.helpLines(width)) + 1
		}
		body = append(body, v.renderTable(vis, width, rows))
		st.setHint(v.rowHint(vis[v.cursor]))
	case v.revoked:
		body = append(body, bodySt.Render("  No revoked bearers."))
	case len(v.capabilities) == 0:
		body = append(body, bodySt.Render("  No bearers yet. Issue one from the menu: Issue."))
	default:
		body = append(body, bodySt.Render("  No active bearers. Issue one from the menu: Issue."))
	}
	if len(vis) == 0 {
		km.short = km.short[1:] // nothing to open
	}
	body = km.overlay(body, width, frameRows(height), v.help)
	return frame(width, height, "Bearers", tabs, "", body, st.String(), km.footerLine(width, v.help))
}

// bearerListKeys is the bearers list's expanded help (short is per tab).
var bearerListKeys = keyMap{
	full: [][]key.Binding{
		{keyMove, hint("enter", "open bearer"), hint("tab", "active / revoked"), keyBack},
		{hint("r", "revoke"), hint("s", "reseal env"), hint("p", "repin (unclaimed only)"), keyQuit},
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
	if v.revoked {
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

// viewDetail is the bearer detail with its actions merged in: primary
// fields, secondary fields muted, then the action list.
func (v *listView) viewDetail(width, height int) string {
	idx := v.selectedIndex()
	if idx < 0 {
		return frame(width, height, "Bearers", nil, "", nil, "", footer(width, keyBack))
	}
	c, id := v.capabilities[idx], v.capIDs[idx]
	exp := absDate(c.ExpiresAt)
	if exp != "never" {
		exp = relDate(c.ExpiresAt) + " · " + exp
	}
	bind := "none"
	if c.Binding != nil && c.Binding.Kind == vault.BindingKindPIN && c.Binding.Pubkey == "" {
		bind = "PIN · unclaimed, the agent has not run dop claim"
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
	grants := strings.Join(c.Grants, ", ")
	if grants == "" {
		grants = "none"
	}
	lines := strings.Split(strings.TrimRight(kv(
		[2]string{"expires", exp}, [2]string{"grants", grants},
		[2]string{"binding", bind}, [2]string{"portable", portable},
		[2]string{"id", mutedSt.Render(id)}, [2]string{"created", mutedSt.Render(absDate(c.CreatedAt))},
		[2]string{"issued by", mutedSt.Render(by)}, [2]string{"generation", mutedSt.Render(fmt.Sprint(c.Generation))},
	), "\n"), "\n")
	body := append(append(append([]string{}, lines[:4]...), ""), lines[4:]...)
	km := bearerDetailKeys
	st := status{err: v.err, flash: v.flash}
	acts := v.currentActions()
	if len(acts) > 0 {
		body = append(body, "")
	} else {
		km.short = []key.Binding{keyBack}
		st.setHint("A revoked bearer has no actions left.")
	}
	body = append(body, actionRows(acts, v.actionCursor, &st)...)
	body = km.overlay(body, width, frameRows(height), v.help)
	return frame(width, height, c.Subject, nil, c.Status, body, st.String(), km.footerLine(width, v.help))
}

func (v *listView) viewConfirm(width, height int) string {
	idx := v.selectedIndex()
	if idx < 0 {
		return frame(width, height, "Bearers", nil, "", nil, "", footer(width, keyBack))
	}
	c := v.capabilities[idx]
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
	verb := map[string]string{"revoke": "Revoking %s…", "reseal": "Resealing the env of %s…",
		"add": "Adding grants to %s…", "remove": "Removing grants from %s…", "repin": "Repinning %s…"}[v.pendingAction]
	if verb == "" {
		verb = "Working on %s…"
	}
	return frame(width, height, fmt.Sprintf(verb, v.doneSubj), nil, "", nil, "", "")
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
	case "add", "remove":
		n := "Grant"
		if strings.Contains(v.doneNote, ",") {
			n = "Grants"
		}
		title = fmt.Sprintf("✓ %s %sed", n, map[string]string{"add": "add", "remove": "remov"}[v.pendingAction])
		rows = append(rows, [2]string{"grants", v.doneNote})
		note = "Env resealed; the agent picks it up on its next exec."
	default: // repin
		title, note = "✓ Bearer repinned", "Share the new PIN with the agent along with its bearer."
		rows = append(rows, [2]string{"new PIN", v.repinNewPin}, [2]string{"valid", shortDur(v.repinNewExpires)})
		st.setFlash(v.flash)
	}
	body := strings.Split(kv(rows...), "\n")
	for _, l := range strings.Split(note, "\n") {
		body = append(body, mutedSt.Render("  "+l))
	}
	return frame(width, height, title, nil, map[bool]string{true: "press c to copy the PIN"}[v.pendingAction == "repin"], body, st.String(), footer(width, hint("enter", "done")))
}

// viewRepin is the two-field repin form: bearer paste + PIN validity.
func (v *listView) viewRepin(width, height int) string {
	label := func(field int, s string) string {
		if v.repinField == field {
			return "  " + bodySt.Render(s)
		}
		return "  " + mutedSt.Render(s)
	}
	paste := "  " + strings.Repeat("•", v.repinBearerBuf.Len())
	if v.repinField == 0 {
		paste += focusSt.Render("▎")
	}
	body := []string{label(0, "current bearer (the agent holds it)"), paste, "", label(1, "new PIN valid for")}
	for i, p := range repinTTLPresets {
		row := fmt.Sprintf("%-4s", p.value)
		if p.label == "" {
			row = p.value
		}
		if v.repinField == 1 && i == v.repinTTLCursor {
			row = focusSt.Render("› " + row)
		} else {
			row = "  " + bodySt.Render(row)
		}
		if p.label != "" {
			row += "  " + mutedSt.Render(p.label)
		}
		body = append(body, row)
	}
	verb := "next"
	if v.repinField == 1 {
		verb = "repin"
	}
	foot := footer(width, hint("enter", verb), hint("tab", "field"), keyBack)
	return frame(width, height, "Repin "+v.doneSubj, nil, "", body, status{err: v.err}.String(), foot)
}

// viewGrantPick is the multi-select grant picker for add / remove grant,
// plus the approval passphrase step when a protected grant is picked.
func (v *listView) viewGrantPick(width, height int) string {
	title, verb := "Add grants to "+v.doneSubj, "add"
	if v.pendingAction == "remove" {
		title, verb = "Remove grants from "+v.doneSubj, "remove"
	}
	var body []string
	for i, gid := range v.grantPickList {
		mark := mutedSt.Render("○")
		if v.grantPickSelected[gid] {
			mark = bodySt.Render("●")
		}
		row := "  " + mark + " " + bodySt.Render(gid)
		if i == v.grantPickCursor {
			row = focusSt.Render("› ") + mark + " " + focusSt.Render(gid)
		}
		if v.grantPickProtectedMap[gid] {
			row += "  " + mutedSt.Render("protected")
		}
		body = append(body, row)
	}
	st := status{err: v.err}
	st.setHint(fmt.Sprintf("%d selected · space toggles, a selects all", v.selectedGrantCount()))
	foot := footer(width, hint("enter", verb), keyBack)
	if v.grantPickPassPhase {
		before, after := v.grantPickPassBuf.SplitMasked("•")
		body = append(body, "", "  "+mutedSt.Render("approval passphrase")+"  "+before+focusSt.Render("▎")+after)
		st.setHint(fmt.Sprintf("%s need the approval passphrase", plural(v.grantPickProtectedCount(), "protected grant")))
		foot = footer(width, hint("enter", verb), keyBack)
	}
	return frame(width, height, title, nil, "", body, st.String(), foot)
}

// silence unused imports pinned to future views
var _ = hex.EncodeToString
var _ = io.Discard
