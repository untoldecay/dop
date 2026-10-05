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

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"gopkg.in/yaml.v3"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/capability"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

// ---------- Status ----------

type statusView struct {
	client *admin.Client
	done   bool
}

func newStatusView(c *admin.Client) *statusView { return &statusView{client: c} }
func (v *statusView) Init() tea.Cmd             { return nil }
func (v *statusView) Done() bool                { return v.done }
func (v *statusView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if _, ok := msg.(tea.KeyMsg); ok {
		v.done = true
	}
	return v, nil
}
func (v *statusView) View() string {
	var b strings.Builder
	b.WriteString(titleSt.Render("Status") + "\n\n")
	st, err := v.client.Status()
	if err != nil {
		b.WriteString(failSt.Render("no active session"))
	} else {
		b.WriteString(fmt.Sprintf("admin pubkey:    %s\n", st.AdminPubkey))
		b.WriteString(fmt.Sprintf("age recipient:   %s\n", st.AgeRecipient))
		idleLeft := remaining(st.IdleTTLSeconds, st.LastActivityUnix)
		absLeft := remaining(st.AbsTTLSeconds, st.StartedAtUnix)
		b.WriteString(fmt.Sprintf("idle TTL left:   %s\n", idleLeft))
		b.WriteString(fmt.Sprintf("abs TTL left:    %s\n", absLeft))
	}
	b.WriteString("\n" + helpSt.Render("any key to go back"))
	return b.String()
}

func remaining(ttl int64, refUnix int64) string {
	r := time.Until(time.Unix(refUnix, 0).Add(time.Duration(ttl) * time.Second))
	if r < 0 {
		r = 0
	}
	return r.Round(time.Second).String()
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
	if _, ok := msg.(tea.KeyMsg); ok {
		v.done = true
	}
	return v, nil
}
func (v *doctorView) View() string {
	var b strings.Builder
	b.WriteString(titleSt.Render("Doctor") + "\n\n")
	line := func(status, name, detail string) {
		style := lipgloss.NewStyle()
		switch status {
		case "✓":
			style = okSt
		case "✗":
			style = failSt
		}
		b.WriteString(fmt.Sprintf("  %s %s  %s\n", style.Render(status), name, mutedSt.Render(detail)))
	}
	if _, err := exec.LookPath("sops"); err != nil {
		line("✗", "binary:sops", "install: brew install sops")
	} else {
		line("✓", "binary:sops", "")
	}
	if _, err := exec.LookPath("git"); err != nil {
		line("✗", "binary:git", "install git")
	} else {
		line("✓", "binary:git", "")
	}
	if admin.KeyFileExists(v.paths) {
		line("✓", "install", "admin (has keys)")
	} else {
		line("!", "install", "agent (no admin key)")
	}
	vp := v.paths.Vault + "/vault.yaml"
	if _, err := os.Stat(vp); err == nil {
		line("✓", "vault", "attached at "+vp)
	} else {
		line("!", "vault", "not attached")
	}
	if v.client.SessionActive() {
		line("✓", "admin session", "unlocked")
	} else {
		line("⋯", "admin session", "locked")
	}
	b.WriteString("\n" + helpSt.Render("any key to go back"))
	return b.String()
}

// ---------- Login (in-place passphrase prompt) ----------

type loginView struct {
	paths       *config.Paths
	buf         strings.Builder
	err         string
	loading     bool
	loggedIn    bool
	done        bool
	flash       string
}

func newLoginView(p *config.Paths) *loginView { return &loginView{paths: p} }
func (v *loginView) Init() tea.Cmd             { return nil }
func (v *loginView) Done() bool                { return v.done }
func (v *loginView) Flash() string             { return v.flash }

type loginResultMsg struct {
	err string
}

func (v *loginView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch mm := msg.(type) {
	case loginResultMsg:
		v.loading = false
		if mm.err != "" {
			v.err = mm.err
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
		switch mm.String() {
		case "esc", "ctrl+c":
			v.done = true
		case "enter":
			pass := v.buf.String()
			if pass == "" {
				return v, nil
			}
			v.loading = true
			v.err = ""
			return v, v.login(pass)
		case "backspace":
			s := v.buf.String()
			if len(s) > 0 {
				v.buf.Reset()
				v.buf.WriteString(s[:len(s)-1])
			}
		default:
			if len(mm.Runes) > 0 {
				v.buf.WriteString(string(mm.Runes))
			}
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
	var b strings.Builder
	b.WriteString(titleSt.Render("Login") + "\n\n")
	b.WriteString("Passphrase: ")
	b.WriteString(strings.Repeat("•", v.buf.Len()))
	if v.loading {
		b.WriteString("   " + mutedSt.Render("unlocking…"))
	}
	b.WriteString("\n")
	if v.err != "" {
		b.WriteString("\n" + failSt.Render(v.err) + "\n")
	}
	b.WriteString("\n" + helpSt.Render("enter unlock | esc back"))
	return b.String()
}

// ---------- Issue token ----------

type issueView struct {
	client *admin.Client
	paths  *config.Paths

	step      int
	nameBuf   strings.Builder
	grantsBuf strings.Builder
	expiryBuf strings.Builder
	err       string
	bearer    string
	pin       string
	done      bool
	flash     string

	// Grants step (v1.6.1) — pick-from-list, following TUI_GUIDELINES
	// "List-picker views" rules. Falls back to text entry when the
	// vault has no grants declared yet.
	// v1.8: rows carry an optional project header. A grant belonging
	// to multiple projects appears in each project's section — but the
	// selection map is keyed by grant ID, so choosing it once counts
	// everywhere.
	grantRows     []grantRow
	grantList     []string        // legacy: unique IDs for fallback callers
	grantByID     map[string]tuiGrantInfo
	grantSelected map[string]bool // key = grant id
	grantCursor   int             // index into grantRows (skips headers)

	// v1.13: capture allow-file-keys prefs at construction time so
	// handoff text + background-reseal watcher know whether this
	// token is destined for a P-256 agent that can do ECDH.
	prefs       Prefs
	subject     string // v1.13: remembered name to drive reseal / detail polls
	resealFlash string // v1.13: filled by the background auto-reseal watcher
	pollCount   int    // v1.13: bounded loop for the auto-reseal poller

	// v1.13.0-rc5 — expiry presets. Step 2 is a picker over
	// expiryPresets. Last entry is "custom…" which drops into the
	// text input (expiryBuf). expiryPickCursor tracks which preset
	// is highlighted; expiryCustom is true once the user picks
	// custom and starts typing.
	expiryPickCursor int
	expiryCustom     bool

	// v1.14.0-rc2 — portable toggle. Step 3 is a picker over
	// portablePresets (yes/no). When yes, the issue subprocess
	// receives --portable so the bearer gets age-wrapped on the
	// capability record for later `dop use <subject>` recall.
	portableChoice     bool
	portablePickCursor int

	// rc6c — passphrase step for protected grants (rc3-smoke-retakes [S2]).
	// Shown as field 4 ONLY when at least one selected grant is protected.
	// Otherwise step 3 (portable) commits directly to issue(). The typed
	// value is piped to the subprocess via --passphrase-stdin.
	protectedPassBuf strings.Builder

	// dop-9ms — success-screen guard. The bearer is shown once, so a
	// stray key must not dismiss it: enter confirms "saved", esc needs
	// a second press, c re-copies. copied/copyNote reflect the last
	// clipboard attempt (done in Update, not on every View repaint).
	copied     bool
	copyNote   string
	leaveArmed bool
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
	Prefix      string   // resolved via EffectivePrefix()
	Tags        []string
	Projects    []string
	// rc6c — carried so the issue flow can detect protected grants and
	// insert a passphrase step before shelling out. CLI's issue path
	// uses promptProtectionPassphrase which reads from a tty; without
	// --passphrase-stdin + a piped passphrase, it errors on the TUI's
	// non-tty subprocess stdin. See rc3-smoke-retakes [S2].
	Protected bool
}

func newIssueView(c *admin.Client, p *config.Paths) *issueView {
	v := &issueView{client: c, paths: p, grantSelected: map[string]bool{}, prefs: LoadPrefs(p)}
	v.expiryBuf.WriteString("72h") // sensible default
	// Try to load available grants from the vault for UX.
	v.grantList, v.grantRows, v.grantByID = loadGrantsForList(c, p)
	// Advance initial cursor past any leading header row.
	for i, r := range v.grantRows {
		if !r.isHeader {
			v.grantCursor = i
			break
		}
	}
	// v1.13.0-rc5: start expiry picker on 72h (the current default).
	v.expiryPickCursor = 0
	return v
}

// expiryPresets lists the preset expiry choices offered on the issue
// step 2. The last entry drops into the free-text input via
// expiryCustom.
var expiryPresets = []struct {
	label string
	value string
}{
	{"72h  (3 days — default)", "72h"},
	{"7d   (one week)", "7d"},
	{"30d  (one month)", "30d"},
	{"1y   (one year — 365d)", "365d"},
	{"never (no expiry — revoke manually)", "never"},
	{"custom…", ""},
}

// portablePresets drives the Portable step (v1.14.0-rc2). Yes stashes
// an age-wrapped bearer on the capability so the issuing admin can
// later `dop use <subject>` from any shell on any of their machines.
// Only the issuing admin's daemon can unwrap — other admins can't.
var portablePresets = []struct {
	label string
	value bool
	hint  string
}{
	{"no", false, "default · bearer shown once, you copy it yourself"},
	{"yes", true, "keep a copy for your own shell · run `dop use <subject>` later to export it"},
}

// grantsListMode returns true when we should show the picker instead
// of the fallback text field.
func (v *issueView) grantsListMode() bool { return len(v.grantList) > 0 }

// syncGrantsBuf reflects the current selection into grantsBuf so the
// downstream `dop token issue` call sees the CSV.
func (v *issueView) syncGrantsBuf() {
	v.grantsBuf.Reset()
	first := true
	for _, g := range v.grantList {
		if !v.grantSelected[g] {
			continue
		}
		if !first {
			v.grantsBuf.WriteString(",")
		}
		v.grantsBuf.WriteString(g)
		first = false
	}
}

// grantCursorMove advances the cursor by delta while skipping header
// rows. Bounds-clamped at both ends.
func (v *issueView) grantCursorMove(delta int) {
	if len(v.grantRows) == 0 {
		return
	}
	i := v.grantCursor + delta
	for i >= 0 && i < len(v.grantRows) {
		if !v.grantRows[i].isHeader {
			v.grantCursor = i
			return
		}
		i += delta
	}
}

// currentGrantID returns the grant id under the cursor, or "" for a header.
func (v *issueView) currentGrantID() string {
	if v.grantCursor < 0 || v.grantCursor >= len(v.grantRows) {
		return ""
	}
	return v.grantRows[v.grantCursor].grantID
}

// currentSection returns the project name the cursor sits under.
func (v *issueView) currentSection() string {
	if v.grantCursor < 0 || v.grantCursor >= len(v.grantRows) {
		return ""
	}
	return v.grantRows[v.grantCursor].project
}

// collidingPrefixes returns a map of prefix → grant-IDs when two or
// more currently-selected grants share the same env prefix.
func (v *issueView) collidingPrefixes() map[string][]string {
	byPrefix := map[string][]string{}
	for gid, on := range v.grantSelected {
		if !on {
			continue
		}
		info, ok := v.grantByID[gid]
		if !ok {
			continue
		}
		byPrefix[info.Prefix] = append(byPrefix[info.Prefix], gid)
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

// rc6c — count protected grants in the current selection. Non-zero
// → inject a passphrase step before issue (rc3-smoke-retakes [S2]).
func (v *issueView) protectedSelectedCount() int {
	n := 0
	for id, sel := range v.grantSelected {
		if !sel {
			continue
		}
		if info, ok := v.grantByID[id]; ok && info.Protected {
			n++
		}
	}
	return n
}

func (v *issueView) selectedGrantCount() int {
	n := 0
	for _, sel := range v.grantSelected {
		if sel {
			n++
		}
	}
	return n
}

func (v *issueView) Init() tea.Cmd { return nil }
func (v *issueView) Done() bool    { return v.done }
func (v *issueView) Flash() string { return v.flash }

type issueResultMsg struct {
	bearer string
	pin    string
	err    string
}

func (v *issueView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch mm := msg.(type) {
	case issueResultMsg:
		if mm.err != "" {
			v.err = mm.err
		} else {
			v.bearer = mm.bearer
			v.pin = mm.pin
			v.step = 100 // success screen
			v.copied = clipboardCopy(v.clipboardText())
			// v1.13 — if allow-file-keys is on, kick off a background
			// poller that watches the record for binding.pubkey to
			// appear (= claim completed) and then runs reseal. Only
			// starts when the PIN flow is in play (step 100 with pin
			// set); unbound tokens skip reseal (no agent to seal to).
			if v.prefs.AllowFileKeys && v.pin != "" {
				return v, v.watchForClaimAndReseal()
			}
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
		if v.step == 100 {
			return v.updateSuccessKey(mm.String())
		}
		switch mm.String() {
		case "esc", "ctrl+c":
			v.done = true
			return v, nil
		}
		// Grants step is a multi-select list when the vault has grants.
		if v.step == 1 && v.grantsListMode() {
			switch mm.String() {
			case "up", "k":
				v.grantCursorMove(-1)
			case "down", "j":
				v.grantCursorMove(+1)
			case " ":
				if id := v.currentGrantID(); id != "" {
					v.grantSelected[id] = !v.grantSelected[id]
				}
			case "a":
				// v1.8: select all in the CURRENT section (project).
				sec := v.currentSection()
				for _, r := range v.grantRows {
					if !r.isHeader && r.project == sec {
						v.grantSelected[r.grantID] = true
					}
				}
			case "A":
				for _, g := range v.grantList {
					v.grantSelected[g] = true
				}
			case "n":
				for _, g := range v.grantList {
					v.grantSelected[g] = false
				}
			case "enter":
				if v.selectedGrantCount() == 0 {
					v.err = "select at least one grant (space to toggle)"
					return v, nil
				}
				if colliders := v.collidingPrefixes(); len(colliders) > 0 {
					lines := make([]string, 0, len(colliders))
					for prefix, gs := range colliders {
						lines = append(lines, prefix+"_TOKEN ← "+strings.Join(gs, ", "))
					}
					v.err = "env prefix collision (last wins silently):\n  " + strings.Join(lines, "\n  ")
					return v, nil
				}
				v.err = ""
				v.syncGrantsBuf()
				v.step++
			}
			return v, nil
		}
		// v1.13.0-rc5 — expiry step: preset picker, unless the user
		// has dropped into the custom text input.
		if v.step == 2 && !v.expiryCustom {
			switch mm.String() {
			case "up", "k":
				if v.expiryPickCursor > 0 {
					v.expiryPickCursor--
				}
			case "down", "j":
				if v.expiryPickCursor < len(expiryPresets)-1 {
					v.expiryPickCursor++
				}
			case "enter", " ":
				sel := expiryPresets[v.expiryPickCursor]
				if sel.value == "" {
					// custom — switch to text input, prefill empty.
					v.expiryCustom = true
					v.expiryBuf.Reset()
					return v, nil
				}
				v.expiryBuf.Reset()
				v.expiryBuf.WriteString(sel.value)
				return v.advance()
			}
			return v, nil
		}
		// v1.14.0-rc2 — portable step: yes/no picker.
		if v.step == 3 {
			switch mm.String() {
			case "up", "k":
				if v.portablePickCursor > 0 {
					v.portablePickCursor--
				}
			case "down", "j":
				if v.portablePickCursor < len(portablePresets)-1 {
					v.portablePickCursor++
				}
			case "enter", " ":
				v.portableChoice = portablePresets[v.portablePickCursor].value
				return v.advance()
			}
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
			} else if v.step == 2 && v.expiryCustom {
				// empty custom buffer + backspace → return to preset picker.
				v.expiryCustom = false
			}
		default:
			if len(mm.Runes) > 0 {
				v.currentBuf().WriteString(string(mm.Runes))
			}
		}
	}
	return v, nil
}

func (v *issueView) currentBuf() *strings.Builder {
	switch v.step {
	case 0:
		return &v.nameBuf
	case 1:
		return &v.grantsBuf
	case 2:
		return &v.expiryBuf
	case 4:
		return &v.protectedPassBuf
	}
	return &strings.Builder{}
}

func (v *issueView) advance() (tea.Model, tea.Cmd) {
	val := strings.TrimSpace(v.currentBuf().String())
	// Step 0/1 require a buffer value; step 2 is the expiry picker and
	// step 3 is the portable picker — both commit via Update's picker
	// path, so the buffer check doesn't apply.
	// rc6c — step 4 is the protected-grant passphrase, required when
	// any selected grant is protected (rc3-smoke-retakes [S2]). Text
	// input, must be non-empty.
	if val == "" && v.step != 2 && v.step != 3 {
		return v, nil
	}
	v.step++
	// After portable step: if any selected grant is protected, insert
	// the passphrase step; else go straight to issue.
	if v.step == 4 && v.protectedSelectedCount() == 0 {
		return v, v.issue()
	}
	if v.step == 5 {
		return v, v.issue()
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
	subject := v.subject
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
			// Transient — just reschedule. If the daemon is really down
			// the subsequent polls will fail the same way; we don't
			// escalate because the user is already looking at a success
			// screen.
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
	name := strings.TrimSpace(v.nameBuf.String())
	grants := strings.TrimSpace(v.grantsBuf.String())
	expires := strings.TrimSpace(v.expiryBuf.String())
	if expires == "" {
		expires = "72h"
	}
	v.subject = name
	prefs := v.prefs
	portable := v.portableChoice
	// rc6c — pipe protected-grant passphrase when any grant is protected.
	// Non-empty only after the step 4 passphrase field was shown.
	protectedPass := v.protectedPassBuf.String()
	needsPass := v.protectedSelectedCount() > 0
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

// clipboardText is what the success screen puts on the clipboard: the
// agent handoff for PIN-bound tokens, the bare bearer otherwise.
func (v *issueView) clipboardText() string {
	if v.pin != "" {
		return buildHandoffText(v.bearer, v.pin, v.prefs.AllowFileKeys)
	}
	return v.bearer
}

// updateSuccessKey handles keys on the one-time bearer screen
// (dop-9ms). Only enter, or esc pressed twice, leaves; c re-copies;
// everything else is ignored so a stray keypress can't lose the bearer.
func (v *issueView) updateSuccessKey(key string) (tea.Model, tea.Cmd) {
	switch key {
	case "enter":
		v.done = true
		v.flash = "issue: token issued"
	case "esc", "ctrl+c":
		if v.leaveArmed {
			v.done = true
			v.flash = "issue: token issued — bearer will not be shown again"
			return v, nil
		}
		v.leaveArmed = true
	case "c":
		v.copied = clipboardCopy(v.clipboardText())
		if v.copied {
			v.copyNote = "copied again"
		} else {
			v.copyNote = "copy failed — select the text above manually"
		}
		v.leaveArmed = false
	default:
		v.leaveArmed = false
	}
	return v, nil
}

func (v *issueView) View() string {
	var b strings.Builder
	b.WriteString(titleSt.Render("Issue token") + "\n\n")
	if v.step == 100 {
		b.WriteString(okSt.Render("✓ issued") + "\n\n")
		if v.pin != "" {
			// PIN-bound: prefer the one-liner your agent will actually run.
			b.WriteString("Bearer + PIN (shown ONCE — copy now):\n")
			b.WriteString("  " + lipgloss.NewStyle().Bold(true).Render(v.bearer) + "\n")
			b.WriteString("  " + lipgloss.NewStyle().Bold(true).Render(v.pin) + "\n\n")
			// v1.9.3: agent-optimized clipboard — direct instructions
			// the agent can act on without back-and-forth.
			// v1.13: when allow-file-keys is on, instruct the agent to
			// claim with --key-type p256 so the token is immediately
			// eligible for direct-availability (reseal / add-grant / rotate).
			// v1.13.0-rc10: dropped --json from the primary claim command
			// (the human output includes the explicit "attach QR to chat"
			// prose an LLM agent handles better than parsing JSON events).
			// --json stays on the --status polling command — that one IS
			// machine-parsed by the agent for progress updates.
			// v1.13.0-rc14 — HANDOFF SHAPE CONTRACT (see
			// _rules/_requirements/contracts/13_handoff_text_shape.md).
			// Built via buildHandoffText so a unit test can grep-assert
			// the shape (no forbidden phrases, exactly one claim command).
			b.WriteString(mutedSt.Render(v.clipboardText()) + "\n\n")
			if v.copied {
				b.WriteString(okSt.Render("agent handoff copied to clipboard — paste into the agent chat") + "\n")
			}
			if v.prefs.AllowFileKeys {
				b.WriteString(mutedSt.Render("\nAllow-file-keys ON → this handoff forces P-256. After the agent claims,\n") +
					mutedSt.Render("the TUI auto-reseals so add-grant / remove-grant / rotate work immediately.\n"))
				if v.resealFlash != "" {
					b.WriteString(okSt.Render("\n"+v.resealFlash) + "\n")
				} else {
					b.WriteString(helpSt.Render("\n⋯ waiting for agent claim to auto-reseal …") + "\n")
				}
			}
		} else {
			b.WriteString("Bearer (shown ONCE — copy now):\n")
			b.WriteString("  " + lipgloss.NewStyle().Bold(true).Render(v.bearer) + "\n\n")
			if v.copied {
				b.WriteString(okSt.Render("copied to clipboard") + "\n\n")
			}
			b.WriteString(mutedSt.Render("then: export DOP_TOKEN="+v.bearer) + "\n")
		}
		if v.copyNote != "" {
			st := okSt
			if !v.copied {
				st = failSt
			}
			b.WriteString("\n" + st.Render(v.copyNote) + "\n")
		}
		if v.leaveArmed {
			b.WriteString("\n" + failSt.Render("leave without saving? the bearer won't be shown again — esc again to leave"))
			b.WriteString("\n" + helpSt.Render("c copy · enter I've saved it · esc leave"))
		} else {
			b.WriteString("\n" + helpSt.Render("c copy again · enter I've saved it — back to menu"))
		}
		return b.String()
	}
	portableLabel := "no"
	if v.portableChoice {
		portableLabel = "yes"
	}
	labels := []string{"Subject (label)", "Grants", "Expires", "Portable"}
	values := []string{v.nameBuf.String(), v.grantsBuf.String(), v.expiryBuf.String(), portableLabel}

	// Steps 0 and 2 render specially. Step 1 renders as a
	// picker when the vault has grants, otherwise text-entry.
	// v1.13.0-rc5: step 2 defaults to a preset picker; drops into
	// text input only when the user picks "custom…".
	// v1.14.0-rc2: step 3 is the portable picker (yes/no).
	pickerAtStep1 := v.step == 1 && v.grantsListMode()
	pickerAtStep2 := v.step == 2 && !v.expiryCustom
	pickerAtStep3 := v.step == 3

	for i, l := range labels {
		if i == 1 && pickerAtStep1 {
			// Skip the text-entry row for grants; the picker renders below.
			continue
		}
		if i == 2 && pickerAtStep2 {
			// Skip; the preset picker renders below.
			continue
		}
		if i == 3 && pickerAtStep3 {
			// Skip; the portable picker renders below.
			continue
		}
		style := mutedSt
		if i == v.step {
			style = cursorSt
		}
		b.WriteString(style.Render(l) + ": ")
		if i == 1 {
			// Show the currently committed selection when NOT on this step.
			b.WriteString(values[i])
		} else {
			b.WriteString(values[i])
			if i == v.step {
				b.WriteString(cursorSt.Render("▎"))
			}
		}
		b.WriteString("\n")
	}

	if pickerAtStep1 {
		b.WriteString("\n")
		b.WriteString(cursorSt.Render("Grants") + "  " +
			mutedSt.Render(fmt.Sprintf("%d/%d selected", v.selectedGrantCount(), len(v.grantList))) +
			"\n")
		var lastSection string
		firstSection := true
		for i, row := range v.grantRows {
			if row.isHeader {
				if !firstSection {
					b.WriteString("\n")
				}
				firstSection = false
				lastSection = row.project
				label := "project · " + row.project
				if row.project == "(ungrouped)" {
					label = row.project
				}
				b.WriteString("  " + mutedSt.Render(label) + "\n")
				continue
			}
			_ = lastSection
			cursor := "    "
			labelStyle := lipgloss.NewStyle()
			if i == v.grantCursor {
				cursor = "  " + cursorSt.Render("➤ ")
				labelStyle = cursorSt
			}
			mark := "○"
			if v.grantSelected[row.grantID] {
				mark = okSt.Render("●")
			}
			// Right-column hint: env prefix + optional tags.
			info := v.grantByID[row.grantID]
			hint := info.Prefix + "_TOKEN"
			if len(info.Tags) > 0 {
				hint += "  " + strings.Join(info.Tags, ",")
			}
			b.WriteString(cursor + mark + " " + labelStyle.Render(row.grantID) +
				"  " + mutedSt.Render(hint) + "\n")
		}
		// Live collision warning.
		if colliders := v.collidingPrefixes(); len(colliders) > 0 {
			b.WriteString("\n")
			b.WriteString(failSt.Render("⚠ env prefix collision:") + "\n")
			prefixes := make([]string, 0, len(colliders))
			for p := range colliders {
				prefixes = append(prefixes, p)
			}
			sort.Strings(prefixes)
			for _, p := range prefixes {
				b.WriteString(mutedSt.Render("  " + p + "_TOKEN ← " + strings.Join(colliders[p], ", ")) + "\n")
			}
		}
	} else if len(v.grantList) == 0 && v.step == 1 {
		b.WriteString("\n" + mutedSt.Render("no grants defined in vault — type them manually") + "\n")
	}

	// v1.13.0-rc5: expiry preset picker on step 2 (unless custom).
	if pickerAtStep2 {
		b.WriteString("\n" + cursorSt.Render("Expires") + "\n")
		for i, p := range expiryPresets {
			prefix := "    "
			label := p.label
			if i == v.expiryPickCursor {
				prefix = "  " + cursorSt.Render("➤ ")
				label = cursorSt.Render(p.label)
			}
			b.WriteString(prefix + label + "\n")
		}
	}

	// v1.14.0-rc2: portable picker on step 3.
	if pickerAtStep3 {
		b.WriteString("\n" + cursorSt.Render("Portable") + "  " +
			mutedSt.Render("· keep a copy for your own shell, recoverable later with `dop use`") + "\n")
		for i, p := range portablePresets {
			prefix := "    "
			label := p.label
			hint := mutedSt.Render(p.hint)
			if i == v.portablePickCursor {
				prefix = "  " + cursorSt.Render("➤ ")
				label = cursorSt.Render(p.label)
			}
			b.WriteString(prefix + label + "  " + hint + "\n")
		}
	}

	// rc6c — step 4: approval passphrase for protected grants.
	if v.step == 4 && v.protectedSelectedCount() > 0 {
		masked := strings.Repeat("•", v.protectedPassBuf.Len())
		hint := fmt.Sprintf("approval passphrase (issue bearer containing %d protected grant(s))", v.protectedSelectedCount())
		b.WriteString("\n" + cursorSt.Render("Approval passphrase") + "  " + mutedSt.Render("· "+hint) + "\n")
		b.WriteString("    " + masked + cursorSt.Render("▎") + "\n")
	}

	if pickerAtStep1 {
		b.WriteString("\n" + helpSt.Render("↑↓ move | space toggle | a section | A all | n none | enter next | esc cancel"))
	} else if pickerAtStep2 {
		b.WriteString("\n" + helpSt.Render("↑↓ move | enter select | esc cancel"))
	} else if v.step == 2 && v.expiryCustom {
		b.WriteString("\n" + helpSt.Render("type duration (e.g. 72h, 30d) · backspace at empty returns to presets · enter submit · esc cancel"))
	} else if pickerAtStep3 {
		b.WriteString("\n" + helpSt.Render("↑↓ move | enter select | esc cancel"))
	} else {
		b.WriteString("\n" + helpSt.Render("enter next | esc cancel"))
	}
	if v.err != "" {
		b.WriteString("\n" + failSt.Render(v.err))
	}
	return b.String()
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
	pendingAction string // "revoke" while confirming
	showAll       bool   // false → hide revoked
	err           string
	flash         string

	// v1.13.0-rc3 — grant-picker state for in-TUI add-grant / remove-grant
	// on an existing token's detail. grantPickList is the list of candidate
	// grant IDs; pendingGrantOp is "add" or "remove".
	// v1.13.0-rc5: grantPickSelected tracks the multi-select set
	// (space toggles, enter applies all). Previous releases were
	// single-select — picking one grant per round.
	grantPickList     []string
	grantPickCursor   int
	grantPickSelected map[string]bool
	pendingGrantOp    string
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
}

// repinTTLPresets — common PIN validity windows offered on repin.
// v1.13.0-rc11: reordered + default moved from 5m to 1h after
// ClaudeMini field report (5m was expiring during chat back-and-forth).
var repinTTLPresets = []struct {
	label string
	value string
}{
	{"1h (default — chat-friendly)", "1h"},
	{"5m (CLI handoff)", "5m"},
	{"30m", "30m"},
	{"4h", "4h"},
	{"24h", "24h"},
}

// v1.10.0 — the tokens list is now an interactive picker. Modes:
//
//	listModeList    ↑↓ pick, enter → action menu, a toggle show-all,
//	                r quick-revoke, esc back
//	listModeAction  ↑↓ pick action, enter → run, backspace/esc back
//	listModeConfirm y/n confirm destructive
//	listModeRun     subprocess in flight
//	listModeDetail  full row, esc back
const (
	listModeList       = 0
	listModeAction     = 1
	listModeConfirm    = 2
	listModeRun        = 3
	listModeDetail     = 4
	listModeGrantPick  = 5 // v1.13.0-rc3 — add-grant / remove-grant picker
	listModeRepin      = 6 // v1.13.0-rc9 — bearer + PIN TTL form, then result
	listModeRepinDone  = 7 // v1.13.0-rc9 — show new PIN + copy to clipboard
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
			return listLoadedMsg{err: renderNoVault("tokens")}
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
	return listLoadedMsg{capabilities: caps, capIDs: ids, viewerPubkey: viewerPubkey}
}

// visible returns the indexes into v.capabilities that should be shown
// under the current filter (revoked hidden unless showAll).
func (v *listView) visible() []int {
	out := []int{}
	for i, c := range v.capabilities {
		if !v.showAll && c.Status != capability.RecordStatusActive {
			continue
		}
		out = append(out, i)
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
	acts := []listAction{{label: "View details", key: "d"}}
	if c.Status == capability.RecordStatusActive {
		// v1.13 — reseal is admin-only and only meaningful for
		// claimed P-256 bearers. We offer it unconditionally; the
		// CLI gatekeeps and prints a clear error on ineligible
		// bearers.
		acts = append(acts, listAction{label: "Reseal env", key: "s"})
		// v1.13.0-rc3 — add-grant / remove-grant via the token
		// detail. Both route through the CLI (same code path as
		// `dop token add-grant` / `remove-grant`), which gatekeeps on
		// P-256 binding and surfaces an actionable error if the
		// bearer isn't eligible.
		acts = append(acts, listAction{label: "Add grant", key: "+"})
		acts = append(acts, listAction{label: "Remove grant", key: "-"})
		// v1.13.0-rc9 — Repin surfaced for PIN-bound bearers whose
		// pubkey hasn't been filled in yet (= still waiting for the
		// agent to claim). After claim the bundle's PIN hash is
		// irrelevant, so we hide the action.
		if c.Binding != nil && c.Binding.Kind == "pin" && c.Binding.Pubkey == "" {
			acts = append(acts, listAction{label: "Repin (new PIN for unclaimed bearer)", key: "p"})
		}
		acts = append(acts, listAction{label: "Revoke", key: "r", destructive: true})
	}
	acts = append(acts, listAction{label: "Back to list", key: "b"})
	return acts
}

type listAction struct {
	label       string
	key         string
	destructive bool
}

func (v *listView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch mm := msg.(type) {
	case listLoadedMsg:
		v.loaded = true
		v.capabilities = mm.capabilities
		v.capIDs = mm.capIDs
		v.viewerPubkey = mm.viewerPubkey
		v.loadErr = mm.err
	case listActionMsg:
		if mm.err != "" {
			v.err = mm.err
			v.mode = listModeAction
			return v, nil
		}
		if mm.flash != "" {
			v.flash = mm.flash
		} else {
			v.flash = "revoked · synced with team — reloading list"
		}
		v.mode = listModeList
		v.err = ""
		return v, v.load
	case repinSuccessMsg:
		v.repinNewPin = mm.pin
		v.repinNewExpires = mm.expires
		v.repinBearerBuf.Reset() // scrub bearer from memory
		v.mode = listModeRepinDone
		return v, nil
	case tea.KeyMsg:
		if !v.loaded {
			if mm.String() == "esc" || mm.String() == "ctrl+c" {
				v.done = true
			}
			return v, nil
		}
		switch v.mode {
		case listModeList:
			return v.updateListMode(mm)
		case listModeAction:
			return v.updateActionMode(mm)
		case listModeConfirm:
			return v.updateConfirmMode(mm)
		case listModeGrantPick:
			return v.updateGrantPickMode(mm)
		case listModeRepin:
			return v.updateRepinMode(mm)
		case listModeRepinDone:
			// Any key dismisses — return to the list for a fresh load.
			v.mode = listModeList
			return v, v.load
		case listModeDetail:
			// v1.13.0-rc4 — nested esc: detail's parent is the action
			// menu, so esc goes there (not all the way back to list).
			// Any other key also returns to action menu — users
			// typically expect "any key" from a view-only pane.
			v.mode = listModeAction
		}
	}
	return v, nil
}

func (v *listView) updateListMode(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	vis := v.visible()
	switch mm.String() {
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
	case "a":
		v.showAll = !v.showAll
		v.cursor = 0
	case "enter":
		if len(vis) == 0 {
			return v, nil
		}
		v.mode = listModeAction
		v.actionCursor = 0
	case "r":
		// quick-revoke shortcut when the row is active.
		idx := v.selectedIndex()
		if idx < 0 {
			return v, nil
		}
		if v.capabilities[idx].Status != capability.RecordStatusActive {
			return v, nil
		}
		v.mode = listModeConfirm
		v.pendingAction = "revoke"
	case "d":
		if v.selectedIndex() >= 0 {
			v.mode = listModeDetail
		}
	}
	return v, nil
}

func (v *listView) updateActionMode(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	acts := v.currentActions()
	switch mm.String() {
	case "esc", "backspace":
		v.mode = listModeList
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
	switch a.key {
	case "d":
		v.mode = listModeDetail
	case "r":
		v.mode = listModeConfirm
		v.pendingAction = "revoke"
	case "s":
		// v1.13 — reseal doesn't need confirmation (non-destructive).
		v.mode = listModeRun
		return v, v.doReseal()
	case "p":
		// v1.13.0-rc9 — Repin: open the bearer+TTL form.
		v.mode = listModeRepin
		v.repinField = 0
		v.repinBearerBuf.Reset()
		v.repinTTLCursor = 0
		v.err = ""
	case "+":
		// v1.13.0-rc3 — load vault grants minus the ones already on
		// this token, open the picker.
		if !v.prepareGrantPicker("add") {
			v.err = "no grants in the vault to add — add one first via Vault → Add grant"
			return v, nil
		}
		v.mode = listModeGrantPick
	case "-":
		if !v.prepareGrantPicker("remove") {
			v.err = "this token has no grants to remove"
			return v, nil
		}
		v.mode = listModeGrantPick
	case "b":
		v.mode = listModeList
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
	v.pendingGrantOp = op
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
	op := v.pendingGrantOp
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
		verb := "added"
		if op == "remove" {
			verb = "removed"
		}
		return listActionMsg{flash: fmt.Sprintf("%s %d grant(s): %s · env resealed", verb, len(applied), strings.Join(applied, ", "))}
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
				v.err = "approval passphrase required for the protected grant(s)"
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
			v.err = "select at least one grant (space to toggle)"
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
		v.pendingGrantOp = ""
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
				v.err = "bearer required (paste it here)"
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
//   dop token repin: reissued PIN for X (valid 5m0s)
//     new PIN (shown ONCE):
//   XX-XX-XX
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
	var b strings.Builder
	// v1.13.0-rc20 — Mole-style title + muted count subtitle. Shows
	// visible count (either active or all, depending on toggle).
	vis := v.visible()
	activeCount := 0
	for _, c := range v.capabilities {
		if c.Status == capability.RecordStatusActive {
			activeCount++
		}
	}
	subtitle := fmt.Sprintf("%d active · %d total", activeCount, len(v.capabilities))
	b.WriteString(titleSt.Render("Bearers") + "   " + mutedSt.Render(subtitle) + "\n\n")
	if !v.loaded {
		b.WriteString("loading…")
		return b.String()
	}
	if v.loadErr != "" {
		b.WriteString(failSt.Render(v.loadErr))
		b.WriteString("\n\n" + helpSt.Render("esc back"))
		return b.String()
	}

	switch v.mode {
	case listModeDetail:
		return v.viewDetail()
	case listModeConfirm:
		return v.viewConfirm()
	case listModeRun:
		return v.viewRun()
	case listModeGrantPick:
		return v.viewGrantPick()
	case listModeRepin:
		return v.viewRepin()
	case listModeRepinDone:
		return v.viewRepinDone()
	}

	if len(vis) == 0 {
		if v.showAll {
			b.WriteString(mutedSt.Render("(no capabilities issued)"))
		} else {
			b.WriteString(mutedSt.Render("(no active capabilities — press `a` to include revoked)"))
		}
	}
	// v1.13.0-rc20 — dynamic label width.
	labelWidth := 16
	for _, capIdx := range vis {
		if w := lipgloss.Width(v.capabilities[capIdx].Subject); w > labelWidth {
			labelWidth = w
		}
	}
	labelWidth += 2
	for i, capIdx := range vis {
		c := v.capabilities[capIdx]
		statusStyle := okSt
		if c.Status == capability.RecordStatusRevoked {
			statusStyle = failSt
		}
		prefix := "    "
		subj := c.Subject
		if i == v.cursor && v.mode == listModeList {
			prefix = "  " + cursorSt.Render("➤ ")
			subj = cursorSt.Render(subj)
		}
		// v1.14.0-rc3 — ownership glyph is gated on OWNER-EXCLUSIVITY,
		// not merely on IssuedBy. The glyph only appears when a lock
		// relationship actually exists: today that's portable (bearer
		// stash wrapped to one admin's age recipient); after Phase 3
		// protection migration lands, also when any grant on this
		// capability is protected. 👤 = owner-locked to this viewer;
		// 🔒 = owner-locked to another admin. Slot is pinned to a
		// fixed cell width via lipgloss.Width so terminals that render
		// emoji at 1 cell don't shift the following columns.
		ownerRaw := ""
		ownerExclusive := c.PortableWrapped != ""
		if ownerExclusive && c.IssuedBy != "" && v.viewerPubkey != "" {
			if c.IssuedBy == v.viewerPubkey {
				ownerRaw = "👤"
			} else {
				ownerRaw = "🔒"
			}
		}
		ownerGlyph := lipgloss.NewStyle().Width(3).Render(ownerRaw)
		// v1.14.0-rc2 — portable prefix. `p.` on the name column when
		// the capability carries an admin-use stash. Dim style so it's
		// noticeable but not loud. Width-pinned at 3 cells.
		portRaw := ""
		if c.PortableWrapped != "" {
			portRaw = mutedSt.Render("p.")
		}
		portPrefix := lipgloss.NewStyle().Width(3).Render(portRaw)
		// v1.13 — surface the cap-id prefix in every row so two
		// tokens sharing a subject are visibly distinct. Without
		// this they looked identical in the TUI and only the first
		// could be acted on.
		capShort := v.capIDs[capIdx]
		if len(capShort) > 8 {
			capShort = capShort[:8]
		}
		// v1.13.0-rc7 — pad `subj` via lipgloss.NewStyle().Width()
		// instead of `%-24s`. The latter counted ANSI escape bytes
		// toward the field width, so the cursor-styled row ended up
		// visually narrower and following columns shifted leftward
		// (Fizz's "metadata jumps when the cursor moves" bug).
		// v1.13.0-rc20 — row trimmed to subj + capId + status. gen +
		// expires moved to the status bar.
		subjPad := lipgloss.NewStyle().Width(labelWidth).Render(subj)
		b.WriteString(prefix + ownerGlyph + portPrefix + subjPad + "  " +
			mutedSt.Render(capShort) + "  " +
			statusStyle.Render(c.Status) + "\n")
	}

	// v1.13.0-rc20 — status bar for the cursor row.
	// v1.14.0-rc2 — adds portable + owner markers.
	if len(vis) > 0 && v.cursor >= 0 && v.cursor < len(vis) {
		c := v.capabilities[vis[v.cursor]]
		portable := "no"
		if c.PortableWrapped != "" {
			portable = "yes"
		}
		owner := "—"
		if c.IssuedBy != "" {
			if c.IssuedBy == v.viewerPubkey {
				owner = "you"
			} else if len(c.IssuedBy) >= 8 {
				owner = c.IssuedBy[:8] + "…"
			} else {
				owner = c.IssuedBy
			}
		}
		bar := fmt.Sprintf("%s  ·  gen %d  ·  expires %s  ·  grants %s  ·  portable %s  ·  owner %s",
			c.Subject, c.Generation,
			expiresDisplay(c.ExpiresAt, "2006-01-02"),
			strings.Join(c.Grants, ","),
			portable, owner)
		b.WriteString("\n" + mutedSt.Render(bar) + "\n")
	}

	hidden := len(v.capabilities) - len(vis)
	if hidden > 0 && !v.showAll {
		b.WriteString(mutedSt.Render(fmt.Sprintf("\n  (%d revoked hidden — press `a` to show)\n", hidden)))
	}

	// v1.13.0-rc4 — unified list-view footer: help line first, then
	// error (red) + flash (green) below so operators always see the
	// controls and any status at the same place.
	if v.mode == listModeAction {
		b.WriteString("\n" + v.renderActionMenu())
	} else {
		b.WriteString("\n" + helpSt.Render("↑↓ move | enter actions | esc back") +
			"\n" + helpSt.Render("👤 yours · 🔒 another admin's · p. portable"))
	}
	if v.err != "" {
		b.WriteString("\n" + failSt.Render(v.err))
	}
	if v.flash != "" {
		b.WriteString("\n" + okSt.Render(v.flash))
		v.flash = ""
	}
	return b.String()
}

func (v *listView) renderActionMenu() string {
	idx := v.selectedIndex()
	if idx < 0 {
		return ""
	}
	c := v.capabilities[idx]
	var b strings.Builder
	b.WriteString(mutedSt.Render(fmt.Sprintf("─── actions for %q ───", c.Subject)) + "\n")
	for i, a := range v.currentActions() {
		prefix := "    "
		lbl := a.label
		if i == v.actionCursor {
			prefix = "  " + cursorSt.Render("➤ ")
			lbl = cursorSt.Render(lbl)
			if a.destructive {
				lbl = failSt.Render(a.label)
			}
		} else if a.destructive {
			lbl = failSt.Render(a.label)
		}
		b.WriteString(fmt.Sprintf("%s%s\n", prefix, lbl))
	}
	b.WriteString("\n" + helpSt.Render("↑↓ move | enter run | backspace back"))
	return b.String()
}

func (v *listView) viewDetail() string {
	idx := v.selectedIndex()
	if idx < 0 {
		return "no selection\n\n" + helpSt.Render("esc back")
	}
	c := v.capabilities[idx]
	id := v.capIDs[idx]
	var b strings.Builder
	b.WriteString(titleSt.Render("Token: "+c.Subject) + "\n\n")
	// v1.13.0-rc18 — kvLine for alignment parity with integration +
	// grant detail. Widest label is `capability_id` (13 chars);
	// `bound pubkey` matches it; use 13 as the column width.
	const w = 13
	b.WriteString(kvLine("capability_id", id, w))
	b.WriteString(kvLine("status", c.Status, w))
	b.WriteString(kvLine("generation", fmt.Sprintf("%d", c.Generation), w))
	b.WriteString(kvLine("grants", fmt.Sprintf("%v", c.Grants), w))
	b.WriteString(kvLine("created_at", c.CreatedAt.Format("2006-01-02 15:04 MST"), w))
	b.WriteString(kvLine("expires_at", expiresDisplay(c.ExpiresAt, "2006-01-02 15:04 MST"), w))
	b.WriteString(kvLine("issued_by", c.IssuedBy, w))
	if c.Binding != nil {
		b.WriteString(kvLine("binding", c.Binding.Kind, w))
		if c.Binding.Pubkey != "" {
			b.WriteString(kvLine("bound pubkey", c.Binding.Pubkey[:24]+"…", w))
		} else if c.Binding.Kind == "pin" {
			b.WriteString(mutedSt.Render("  (unclaimed — the agent hasn't run `dop claim` yet)\n"))
		}
	}
	b.WriteString(mutedSt.Render("\n  Grants are baked into the bundle at issue time.\n"))
	b.WriteString(mutedSt.Render("  To change grants → revoke + reissue.\n"))
	b.WriteString(mutedSt.Render("  To change projects/tags on a grant → use `List grants`.\n"))
	b.WriteString("\n" + helpSt.Render("any key back"))
	return b.String()
}

func (v *listView) viewConfirm() string {
	idx := v.selectedIndex()
	if idx < 0 {
		return "no selection"
	}
	c := v.capabilities[idx]
	var b strings.Builder
	b.WriteString(titleSt.Render("Revoke token?") + "\n\n")
	b.WriteString(fmt.Sprintf("  subject: %s\n  grants:  %v\n\n", c.Subject, c.Grants))
	b.WriteString(failSt.Render("This is immediate — the bearer will fail on next exec.") + "\n")
	b.WriteString("\n" + helpSt.Render("y/enter confirm | n/esc cancel"))
	return b.String()
}

func (v *listView) viewRun() string {
	label := "running dop token revoke…"
	switch v.pendingGrantOp {
	case "add":
		label = "running dop token add-grant…"
	case "remove":
		label = "running dop token remove-grant…"
	}
	// v1.13.0-rc9 — detect repin by looking at the buffer state at
	// entry time (we clear it on success, so a non-empty buffer here
	// means the form was in progress before Run).
	if v.repinBearerBuf.Len() > 0 || v.repinField == 1 {
		label = "running dop token repin…"
	}
	return titleSt.Render("Working…") + "\n\n" + mutedSt.Render(label)
}

// viewRepin renders the two-field repin form: bearer paste + TTL
// picker. v1.13.0-rc9.
func (v *listView) viewRepin() string {
	var b strings.Builder
	idx := v.selectedIndex()
	b.WriteString(titleSt.Render("Repin — new PIN for unclaimed bearer") + "\n\n")
	if idx >= 0 {
		b.WriteString(mutedSt.Render("Target: "+v.capabilities[idx].Subject+"  ("+v.capIDs[idx][:12]+"…)") + "\n\n")
	}
	// Bearer field.
	bearerStyle := mutedSt
	if v.repinField == 0 {
		bearerStyle = cursorSt
	}
	b.WriteString(bearerStyle.Render("Paste current bearer (tok_…)") + ":\n")
	bearer := v.repinBearerBuf.String()
	display := strings.Repeat("•", len(bearer))
	b.WriteString("  " + display)
	if v.repinField == 0 {
		b.WriteString(cursorSt.Render("▎"))
	}
	b.WriteString("\n\n")
	// TTL picker.
	ttlStyle := mutedSt
	if v.repinField == 1 {
		ttlStyle = cursorSt
	}
	b.WriteString(ttlStyle.Render("New PIN valid for") + ":\n")
	for i, p := range repinTTLPresets {
		prefix := "    "
		label := p.label
		if v.repinField == 1 && i == v.repinTTLCursor {
			prefix = "  " + cursorSt.Render("➤ ")
			label = cursorSt.Render(p.label)
		}
		b.WriteString(prefix + label + "\n")
	}
	// Help / error footer.
	switch v.repinField {
	case 0:
		b.WriteString("\n" + helpSt.Render("type/paste bearer | enter next | tab switch field | esc back"))
	case 1:
		b.WriteString("\n" + helpSt.Render("↑↓ move | enter submit | tab switch field | esc back"))
	}
	if v.err != "" {
		b.WriteString("\n" + failSt.Render(v.err))
	}
	return b.String()
}

// viewRepinDone shows the new PIN prominently + copies the agent
// handoff command to the clipboard. v1.13.0-rc9.
func (v *listView) viewRepinDone() string {
	var b strings.Builder
	b.WriteString(titleSt.Render("✓ repinned") + "\n\n")
	b.WriteString("New PIN (valid " + v.repinNewExpires + "):\n")
	b.WriteString("  " + lipgloss.NewStyle().Bold(true).Render(v.repinNewPin) + "\n\n")
	b.WriteString(mutedSt.Render("Share this with the agent along with the original bearer.") + "\n")
	if copyToClipboard(v.repinNewPin) {
		b.WriteString(okSt.Render("new PIN copied to clipboard") + "\n")
	}
	b.WriteString("\n" + helpSt.Render("any key back to list"))
	return b.String()
}

// viewGrantPick renders the multi-select grant picker for the
// add-grant / remove-grant actions on a token detail. The list is
// pre-filtered by prepareGrantPicker (vault's grants minus the
// token's current grants, or the token's current grants).
//
// v1.13.0-rc5: multi-select — space toggles ● / ○, a/n bulk ops,
// enter applies the whole selection in one batch.
func (v *listView) viewGrantPick() string {
	var b strings.Builder
	idx := v.selectedIndex()
	title := "Pick grants to add"
	if v.pendingGrantOp == "remove" {
		title = "Pick grants to remove"
	}
	b.WriteString(titleSt.Render(title) + "\n\n")
	if idx >= 0 {
		b.WriteString(mutedSt.Render("Target token: "+v.capabilities[idx].Subject+"  ("+v.capIDs[idx][:12]+"…)") + "\n\n")
	}
	for i, gid := range v.grantPickList {
		prefix := "    "
		marker := "○"
		if v.grantPickSelected[gid] {
			marker = okSt.Render("●")
		} else {
			marker = mutedSt.Render("○")
		}
		label := gid
		if i == v.grantPickCursor {
			prefix = "  " + cursorSt.Render("➤ ")
			label = cursorSt.Render(gid)
		}
		// rc6f — flag protected grants with 🔒 so operators know a
		// passphrase will be requested when they commit the selection.
		lockMark := ""
		if v.grantPickProtectedMap[gid] {
			lockMark = "  " + mutedSt.Render("🔒")
		}
		b.WriteString(prefix + marker + "  " + label + lockMark + "\n")
	}
	// rc6f — passphrase sub-step. Rendered under the picker once the
	// operator has pressed enter AND the selection includes a protected
	// grant. Mirrors the issueView passphrase row.
	if v.grantPickPassPhase {
		b.WriteString("\n")
		n := v.grantPickProtectedCount()
		passLbl := cursorSt.Render(fmt.Sprintf("Approval passphrase (%d protected grant(s))", n))
		before, after := v.grantPickPassBuf.SplitMasked("•")
		b.WriteString(passLbl + ": " + before + cursorSt.Render("▎") + after + "\n")
		b.WriteString("\n" + helpSt.Render("enter apply | ←→ move caret | backspace delete | esc back to picker"))
	} else {
		b.WriteString("\n" + helpSt.Render("↑↓ move | space toggle | a all | n none | enter apply | esc back"))
	}
	if v.err != "" {
		b.WriteString("\n" + failSt.Render(v.err))
	}
	return b.String()
}

// silence unused imports pinned to future views
var _ = hex.EncodeToString
var _ = io.Discard
