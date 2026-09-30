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
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1")
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
	b.WriteString("\n" + helpSt.Render("enter unlock · esc back"))
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
}

func newIssueView(c *admin.Client, p *config.Paths) *issueView {
	v := &issueView{client: c, paths: p, grantSelected: map[string]bool{}}
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
	return v
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
		}
		return v, nil
	case tea.KeyMsg:
		switch mm.String() {
		case "esc", "ctrl+c":
			v.done = true
			return v, nil
		}
		if v.step == 100 {
			// Any key from bearer display → done
			v.done = true
			v.flash = "issue: bearer copied to clipboard? make sure — it's shown once"
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

func (v *issueView) currentBuf() *strings.Builder {
	switch v.step {
	case 0:
		return &v.nameBuf
	case 1:
		return &v.grantsBuf
	case 2:
		return &v.expiryBuf
	}
	return &strings.Builder{}
}

func (v *issueView) advance() (tea.Model, tea.Cmd) {
	val := strings.TrimSpace(v.currentBuf().String())
	if val == "" && v.step != 2 {
		return v, nil
	}
	v.step++
	if v.step == 3 {
		return v, v.issue()
	}
	return v, nil
}

func (v *issueView) issue() tea.Cmd {
	name := strings.TrimSpace(v.nameBuf.String())
	grants := strings.TrimSpace(v.grantsBuf.String())
	expires := strings.TrimSpace(v.expiryBuf.String())
	if expires == "" {
		expires = "72h"
	}
	return func() tea.Msg {
		self, err := os.Executable()
		if err != nil {
			return issueResultMsg{err: err.Error()}
		}
		cmd := exec.Command(self, "token", "issue", "--grants", grants, "--name", name, "--expires", expires)
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1")
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
			handoff := "You have been given scoped credential access via DOP.\n\n" +
				"Run this in your shell:\n\n" +
				"  DOP_TOKEN=" + v.bearer + " dop claim --json " + v.pin
			b.WriteString(mutedSt.Render(handoff) + "\n\n")
			if copyToClipboard(handoff) {
				b.WriteString(okSt.Render("agent handoff copied to clipboard — paste into the agent chat") + "\n")
			}
		} else {
			b.WriteString("Bearer (shown ONCE — copy now):\n")
			b.WriteString("  " + lipgloss.NewStyle().Bold(true).Render(v.bearer) + "\n\n")
			if copyToClipboard(v.bearer) {
				b.WriteString(okSt.Render("copied to clipboard") + "\n\n")
			}
			b.WriteString(mutedSt.Render("then: export DOP_TOKEN="+v.bearer) + "\n")
		}
		b.WriteString("\n" + helpSt.Render("any key to return to menu"))
		return b.String()
	}
	labels := []string{"Subject (label)", "Grants", "Expires (e.g. 72h, 30d)"}
	values := []string{v.nameBuf.String(), v.grantsBuf.String(), v.expiryBuf.String()}

	// Steps 0 and 2 always render as text-entry. Step 1 renders as a
	// picker when the vault has grants, otherwise text-entry.
	pickerAtStep1 := v.step == 1 && v.grantsListMode()

	for i, l := range labels {
		if i == 1 && pickerAtStep1 {
			// Skip the text-entry row for grants; the picker renders below.
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

	if v.err != "" {
		b.WriteString("\n" + failSt.Render(v.err) + "\n")
	}
	if pickerAtStep1 {
		b.WriteString("\n" + helpSt.Render("↑↓ move · space toggle · a section · A all · n none · enter next · esc cancel"))
	} else {
		b.WriteString("\n" + helpSt.Render("enter next · esc cancel"))
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

	// v1.10.0 picker state
	mode          int    // listMode*
	cursor        int    // index into visible()
	actionCursor  int    // index into currentActions()
	pendingAction string // "revoke" while confirming
	showAll       bool   // false → hide revoked
	err           string
	flash         string
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
	listModeList    = 0
	listModeAction  = 1
	listModeConfirm = 2
	listModeRun     = 3
	listModeDetail  = 4
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
	err          string
}
type listActionMsg struct{ err string }

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
	return listLoadedMsg{capabilities: caps, capIDs: ids}
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
		v.loadErr = mm.err
	case listActionMsg:
		if mm.err != "" {
			v.err = mm.err
			v.mode = listModeAction
			return v, nil
		}
		v.flash = "revoked · synced with team — reloading list"
		v.mode = listModeList
		v.err = ""
		return v, v.load
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
		case listModeDetail:
			// any key → back to list
			v.mode = listModeList
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
	case "b":
		v.mode = listModeList
	}
	return v, nil
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
	subject := v.capabilities[idx].Subject
	return func() tea.Msg {
		self, _ := os.Executable()
		cmd := exec.Command(self, "token", "revoke", subject)
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1")
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
	b.WriteString(titleSt.Render("Tokens") + "\n\n")
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
	}

	vis := v.visible()
	if len(vis) == 0 {
		if v.showAll {
			b.WriteString(mutedSt.Render("(no capabilities issued)"))
		} else {
			b.WriteString(mutedSt.Render("(no active capabilities — press `a` to include revoked)"))
		}
	}
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
		b.WriteString(fmt.Sprintf("%s%-24s  %s  gen=%d  expires=%s\n",
			prefix, subj,
			statusStyle.Render(c.Status),
			c.Generation,
			c.ExpiresAt.Format("2006-01-02")))
	}

	hidden := len(v.capabilities) - len(vis)
	if hidden > 0 && !v.showAll {
		b.WriteString(mutedSt.Render(fmt.Sprintf("\n  (%d revoked hidden — press `a` to show)\n", hidden)))
	}

	if v.err != "" {
		b.WriteString("\n" + failSt.Render(v.err) + "\n")
	}
	if v.flash != "" {
		b.WriteString("\n" + okSt.Render(v.flash) + "\n")
		v.flash = ""
	}

	if v.mode == listModeAction {
		b.WriteString("\n" + v.renderActionMenu())
	} else {
		b.WriteString("\n" + helpSt.Render("↑↓ move · enter actions · d details · r revoke · a all · esc back"))
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
	b.WriteString("\n" + helpSt.Render("↑↓ move · enter run · backspace back"))
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
	b.WriteString(fmt.Sprintf("  capability_id: %s\n", id))
	b.WriteString(fmt.Sprintf("  status:        %s\n", c.Status))
	b.WriteString(fmt.Sprintf("  generation:    %d\n", c.Generation))
	b.WriteString(fmt.Sprintf("  grants:        %v\n", c.Grants))
	b.WriteString(fmt.Sprintf("  created_at:    %s\n", c.CreatedAt.Format("2006-01-02 15:04 MST")))
	b.WriteString(fmt.Sprintf("  expires_at:    %s\n", c.ExpiresAt.Format("2006-01-02 15:04 MST")))
	b.WriteString(fmt.Sprintf("  issued_by:     %s\n", c.IssuedBy))
	if c.Binding != nil {
		b.WriteString(fmt.Sprintf("  binding:       %s\n", c.Binding.Kind))
		if c.Binding.Pubkey != "" {
			b.WriteString(fmt.Sprintf("  bound pubkey:  %s…\n", c.Binding.Pubkey[:24]))
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
	b.WriteString("\n" + helpSt.Render("y confirm · n cancel"))
	return b.String()
}

func (v *listView) viewRun() string {
	return titleSt.Render("Revoking…") + "\n\n" + mutedSt.Render("running dop token revoke…")
}

// silence unused imports pinned to future views
var _ = hex.EncodeToString
var _ = io.Discard
