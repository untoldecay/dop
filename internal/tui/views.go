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
	done      bool
	flash     string
	grantList []string
}

func newIssueView(c *admin.Client, p *config.Paths) *issueView {
	v := &issueView{client: c, paths: p}
	v.expiryBuf.WriteString("72h") // sensible default
	// Try to load available grants from the vault for UX.
	v.grantList = loadGrantsForList(c, p)
	return v
}

func (v *issueView) Init() tea.Cmd { return nil }
func (v *issueView) Done() bool    { return v.done }
func (v *issueView) Flash() string { return v.flash }

type issueResultMsg struct {
	bearer string
	err    string
}

func (v *issueView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch mm := msg.(type) {
	case issueResultMsg:
		if mm.err != "" {
			v.err = mm.err
		} else {
			v.bearer = mm.bearer
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
		// Bearer is on stdout (single line).
		return issueResultMsg{bearer: strings.TrimSpace(stdout.String())}
	}
}

func (v *issueView) View() string {
	var b strings.Builder
	b.WriteString(titleSt.Render("Issue token") + "\n\n")
	if v.step == 100 {
		b.WriteString(okSt.Render("✓ issued") + "\n\n")
		b.WriteString("Bearer (shown ONCE — copy now):\n")
		b.WriteString("  " + lipgloss.NewStyle().Bold(true).Render(v.bearer) + "\n\n")
		if copyToClipboard(v.bearer) {
			b.WriteString(okSt.Render("copied to clipboard") + "\n\n")
		}
		b.WriteString(mutedSt.Render("then: export DOP_TOKEN="+v.bearer) + "\n")
		b.WriteString("\n" + helpSt.Render("any key to return to menu"))
		return b.String()
	}
	labels := []string{"Subject (label)", "Grants (comma-separated)", "Expires (e.g. 72h, 30d)"}
	values := []string{v.nameBuf.String(), v.grantsBuf.String(), v.expiryBuf.String()}
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
	if len(v.grantList) > 0 && v.step == 1 {
		b.WriteString("\n" + mutedSt.Render("available grants: "+strings.Join(v.grantList, ", ")) + "\n")
	}
	if v.err != "" {
		b.WriteString("\n" + failSt.Render(v.err) + "\n")
	}
	b.WriteString("\n" + helpSt.Render("enter next · esc cancel"))
	return b.String()
}

// loadGrantsForList — best-effort read of the vault to surface grants.
func loadGrantsForList(client *admin.Client, paths *config.Paths) []string {
	vp := paths.Vault + "/vault.yaml"
	raw, err := os.ReadFile(vp)
	if err != nil {
		return nil
	}
	if bytes.Contains(raw, []byte("\nsops:")) || bytes.HasPrefix(raw, []byte("sops:")) {
		plain, err := client.DecryptVault(vp)
		if err != nil {
			return nil
		}
		raw = plain
	}
	var v vault.Vault
	if err := yaml.Unmarshal(raw, &v); err != nil {
		return nil
	}
	out := make([]string, 0, len(v.Grants))
	for g := range v.Grants {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
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
}

func newListView(c *admin.Client, p *config.Paths) *listView {
	return &listView{client: c, paths: p}
}
func (v *listView) Init() tea.Cmd { return v.load }
func (v *listView) Done() bool    { return v.done }

type listLoadedMsg struct {
	capabilities []vault.Capability
	capIDs       []string
	err          string
}

func (v *listView) load() tea.Msg {
	vp := v.paths.Vault + "/vault.yaml"
	raw, err := os.ReadFile(vp)
	if err != nil {
		return listLoadedMsg{err: err.Error()}
	}
	if bytes.Contains(raw, []byte("\nsops:")) || bytes.HasPrefix(raw, []byte("sops:")) {
		plain, err := v.client.DecryptVault(vp)
		if err != nil {
			return listLoadedMsg{err: err.Error()}
		}
		raw = plain
	}
	var vv vault.Vault
	if err := yaml.Unmarshal(raw, &vv); err != nil {
		return listLoadedMsg{err: err.Error()}
	}
	caps := make([]vault.Capability, 0, len(vv.Capabilities))
	ids := make([]string, 0, len(vv.Capabilities))
	for id, c := range vv.Capabilities {
		caps = append(caps, c)
		ids = append(ids, id)
	}
	return listLoadedMsg{capabilities: caps, capIDs: ids}
}
func (v *listView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch mm := msg.(type) {
	case listLoadedMsg:
		v.loaded = true
		v.capabilities = mm.capabilities
		v.capIDs = mm.capIDs
		v.loadErr = mm.err
	case tea.KeyMsg:
		if v.loaded {
			v.done = true
		}
	}
	return v, nil
}
func (v *listView) View() string {
	var b strings.Builder
	b.WriteString(titleSt.Render("Capabilities") + "\n\n")
	if !v.loaded {
		b.WriteString("loading…")
		return b.String()
	}
	if v.loadErr != "" {
		b.WriteString(failSt.Render(v.loadErr))
		b.WriteString("\n\n" + helpSt.Render("any key to go back"))
		return b.String()
	}
	if len(v.capabilities) == 0 {
		b.WriteString(mutedSt.Render("(no capabilities issued yet)"))
	}
	for i, c := range v.capabilities {
		statusStyle := okSt
		if c.Status == capability.RecordStatusRevoked {
			statusStyle = failSt
		}
		b.WriteString(fmt.Sprintf("  %s  %s  %s  gen=%d  expires=%s\n",
			mutedSt.Render(v.capIDs[i][:12]),
			c.Subject,
			statusStyle.Render(c.Status),
			c.Generation,
			c.ExpiresAt.Format("2006-01-02")))
	}
	b.WriteString("\n" + helpSt.Render("any key to go back"))
	return b.String()
}

// silence unused imports pinned to future views
var _ = hex.EncodeToString
var _ = io.Discard
