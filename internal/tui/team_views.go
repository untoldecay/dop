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

	tea "github.com/charmbracelet/bubbletea"

	"github.com/fray/dop/internal/admin"
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
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1")
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
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1")
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

type teamListView struct {
	client  *admin.Client
	paths   *config.Paths
	loaded  bool
	loadErr string
	admins  map[string]vault.Admin
	names   []string
	done    bool
}

func newTeamListView(c *admin.Client, p *config.Paths) *teamListView {
	return &teamListView{client: c, paths: p}
}
func (v *teamListView) Init() tea.Cmd { return v.load }
func (v *teamListView) Done() bool    { return v.done }

type teamListLoadedMsg struct {
	admins map[string]vault.Admin
	err    string
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
	return teamListLoadedMsg{admins: vlt.Admins}
}

func (v *teamListView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch mm := msg.(type) {
	case teamListLoadedMsg:
		v.loaded = true
		v.admins = mm.admins
		v.loadErr = mm.err
		for n := range v.admins {
			v.names = append(v.names, n)
		}
		sort.Strings(v.names)
	case tea.KeyMsg:
		// v1.13.0-rc20 — tighten key handling to match other list views:
		// only esc/q/ctrl+c closes. Previously any key closed; the help
		// text already says "esc back" so the behavior now matches.
		if v.loaded {
			switch mm.String() {
			case "esc", "q", "ctrl+c", "backspace":
				v.done = true
			}
		}
	}
	return v, nil
}

func (v *teamListView) View() string {
	var b strings.Builder
	// v1.13.0-rc20 — Mole-style title + muted count subtitle.
	b.WriteString(titleSt.Render("Team members") + "   " +
		mutedSt.Render(fmt.Sprintf("%d admin(s)", len(v.names))) + "\n\n")
	if !v.loaded {
		b.WriteString("loading…")
		return b.String()
	}
	if v.loadErr != "" {
		b.WriteString(failSt.Render(v.loadErr) + "\n\n")
		b.WriteString(helpSt.Render("esc back"))
		return b.String()
	}
	if len(v.names) == 0 {
		b.WriteString(mutedSt.Render("(no admins yet)"))
	}
	for _, n := range v.names {
		a := v.admins[n]
		note := a.Note
		if note == "" {
			note = "-"
		}
		b.WriteString(fmt.Sprintf("- %s\n    age:     %s\n    ed25519: %s\n    note:    %s\n",
			n, a.AgeRecipient, a.Ed25519Pubkey, note))
	}
	// v1.10.3 — quiet note explaining shared-identity's implication so
	// people who used "same identity" on their Add-a-device don't
	// wonder why the second machine isn't shown here.
	b.WriteString("\n" + mutedSt.Render("This list shows distinct admin identities.") + "\n")
	b.WriteString(mutedSt.Render("Devices you added with 'same identity' share one entry with the machine that invited them.") + "\n")
	b.WriteString(mutedSt.Render("If you want two separate rows here, invite the second device with 'separate identity'.") + "\n")
	// v1.13.0-rc20 — "any key to go back" → "esc back" for consistency.
	b.WriteString("\n" + helpSt.Render("esc back"))
	return b.String()
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
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1")
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
