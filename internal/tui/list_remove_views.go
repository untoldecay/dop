// Integration + grant list/remove TUI views (Batch 3).

package tui

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

// ---------- Integration list ----------

type integrationListView struct {
	client *admin.Client
	paths  *config.Paths
	loaded bool
	err    string
	names  []string
	items  map[string]vault.Integration
	done   bool
}

func newIntegrationListView(c *admin.Client, p *config.Paths) *integrationListView {
	return &integrationListView{client: c, paths: p}
}
func (v *integrationListView) Init() tea.Cmd { return v.load }
func (v *integrationListView) Done() bool    { return v.done }

type integListLoadedMsg struct {
	items map[string]vault.Integration
	err   string
}

func (v *integrationListView) load() tea.Msg {
	vlt, _, err := loadVaultForListing(v.client, v.paths)
	if err != nil {
		return integListLoadedMsg{err: err.Error()}
	}
	return integListLoadedMsg{items: vlt.Integrations}
}
func (v *integrationListView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch mm := msg.(type) {
	case integListLoadedMsg:
		v.loaded = true
		v.err = mm.err
		v.items = mm.items
		for n := range mm.items {
			v.names = append(v.names, n)
		}
		sort.Strings(v.names)
	case tea.KeyMsg:
		_ = mm
		if v.loaded {
			v.done = true
		}
	}
	return v, nil
}
func (v *integrationListView) View() string {
	var b strings.Builder
	b.WriteString(titleSt.Render("Integrations") + "\n\n")
	if !v.loaded {
		return b.String() + "loading…"
	}
	if v.err != "" {
		return b.String() + failSt.Render(v.err)
	}
	if len(v.names) == 0 {
		b.WriteString(mutedSt.Render("(none yet)"))
	}
	for _, n := range v.names {
		it := v.items[n]
		desc := it.Description
		if desc == "" {
			desc = "-"
		}
		b.WriteString(fmt.Sprintf("- %s  (%s)\n", n, desc))
		if bu, ok := it.Metadata["base_url"]; ok {
			b.WriteString("    base_url: " + bu + "\n")
		}
		toks := make([]string, 0, len(it.Tokens))
		for tn := range it.Tokens {
			toks = append(toks, tn)
		}
		sort.Strings(toks)
		for _, tn := range toks {
			b.WriteString(fmt.Sprintf("    token %s: (%s)\n", tn, it.Tokens[tn].ScopeNote))
		}
	}
	b.WriteString("\n" + helpSt.Render("any key to go back"))
	return b.String()
}

// ---------- Integration remove ----------

type integrationRemoveView struct {
	client *admin.Client
	paths  *config.Paths

	step   int // 0 = pick, 1 = confirm, 2 = running
	loaded bool
	err    string
	names  []string
	cursor int
	referrers []string // grants that would need cascading remove
	flash  string
	done   bool
}

func newIntegrationRemoveView(c *admin.Client, p *config.Paths) *integrationRemoveView {
	return &integrationRemoveView{client: c, paths: p}
}
func (v *integrationRemoveView) Init() tea.Cmd { return v.load }
func (v *integrationRemoveView) Done() bool    { return v.done }
func (v *integrationRemoveView) Flash() string { return v.flash }

type integrationRemoveResultMsg struct{ err string }

func (v *integrationRemoveView) load() tea.Msg {
	vlt, _, err := loadVaultForListing(v.client, v.paths)
	if err != nil {
		return integListLoadedMsg{err: err.Error()}
	}
	// reuse integListLoadedMsg for the initial load — we only need names.
	return integListLoadedMsg{items: vlt.Integrations}
}

func (v *integrationRemoveView) recomputeReferrers() {
	if len(v.names) == 0 {
		v.referrers = nil
		return
	}
	target := v.names[v.cursor]
	vlt, _, err := loadVaultForListing(v.client, v.paths)
	if err != nil {
		v.referrers = nil
		return
	}
	v.referrers = v.referrers[:0]
	for gid, g := range vlt.Grants {
		if g.Integration == target {
			v.referrers = append(v.referrers, gid)
		}
	}
	sort.Strings(v.referrers)
}

func (v *integrationRemoveView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch mm := msg.(type) {
	case integListLoadedMsg:
		v.loaded = true
		v.err = mm.err
		for n := range mm.items {
			v.names = append(v.names, n)
		}
		sort.Strings(v.names)
	case integrationRemoveResultMsg:
		if mm.err != "" {
			v.err = mm.err
			v.step = 1
			return v, nil
		}
		v.flash = "integration removed"
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
				v.recomputeReferrers()
				v.step = 1
			}
		case 1:
			switch mm.String() {
			case "y", "Y":
				v.step = 2
				return v, v.doRemove()
			case "n", "N":
				v.step = 0
			}
		}
	}
	return v, nil
}

func (v *integrationRemoveView) doRemove() tea.Cmd {
	name := v.names[v.cursor]
	force := len(v.referrers) > 0
	return func() tea.Msg {
		self, _ := os.Executable()
		args := []string{"integration", "remove", "--name", name}
		if force {
			args = append(args, "--force")
		}
		cmd := exec.Command(self, args...)
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return integrationRemoveResultMsg{err: strings.TrimSpace(stderr.String())}
		}
		return integrationRemoveResultMsg{}
	}
}

func (v *integrationRemoveView) View() string {
	var b strings.Builder
	b.WriteString(titleSt.Render("Remove integration") + "\n\n")
	if !v.loaded {
		return b.String() + "loading…"
	}
	if len(v.names) == 0 {
		b.WriteString(mutedSt.Render("(nothing to remove)") + "\n\n" + helpSt.Render("esc back"))
		return b.String()
	}
	switch v.step {
	case 0:
		b.WriteString("Pick integration to remove:\n\n")
		for i, n := range v.names {
			prefix := "  "
			if i == v.cursor {
				prefix = cursorSt.Render("➤ ")
			}
			b.WriteString(prefix + n + "\n")
		}
		b.WriteString("\n" + helpSt.Render("↑↓ move · enter next · esc cancel"))
	case 1:
		target := v.names[v.cursor]
		b.WriteString(fmt.Sprintf("Remove integration %q?\n\n", target))
		if len(v.referrers) > 0 {
			b.WriteString(failSt.Render("⚠  These grants reference it and will ALSO be removed:") + "\n")
			for _, g := range v.referrers {
				b.WriteString("  - " + g + "\n")
			}
			b.WriteString("\n")
		}
		if v.err != "" {
			b.WriteString(failSt.Render(v.err) + "\n\n")
		}
		b.WriteString(helpSt.Render("y confirm · n go back · esc cancel"))
	case 2:
		b.WriteString("removing…\n")
	}
	return b.String()
}

// ---------- Grant list ----------

type grantListView struct {
	client *admin.Client
	paths  *config.Paths
	loaded bool
	err    string
	ids    []string
	items  map[string]vault.Grant
	done   bool
}

func newGrantListView(c *admin.Client, p *config.Paths) *grantListView {
	return &grantListView{client: c, paths: p}
}
func (v *grantListView) Init() tea.Cmd { return v.load }
func (v *grantListView) Done() bool    { return v.done }

type grantListLoadedMsg struct {
	items map[string]vault.Grant
	err   string
}

func (v *grantListView) load() tea.Msg {
	vlt, _, err := loadVaultForListing(v.client, v.paths)
	if err != nil {
		return grantListLoadedMsg{err: err.Error()}
	}
	return grantListLoadedMsg{items: vlt.Grants}
}
func (v *grantListView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch mm := msg.(type) {
	case grantListLoadedMsg:
		v.loaded = true
		v.err = mm.err
		v.items = mm.items
		for id := range v.items {
			v.ids = append(v.ids, id)
		}
		sort.Strings(v.ids)
	case tea.KeyMsg:
		_ = mm
		if v.loaded {
			v.done = true
		}
	}
	return v, nil
}
func (v *grantListView) View() string {
	var b strings.Builder
	b.WriteString(titleSt.Render("Grants") + "\n\n")
	if !v.loaded {
		return b.String() + "loading…"
	}
	if v.err != "" {
		return b.String() + failSt.Render(v.err)
	}
	if len(v.ids) == 0 {
		b.WriteString(mutedSt.Render("(none)"))
	}
	for _, id := range v.ids {
		g := v.items[id]
		b.WriteString(fmt.Sprintf("- %s  → %s.%s  env_prefix=%s\n", id, g.Integration, g.Token, g.EnvPrefix))
	}
	b.WriteString("\n" + helpSt.Render("any key to go back"))
	return b.String()
}

// ---------- Grant remove ----------

type grantRemoveView struct {
	client *admin.Client
	paths  *config.Paths

	step   int // 0 = pick, 1 = confirm, 2 = running
	loaded bool
	err    string
	ids    []string
	cursor int
	flash  string
	done   bool
}

func newGrantRemoveView(c *admin.Client, p *config.Paths) *grantRemoveView {
	return &grantRemoveView{client: c, paths: p}
}
func (v *grantRemoveView) Init() tea.Cmd { return v.load }
func (v *grantRemoveView) Done() bool    { return v.done }
func (v *grantRemoveView) Flash() string { return v.flash }

type grantRemoveResultMsg struct{ err string }

func (v *grantRemoveView) load() tea.Msg {
	vlt, _, err := loadVaultForListing(v.client, v.paths)
	if err != nil {
		return grantListLoadedMsg{err: err.Error()}
	}
	return grantListLoadedMsg{items: vlt.Grants}
}
func (v *grantRemoveView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch mm := msg.(type) {
	case grantListLoadedMsg:
		v.loaded = true
		v.err = mm.err
		for id := range mm.items {
			v.ids = append(v.ids, id)
		}
		sort.Strings(v.ids)
	case grantRemoveResultMsg:
		if mm.err != "" {
			v.err = mm.err
			v.step = 1
			return v, nil
		}
		v.flash = "grant removed"
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
				if v.cursor < len(v.ids)-1 {
					v.cursor++
				}
			case "enter":
				if len(v.ids) == 0 {
					return v, nil
				}
				v.step = 1
			}
		case 1:
			switch mm.String() {
			case "y", "Y":
				v.step = 2
				return v, v.doRemove()
			case "n", "N":
				v.step = 0
			}
		}
	}
	return v, nil
}

func (v *grantRemoveView) doRemove() tea.Cmd {
	id := v.ids[v.cursor]
	return func() tea.Msg {
		self, _ := os.Executable()
		cmd := exec.Command(self, "grant", "remove", "--id", id)
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return grantRemoveResultMsg{err: strings.TrimSpace(stderr.String())}
		}
		return grantRemoveResultMsg{}
	}
}
func (v *grantRemoveView) View() string {
	var b strings.Builder
	b.WriteString(titleSt.Render("Remove grant") + "\n\n")
	if !v.loaded {
		return b.String() + "loading…"
	}
	if len(v.ids) == 0 {
		b.WriteString(mutedSt.Render("(nothing to remove)") + "\n\n" + helpSt.Render("esc back"))
		return b.String()
	}
	switch v.step {
	case 0:
		b.WriteString("Pick grant to remove:\n\n")
		for i, id := range v.ids {
			prefix := "  "
			if i == v.cursor {
				prefix = cursorSt.Render("➤ ")
			}
			b.WriteString(prefix + id + "\n")
		}
		b.WriteString("\n" + helpSt.Render("↑↓ move · enter next · esc cancel"))
	case 1:
		b.WriteString(fmt.Sprintf("Remove grant %q?\n\n", v.ids[v.cursor]))
		if v.err != "" {
			b.WriteString(failSt.Render(v.err) + "\n\n")
		}
		b.WriteString(helpSt.Render("y confirm · n go back"))
	case 2:
		b.WriteString("removing…\n")
	}
	return b.String()
}
