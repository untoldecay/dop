// Integration + grant list/remove TUI views (Batch 3).

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
	"github.com/charmbracelet/lipgloss"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

// ---------- Integration list (v1.10.1 picker) ----------

const (
	integModeList    = 0
	integModeAction  = 1
	integModeConfirm = 2
	integModeRun     = 3
	integModeDetail  = 4
)

type integrationListView struct {
	client *admin.Client
	paths  *config.Paths
	loaded bool
	err    string
	names  []string
	items  map[string]vault.Integration
	grants map[string]vault.Grant // for referrer counts
	done   bool

	mode         int
	cursor       int
	actionCursor int
	flash        string
	pending      string // "remove"
}

func newIntegrationListView(c *admin.Client, p *config.Paths) *integrationListView {
	return &integrationListView{client: c, paths: p}
}
func (v *integrationListView) Init() tea.Cmd { return v.load }
func (v *integrationListView) Done() bool    { return v.done }
func (v *integrationListView) Flash() string { return v.flash }

type integListLoadedMsg struct {
	items  map[string]vault.Integration
	grants map[string]vault.Grant
	// v1.13.0-rc8 — the remove-view needs capabilities too so it can
	// compute the cascade preview (which bearers get resealed, which
	// go stale, which drop to zero grants).
	caps map[string]vault.Capability
	err  string
}

type integActionMsg struct{ err string }

func (v *integrationListView) load() tea.Msg {
	vlt, _, err := loadVaultForListing(v.client, v.paths)
	if err != nil {
		if errors.Is(err, vault.ErrNotAttached) {
			return integListLoadedMsg{err: renderNoVault("integrations")}
		}
		if errors.Is(err, vault.ErrSessionEnded) {
			return integListLoadedMsg{err: renderSessionEnded()}
		}
		return integListLoadedMsg{err: err.Error()}
	}
	return integListLoadedMsg{items: vlt.Integrations, grants: vlt.Grants}
}

func (v *integrationListView) selectedName() string {
	if v.cursor < 0 || v.cursor >= len(v.names) {
		return ""
	}
	return v.names[v.cursor]
}

func (v *integrationListView) referrers(name string) []string {
	out := []string{}
	for gid, g := range v.grants {
		if g.Integration == name {
			out = append(out, gid)
		}
	}
	sort.Strings(out)
	return out
}

type integAction struct {
	label       string
	key         string
	destructive bool
}

func (v *integrationListView) currentActions() []integAction {
	if v.selectedName() == "" {
		return nil
	}
	return []integAction{
		{label: "View details", key: "d"},
		{label: "Remove", key: "r", destructive: true},
		{label: "Back to list", key: "b"},
	}
}

func (v *integrationListView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch mm := msg.(type) {
	case integListLoadedMsg:
		v.loaded = true
		v.err = mm.err
		v.items = mm.items
		v.grants = mm.grants
		v.names = v.names[:0]
		for n := range mm.items {
			v.names = append(v.names, n)
		}
		sort.Strings(v.names)
		if v.cursor >= len(v.names) {
			v.cursor = 0
		}
	case integActionMsg:
		if mm.err != "" {
			v.err = mm.err
			v.mode = integModeAction
			return v, nil
		}
		v.flash = "integration removed · synced with team"
		v.mode = integModeList
		return v, v.load
	case tea.KeyMsg:
		if !v.loaded {
			if mm.String() == "esc" || mm.String() == "ctrl+c" {
				v.done = true
			}
			return v, nil
		}
		switch v.mode {
		case integModeList:
			return v.updateList(mm)
		case integModeAction:
			return v.updateAction(mm)
		case integModeConfirm:
			return v.updateConfirm(mm)
		case integModeDetail:
			v.mode = integModeList
		}
	}
	return v, nil
}

func (v *integrationListView) updateList(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch mm.String() {
	case "esc", "ctrl+c", "q":
		v.done = true
	case "up", "k":
		if v.cursor > 0 {
			v.cursor--
		}
	case "down", "j":
		if v.cursor < len(v.names)-1 {
			v.cursor++
		}
	case "enter":
		// v1.13.0-rc6 — enter drills down into the integration's
		// detail (its tokens + referrer grants). The intermediate
		// action menu is gone — the only destructive op (remove)
		// lives on the main menu as "Remove integration" and the
		// detail view surfaces it inline too.
		if len(v.names) == 0 {
			return v, nil
		}
		v.mode = integModeDetail
	}
	return v, nil
}

func (v *integrationListView) updateAction(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	acts := v.currentActions()
	switch mm.String() {
	case "esc", "backspace":
		v.mode = integModeList
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
		for _, a := range acts {
			if a.key == mm.String() {
				return v.runAction(a)
			}
		}
	}
	return v, nil
}

func (v *integrationListView) runAction(a integAction) (tea.Model, tea.Cmd) {
	switch a.key {
	case "d":
		v.mode = integModeDetail
	case "r":
		v.mode = integModeConfirm
		v.pending = "remove"
	case "b":
		v.mode = integModeList
	}
	return v, nil
}

func (v *integrationListView) updateConfirm(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch mm.String() {
	case "y", "Y", "enter":
		if v.pending == "remove" {
			v.mode = integModeRun
			return v, v.doRemove()
		}
	case "n", "N", "esc":
		v.mode = integModeAction
		v.pending = ""
	}
	return v, nil
}

func (v *integrationListView) doRemove() tea.Cmd {
	name := v.selectedName()
	force := len(v.referrers(name)) > 0
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
			return integActionMsg{err: strings.TrimSpace(stderr.String())}
		}
		return integActionMsg{}
	}
}

func (v *integrationListView) View() string {
	var b strings.Builder
	b.WriteString(titleSt.Render("Integrations") + "\n\n")
	if !v.loaded {
		return b.String() + "loading…"
	}
	if v.err != "" {
		return b.String() + failSt.Render(v.err) + "\n\n" + helpSt.Render("esc back")
	}

	switch v.mode {
	case integModeDetail:
		return v.viewDetail()
	case integModeConfirm:
		return v.viewConfirm()
	case integModeRun:
		return titleSt.Render("Removing…") + "\n\n" + mutedSt.Render("running dop integration remove…")
	}

	if len(v.names) == 0 {
		b.WriteString(mutedSt.Render("(no integrations yet — use `Add integration` from the main menu)"))
	}
	for i, n := range v.names {
		it := v.items[n]
		prefix := "    "
		disp := n
		if i == v.cursor && v.mode == integModeList {
			prefix = "  " + cursorSt.Render("➤ ")
			disp = cursorSt.Render(n)
		}
		// v1.13.0-rc7 — lipgloss.Width-based padding so the cursor
		// style doesn't shrink the visible column (ANSI escapes don't
		// count toward Width()).
		// v1.13.0-rc12 — prepend a muted lock glyph on protected rows.
		// It sits inside the padded column so alignment stays stable.
		lock := "  "
		if it.Protected {
			lock = mutedSt.Render("🔒 ")
		}
		desc := it.Description
		if desc == "" {
			desc = "-"
		}
		nrefs := len(v.referrers(n))
		dispPad := lipgloss.NewStyle().Width(20).Render(disp)
		b.WriteString(prefix + lock + dispPad + "  " +
			mutedSt.Render(desc) +
			fmt.Sprintf("  (grants=%d, tokens=%d)\n", nrefs, len(it.Tokens)))
	}

	// v1.13.0-rc4 — unified footer: help first, then flash/error.
	// v1.13.0-rc6 — enter drills down to the service's tokens, no
	// intermediate action menu (remove lives on the main menu).
	if v.mode == integModeAction {
		b.WriteString("\n" + v.renderActionMenu())
	} else {
		b.WriteString("\n" + helpSt.Render("↑↓ move · enter show tokens · esc back"))
	}
	if v.flash != "" {
		b.WriteString("\n" + okSt.Render(v.flash))
		v.flash = ""
	}
	return b.String()
}

func (v *integrationListView) renderActionMenu() string {
	name := v.selectedName()
	if name == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString(mutedSt.Render(fmt.Sprintf("─── actions for %q ───", name)) + "\n")
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

func (v *integrationListView) viewDetail() string {
	name := v.selectedName()
	if name == "" {
		return "no selection"
	}
	it := v.items[name]
	var b strings.Builder
	b.WriteString(titleSt.Render("Integration: "+name) + "\n\n")
	desc := it.Description
	if desc == "" {
		desc = "(none)"
	}
	b.WriteString(fmt.Sprintf("  description: %s\n", desc))
	// v1.13.0-rc12 — surface owner-lock state. Short owner hex so the
	// line stays readable; `dop team list` is the long-form view.
	if it.Protected {
		owner := it.Owner
		if len(owner) > 8 {
			owner = owner[:8] + "…"
		}
		b.WriteString(fmt.Sprintf("  protection: 🔒 owner-locked (owner=%s)\n", owner))
	}
	if len(it.Metadata) > 0 {
		b.WriteString("  metadata:\n")
		keys := make([]string, 0, len(it.Metadata))
		for k := range it.Metadata {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			b.WriteString(fmt.Sprintf("    %s: %s\n", k, it.Metadata[k]))
		}
	}
	if len(it.Tokens) > 0 {
		b.WriteString("  tokens:\n")
		names := make([]string, 0, len(it.Tokens))
		for tn := range it.Tokens {
			names = append(names, tn)
		}
		sort.Strings(names)
		for _, tn := range names {
			t := it.Tokens[tn]
			val := t.Value
			// Mask everything except the last 4 chars so the operator
			// can eyeball whether it looks real vs a placeholder.
			if len(val) > 4 {
				val = strings.Repeat("•", len(val)-4) + val[len(val)-4:]
			}
			// v1.10.1 — placeholder-token nudge. Short, all-lowercase
			// values almost always mean the operator seeded the vault
			// with `read`/`test`/`xxx`/etc and never dropped a real key.
			warn := ""
			if isPlaceholderTokenValue(t.Value) {
				warn = "  " + failSt.Render("⚠ looks like a placeholder — replace with the real upstream token")
			}
			note := t.ScopeNote
			if note == "" {
				note = "-"
			}
			b.WriteString(fmt.Sprintf("    %s: %s (%s)%s\n", tn, val, note, warn))
		}
	}
	refs := v.referrers(name)
	if len(refs) > 0 {
		b.WriteString("  grants referencing this integration:\n")
		for _, gid := range refs {
			b.WriteString("    - " + gid + "\n")
		}
	} else {
		b.WriteString("  " + mutedSt.Render("(no grants reference this integration yet)") + "\n")
	}
	b.WriteString(mutedSt.Render("\n  To edit token values: `dop integration add --name "+name+" --token TN=NEW_VALUE`\n"))
	b.WriteString(mutedSt.Render("  Or open the plaintext YAML: `dop vault edit`\n"))
	b.WriteString("\n" + helpSt.Render("any key back"))
	return b.String()
}

func (v *integrationListView) viewConfirm() string {
	name := v.selectedName()
	refs := v.referrers(name)
	var b strings.Builder
	b.WriteString(titleSt.Render("Remove integration?") + "\n\n")
	b.WriteString(fmt.Sprintf("  name: %s\n\n", name))
	if len(refs) > 0 {
		b.WriteString(failSt.Render("⚠  These grants reference it and will be removed with it:") + "\n")
		for _, gid := range refs {
			b.WriteString("  - " + gid + "\n")
		}
		b.WriteString("\n")
	}
	if v.err != "" {
		b.WriteString(failSt.Render(v.err) + "\n\n")
	}
	b.WriteString(helpSt.Render("y/enter confirm · n/esc cancel"))
	return b.String()
}

// isPlaceholderTokenValue heuristically flags common placeholder strings
// like "read", "test", "xxx", "changeme", "ntn_xxx" — short, no digits,
// no punctuation typical of real API keys. False positives are acceptable
// here since this only surfaces a soft warning in the details view.
func isPlaceholderTokenValue(s string) bool {
	if len(s) == 0 {
		return true
	}
	if len(s) < 8 {
		return true
	}
	hasDigit := false
	hasUpper := false
	for _, r := range s {
		if r >= '0' && r <= '9' {
			hasDigit = true
		}
		if r >= 'A' && r <= 'Z' {
			hasUpper = true
		}
	}
	// Real API tokens have digits or mixed-case; placeholders like "notion_read" don't.
	if !hasDigit && !hasUpper {
		return true
	}
	lower := strings.ToLower(s)
	for _, needle := range []string{"placeholder", "changeme", "xxxxx", "example"} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	return false
}

// ---------- Integration remove ----------

type integrationRemoveView struct {
	client *admin.Client
	paths  *config.Paths

	// v1.13.0-rc8 — flow now goes:
	//   0 pick service
	//   1 multi-select tokens within the service
	//   2 confirm (shows cascade preview: grants dropped + bearers affected)
	//   3 running
	step   int
	loaded bool
	err    string
	names  []string
	items  map[string]vault.Integration
	grants map[string]vault.Grant
	caps   map[string]vault.Capability
	cursor int
	referrers []string // grants referencing the picked service (legacy; still used by preview)
	// Multi-select token state (step 1).
	tokenNames    []string
	tokenCursor   int
	tokenSelected map[string]bool
	// Cascade preview (step 2 label).
	previewGrants []string
	previewReseal []string // subjects
	previewStale  []string // subjects
	previewEmpty  []string // subjects
	flash  string
	done   bool
}

func newIntegrationRemoveView(c *admin.Client, p *config.Paths) *integrationRemoveView {
	return &integrationRemoveView{client: c, paths: p, tokenSelected: map[string]bool{}}
}
func (v *integrationRemoveView) Init() tea.Cmd { return v.load }
func (v *integrationRemoveView) Done() bool    { return v.done }
func (v *integrationRemoveView) Flash() string { return v.flash }

type integrationRemoveResultMsg struct{ err string }

func (v *integrationRemoveView) load() tea.Msg {
	vlt, _, err := loadVaultForListing(v.client, v.paths)
	if err != nil {
		if errors.Is(err, vault.ErrNotAttached) {
			return integListLoadedMsg{err: renderNoVault("integrations")}
		}
		if errors.Is(err, vault.ErrSessionEnded) {
			return integListLoadedMsg{err: renderSessionEnded()}
		}
		return integListLoadedMsg{err: err.Error()}
	}
	// v1.13.0-rc8 — we need grants + capabilities for the cascade preview.
	return integListLoadedMsg{items: vlt.Integrations, grants: vlt.Grants, caps: vlt.Capabilities}
}

// prepareTokenPicker populates tokenNames + resets selection for the
// multi-select step when the user picks a service.
func (v *integrationRemoveView) prepareTokenPicker() {
	if len(v.names) == 0 {
		return
	}
	target := v.names[v.cursor]
	integ := v.items[target]
	v.tokenNames = v.tokenNames[:0]
	for tn := range integ.Tokens {
		v.tokenNames = append(v.tokenNames, tn)
	}
	sort.Strings(v.tokenNames)
	v.tokenCursor = 0
	v.tokenSelected = map[string]bool{}
}

// computePreview builds the cascade preview strings based on the
// currently selected tokens and the loaded vault state.
func (v *integrationRemoveView) computePreview() {
	v.previewGrants = v.previewGrants[:0]
	v.previewReseal = v.previewReseal[:0]
	v.previewStale = v.previewStale[:0]
	v.previewEmpty = v.previewEmpty[:0]
	target := v.names[v.cursor]
	// Grants that will be dropped.
	grantSet := map[string]bool{}
	for gid, g := range v.grants {
		if g.Integration != target {
			// Allow the normalized form too.
			if vault.NormalizeIntegrationName(g.Integration) != vault.NormalizeIntegrationName(target) {
				continue
			}
		}
		if v.tokenSelected[g.Token] {
			v.previewGrants = append(v.previewGrants, gid)
			grantSet[gid] = true
		}
	}
	sort.Strings(v.previewGrants)
	// Bearers affected.
	for _, c := range v.caps {
		if c.Status != "active" {
			continue
		}
		remaining := 0
		touched := false
		for _, gid := range c.Grants {
			if grantSet[gid] {
				touched = true
			} else {
				remaining++
			}
		}
		if !touched {
			continue
		}
		if remaining == 0 {
			v.previewEmpty = append(v.previewEmpty, c.Subject)
			continue
		}
		keyType := "ed25519"
		if c.Binding != nil && c.Binding.KeyType != "" {
			keyType = c.Binding.KeyType
		}
		if keyType == "p256" {
			v.previewReseal = append(v.previewReseal, c.Subject)
		} else {
			v.previewStale = append(v.previewStale, c.Subject)
		}
	}
	sort.Strings(v.previewReseal)
	sort.Strings(v.previewStale)
	sort.Strings(v.previewEmpty)
}

func (v *integrationRemoveView) selectedTokenCount() int {
	n := 0
	for _, picked := range v.tokenSelected {
		if picked {
			n++
		}
	}
	return n
}

func (v *integrationRemoveView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch mm := msg.(type) {
	case integListLoadedMsg:
		v.loaded = true
		v.err = mm.err
		v.items = mm.items
		v.grants = mm.grants
		v.caps = mm.caps
		for n := range mm.items {
			v.names = append(v.names, n)
		}
		sort.Strings(v.names)
	case integrationRemoveResultMsg:
		if mm.err != "" {
			v.err = mm.err
			v.step = 2
			return v, nil
		}
		v.flash = "credentials removed · synced with team"
		v.done = true
	case tea.KeyMsg:
		switch mm.String() {
		case "esc", "ctrl+c":
			if v.step == 0 {
				v.done = true
				return v, nil
			}
			// v1.13.0-rc8 — nested esc: step back one level.
			v.step--
			v.err = ""
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
				v.prepareTokenPicker()
				v.step = 1
			}
		case 1:
			// Multi-select tokens: space toggles, a/n bulk, enter advances.
			switch mm.String() {
			case "up", "k":
				if v.tokenCursor > 0 {
					v.tokenCursor--
				}
			case "down", "j":
				if v.tokenCursor < len(v.tokenNames)-1 {
					v.tokenCursor++
				}
			case " ":
				if v.tokenCursor >= 0 && v.tokenCursor < len(v.tokenNames) {
					tn := v.tokenNames[v.tokenCursor]
					v.tokenSelected[tn] = !v.tokenSelected[tn]
				}
			case "a":
				for _, tn := range v.tokenNames {
					v.tokenSelected[tn] = true
				}
			case "n":
				for tn := range v.tokenSelected {
					delete(v.tokenSelected, tn)
				}
			case "enter":
				if v.selectedTokenCount() == 0 {
					v.err = "select at least one credential (space to toggle)"
					return v, nil
				}
				v.err = ""
				v.computePreview()
				v.step = 2
			}
		case 2:
			// Confirm cascade preview.
			switch mm.String() {
			case "y", "Y", "enter":
				v.step = 3
				return v, v.doRemove()
			case "n", "N":
				v.step = 1
			}
		}
	}
	return v, nil
}

func (v *integrationRemoveView) doRemove() tea.Cmd {
	name := v.names[v.cursor]
	picked := []string{}
	for _, tn := range v.tokenNames {
		if v.tokenSelected[tn] {
			picked = append(picked, tn)
		}
	}
	return func() tea.Msg {
		self, _ := os.Executable()
		args := []string{"integration", "remove-token", "--name", name}
		for _, tn := range picked {
			args = append(args, "--token", tn)
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
	b.WriteString(titleSt.Render("Remove credentials") + "\n\n")
	if !v.loaded {
		return b.String() + "loading…"
	}
	if len(v.names) == 0 {
		b.WriteString(mutedSt.Render("(nothing to remove)") + "\n\n" + helpSt.Render("esc back"))
		return b.String()
	}
	switch v.step {
	case 0:
		b.WriteString("Pick a service:\n\n")
		for i, n := range v.names {
			prefix := "  "
			if i == v.cursor {
				prefix = cursorSt.Render("➤ ")
			}
			b.WriteString(prefix + n + "\n")
		}
		b.WriteString("\n" + helpSt.Render("↑↓ move · enter next · esc back"))
	case 1:
		target := v.names[v.cursor]
		b.WriteString(fmt.Sprintf("Pick credentials under %q to remove:\n\n", target))
		for i, tn := range v.tokenNames {
			prefix := "    "
			marker := mutedSt.Render("○")
			if v.tokenSelected[tn] {
				marker = okSt.Render("●")
			}
			label := tn
			if i == v.tokenCursor {
				prefix = "  " + cursorSt.Render("➤ ")
				label = cursorSt.Render(tn)
			}
			b.WriteString(prefix + marker + "  " + label + "\n")
		}
		b.WriteString("\n" + helpSt.Render("↑↓ move · space toggle · a all · n none · enter next · esc back"))
		if v.err != "" {
			b.WriteString("\n" + failSt.Render(v.err))
		}
	case 2:
		target := v.names[v.cursor]
		picked := []string{}
		for _, tn := range v.tokenNames {
			if v.tokenSelected[tn] {
				picked = append(picked, tn)
			}
		}
		b.WriteString(fmt.Sprintf("Remove %d credential(s) from %q: %s\n\n",
			len(picked), target, strings.Join(picked, ", ")))
		// Cascade preview.
		if len(v.previewGrants) > 0 {
			b.WriteString(failSt.Render(fmt.Sprintf("⚠ %d grant(s) will be removed:", len(v.previewGrants))) + "\n")
			for _, g := range v.previewGrants {
				b.WriteString("    - " + g + "\n")
			}
		}
		if len(v.previewReseal) > 0 {
			b.WriteString("\n" + okSt.Render(fmt.Sprintf("✓ %d bearer(s) will be resealed (P-256 — env updated live):", len(v.previewReseal))) + "\n")
			for _, s := range v.previewReseal {
				b.WriteString("    - " + s + "\n")
			}
		}
		if len(v.previewStale) > 0 {
			b.WriteString("\n" + failSt.Render(fmt.Sprintf("⚠ %d ed25519 bearer(s) will have STALE env (bundle can't be rewritten):", len(v.previewStale))) + "\n")
			for _, s := range v.previewStale {
				b.WriteString("    - " + s + "\n")
			}
		}
		if len(v.previewEmpty) > 0 {
			b.WriteString("\n" + failSt.Render(fmt.Sprintf("⚠ %d bearer(s) will have NO grants left and be revoked:", len(v.previewEmpty))) + "\n")
			for _, s := range v.previewEmpty {
				b.WriteString("    - " + s + "\n")
			}
		}
		// Integration-wide notice.
		integ := v.items[target]
		if len(picked) == len(integ.Tokens) {
			b.WriteString("\n" + failSt.Render("All credentials of this service are selected — the service entry will be removed too.") + "\n")
		}
		if v.err != "" {
			b.WriteString("\n" + failSt.Render(v.err) + "\n")
		}
		b.WriteString("\n" + helpSt.Render("y/enter confirm · n/esc cancel"))
	case 3:
		b.WriteString("removing…\n")
	}
	return b.String()
}

// ---------- Grant list (v1.10.1 picker) ----------

const (
	grantModeList    = 0
	grantModeAction  = 1
	grantModeConfirm = 2
	grantModeRun     = 3
	grantModeDetail  = 4
	grantModeEdit    = 5
)

// Edit sub-steps: field selection is by row (projects, tags, env_prefix).
const (
	grantEditFieldProjects  = 0
	grantEditFieldTags      = 1
	grantEditFieldEnvPrefix = 2
	grantEditFieldSave      = 3
)

type grantListView struct {
	client *admin.Client
	paths  *config.Paths
	loaded bool
	err    string
	ids    []string
	items  map[string]vault.Grant
	done   bool

	mode         int
	cursor       int
	actionCursor int
	flash        string
	pending      string

	editField   int
	editProject strings.Builder
	editTags    strings.Builder
	editPrefix  strings.Builder
}

func newGrantListView(c *admin.Client, p *config.Paths) *grantListView {
	return &grantListView{client: c, paths: p}
}
func (v *grantListView) Init() tea.Cmd { return v.load }
func (v *grantListView) Done() bool    { return v.done }
func (v *grantListView) Flash() string { return v.flash }

type grantListLoadedMsg struct {
	items map[string]vault.Grant
	err   string
}

type grantActionMsg struct {
	err  string
	kind string // "remove" or "edit"
}

func (v *grantListView) load() tea.Msg {
	vlt, _, err := loadVaultForListing(v.client, v.paths)
	if err != nil {
		if errors.Is(err, vault.ErrNotAttached) {
			return grantListLoadedMsg{err: renderNoVault("grants")}
		}
		if errors.Is(err, vault.ErrSessionEnded) {
			return grantListLoadedMsg{err: renderSessionEnded()}
		}
		return grantListLoadedMsg{err: err.Error()}
	}
	return grantListLoadedMsg{items: vlt.Grants}
}

func (v *grantListView) selectedID() string {
	if v.cursor < 0 || v.cursor >= len(v.ids) {
		return ""
	}
	return v.ids[v.cursor]
}

type grantAction struct {
	label       string
	key         string
	destructive bool
}

func (v *grantListView) currentActions() []grantAction {
	if v.selectedID() == "" {
		return nil
	}
	return []grantAction{
		{label: "View details", key: "d"},
		{label: "Edit projects / tags / env_prefix", key: "e"},
		{label: "Remove", key: "r", destructive: true},
		{label: "Back to list", key: "b"},
	}
}

func (v *grantListView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch mm := msg.(type) {
	case grantListLoadedMsg:
		v.loaded = true
		v.err = mm.err
		v.items = mm.items
		v.ids = v.ids[:0]
		for id := range v.items {
			v.ids = append(v.ids, id)
		}
		sort.Strings(v.ids)
		if v.cursor >= len(v.ids) {
			v.cursor = 0
		}
	case grantActionMsg:
		if mm.err != "" {
			v.err = mm.err
			if mm.kind == "edit" {
				v.mode = grantModeEdit
			} else {
				v.mode = grantModeAction
			}
			return v, nil
		}
		if mm.kind == "edit" {
			v.flash = "grant metadata updated · synced with team"
		} else {
			v.flash = "grant removed · synced with team"
		}
		v.mode = grantModeList
		return v, v.load
	case tea.KeyMsg:
		if !v.loaded {
			if mm.String() == "esc" || mm.String() == "ctrl+c" {
				v.done = true
			}
			return v, nil
		}
		switch v.mode {
		case grantModeList:
			return v.updateList(mm)
		case grantModeAction:
			return v.updateAction(mm)
		case grantModeConfirm:
			return v.updateConfirm(mm)
		case grantModeDetail:
			v.mode = grantModeList
		case grantModeEdit:
			return v.updateEdit(mm)
		}
	}
	return v, nil
}

func (v *grantListView) updateList(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch mm.String() {
	case "esc", "ctrl+c", "q":
		v.done = true
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
		v.mode = grantModeAction
		v.actionCursor = 0
	case "d":
		if v.selectedID() != "" {
			v.mode = grantModeDetail
		}
	case "e":
		if v.selectedID() != "" {
			v.openEditor()
		}
	case "r":
		if v.selectedID() != "" {
			v.mode = grantModeConfirm
			v.pending = "remove"
		}
	}
	return v, nil
}

func (v *grantListView) updateAction(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	acts := v.currentActions()
	switch mm.String() {
	case "esc", "backspace":
		v.mode = grantModeList
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
		for _, a := range acts {
			if a.key == mm.String() {
				return v.runAction(a)
			}
		}
	}
	return v, nil
}

func (v *grantListView) runAction(a grantAction) (tea.Model, tea.Cmd) {
	switch a.key {
	case "d":
		v.mode = grantModeDetail
	case "e":
		v.openEditor()
	case "r":
		v.mode = grantModeConfirm
		v.pending = "remove"
	case "b":
		v.mode = grantModeList
	}
	return v, nil
}

func (v *grantListView) openEditor() {
	id := v.selectedID()
	g := v.items[id]
	v.editProject.Reset()
	v.editProject.WriteString(strings.Join(g.Projects, ","))
	v.editTags.Reset()
	v.editTags.WriteString(strings.Join(g.Tags, ","))
	v.editPrefix.Reset()
	v.editPrefix.WriteString(g.EnvPrefix)
	v.editField = grantEditFieldProjects
	v.mode = grantModeEdit
	v.err = ""
}

func (v *grantListView) updateEdit(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch mm.String() {
	case "esc":
		v.mode = grantModeAction
		return v, nil
	case "tab", "down":
		if v.editField < grantEditFieldSave {
			v.editField++
		}
		return v, nil
	case "shift+tab", "up":
		if v.editField > grantEditFieldProjects {
			v.editField--
		}
		return v, nil
	case "enter":
		if v.editField == grantEditFieldSave {
			v.mode = grantModeRun
			return v, v.doEdit()
		}
		// otherwise advance to next field
		if v.editField < grantEditFieldSave {
			v.editField++
		}
		return v, nil
	case "backspace":
		buf := v.editBuf()
		if buf == nil {
			return v, nil
		}
		s := buf.String()
		if len(s) > 0 {
			buf.Reset()
			buf.WriteString(s[:len(s)-1])
		}
	default:
		if len(mm.Runes) > 0 {
			buf := v.editBuf()
			if buf != nil {
				buf.WriteString(string(mm.Runes))
			}
		}
	}
	return v, nil
}

func (v *grantListView) editBuf() *strings.Builder {
	switch v.editField {
	case grantEditFieldProjects:
		return &v.editProject
	case grantEditFieldTags:
		return &v.editTags
	case grantEditFieldEnvPrefix:
		return &v.editPrefix
	}
	return nil
}

func (v *grantListView) updateConfirm(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch mm.String() {
	case "y", "Y", "enter":
		if v.pending == "remove" {
			v.mode = grantModeRun
			return v, v.doRemove()
		}
	case "n", "N", "esc":
		v.mode = grantModeAction
		v.pending = ""
	}
	return v, nil
}

func (v *grantListView) doRemove() tea.Cmd {
	id := v.selectedID()
	return func() tea.Msg {
		self, _ := os.Executable()
		cmd := exec.Command(self, "grant", "remove", "--id", id)
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return grantActionMsg{kind: "remove", err: strings.TrimSpace(stderr.String())}
		}
		return grantActionMsg{kind: "remove"}
	}
}

func (v *grantListView) doEdit() tea.Cmd {
	id := v.selectedID()
	g := v.items[id]
	projects := strings.TrimSpace(v.editProject.String())
	tags := strings.TrimSpace(v.editTags.String())
	prefix := strings.TrimSpace(v.editPrefix.String())
	return func() tea.Msg {
		self, _ := os.Executable()
		// `dop grant add` is upsert; passing the same id + integration +
		// token with new metadata overwrites the record in place.
		args := []string{
			"grant", "add",
			"--id", id,
			"--integration", g.Integration,
			"--token", g.Token,
			"--projects", projects,
			"--tags", tags,
		}
		if prefix != "" {
			args = append(args, "--env-prefix", prefix)
		}
		cmd := exec.Command(self, args...)
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return grantActionMsg{kind: "edit", err: strings.TrimSpace(stderr.String())}
		}
		return grantActionMsg{kind: "edit"}
	}
}

func (v *grantListView) View() string {
	var b strings.Builder
	b.WriteString(titleSt.Render("Grants") + "\n\n")
	if !v.loaded {
		return b.String() + "loading…"
	}
	if v.err != "" && v.mode == grantModeList {
		b.WriteString(failSt.Render(v.err) + "\n\n")
		v.err = ""
	}

	switch v.mode {
	case grantModeDetail:
		return v.viewDetail()
	case grantModeConfirm:
		return v.viewConfirm()
	case grantModeRun:
		return titleSt.Render("Working…") + "\n\n" + mutedSt.Render("saving…")
	case grantModeEdit:
		return v.viewEdit()
	}

	if len(v.ids) == 0 {
		b.WriteString(mutedSt.Render("(no grants yet — use `Add grant` from the main menu)"))
	}
	for i, id := range v.ids {
		g := v.items[id]
		prefix := "    "
		disp := id
		if i == v.cursor && v.mode == grantModeList {
			prefix = "  " + cursorSt.Render("➤ ")
			disp = cursorSt.Render(id)
		}
		projTag := "(none)"
		if len(g.Projects) > 0 {
			projTag = strings.Join(g.Projects, ",")
		}
		// v1.13.0-rc7 — see views.go/list_remove_views.go: lipgloss.Width
		// padding so cursor styling doesn't shift the metadata columns.
		dispPad := lipgloss.NewStyle().Width(22).Render(disp)
		b.WriteString(prefix + dispPad +
			fmt.Sprintf("  → %s.%s  projects=%s\n",
				g.Integration, g.Token, mutedSt.Render(projTag)))
	}

	// v1.13.0-rc4 — unified footer: help first, then flash/error.
	if v.mode == grantModeAction {
		b.WriteString("\n" + v.renderActionMenu())
	} else {
		b.WriteString("\n" + helpSt.Render("↑↓ move · enter actions · esc back"))
	}
	if v.flash != "" {
		b.WriteString("\n" + okSt.Render(v.flash))
		v.flash = ""
	}
	return b.String()
}

func (v *grantListView) renderActionMenu() string {
	id := v.selectedID()
	if id == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString(mutedSt.Render(fmt.Sprintf("─── actions for %q ───", id)) + "\n")
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

func (v *grantListView) viewDetail() string {
	id := v.selectedID()
	g := v.items[id]
	var b strings.Builder
	b.WriteString(titleSt.Render("Grant: "+id) + "\n\n")
	b.WriteString(fmt.Sprintf("  integration: %s\n", g.Integration))
	b.WriteString(fmt.Sprintf("  token:       %s\n", g.Token))
	prefix := g.EnvPrefix
	if prefix == "" {
		prefix = mutedSt.Render(fmt.Sprintf("(default: %s)", g.EffectivePrefix()))
	}
	b.WriteString(fmt.Sprintf("  env_prefix:  %s\n", prefix))
	if len(g.Projects) > 0 {
		b.WriteString(fmt.Sprintf("  projects:    %s\n", strings.Join(g.Projects, ", ")))
	} else {
		b.WriteString("  projects:    " + mutedSt.Render("(none — press `e` to add)") + "\n")
	}
	if len(g.Tags) > 0 {
		b.WriteString(fmt.Sprintf("  tags:        %s\n", strings.Join(g.Tags, ", ")))
	} else {
		b.WriteString("  tags:        " + mutedSt.Render("(none)") + "\n")
	}
	b.WriteString(mutedSt.Render("\n  Projects and tags are metadata for grouping.\n"))
	b.WriteString(mutedSt.Render("  They do NOT act as permission boundaries — the grant is the unit of permission.\n"))
	b.WriteString("\n" + helpSt.Render("any key back"))
	return b.String()
}

func (v *grantListView) viewConfirm() string {
	id := v.selectedID()
	var b strings.Builder
	b.WriteString(titleSt.Render("Remove grant?") + "\n\n")
	b.WriteString(fmt.Sprintf("  id: %s\n\n", id))
	b.WriteString(failSt.Render("Any bearer that references this grant will fail on next exec.") + "\n")
	if v.err != "" {
		b.WriteString("\n" + failSt.Render(v.err) + "\n")
	}
	b.WriteString("\n" + helpSt.Render("y confirm · n cancel"))
	return b.String()
}

func (v *grantListView) viewEdit() string {
	id := v.selectedID()
	var b strings.Builder
	b.WriteString(titleSt.Render("Edit grant: "+id) + "\n\n")

	rows := []struct {
		label string
		val   string
	}{
		{"Projects (comma-separated)", v.editProject.String()},
		{"Tags (comma-separated)", v.editTags.String()},
		{"Env prefix (blank = default)", v.editPrefix.String()},
	}
	for i, r := range rows {
		style := mutedSt
		if i == v.editField {
			style = cursorSt
		}
		b.WriteString(style.Render(r.label) + ": " + r.val)
		if i == v.editField {
			b.WriteString(cursorSt.Render("▎"))
		}
		b.WriteString("\n")
	}
	b.WriteString("\n")
	saveStyle := mutedSt
	if v.editField == grantEditFieldSave {
		saveStyle = cursorSt
	}
	b.WriteString("    " + saveStyle.Render("[ Save ]") + "\n")

	if v.err != "" {
		b.WriteString("\n" + failSt.Render(v.err) + "\n")
	}
	b.WriteString("\n" + helpSt.Render("tab / ↑↓ field · enter save (on [Save]) · esc cancel"))
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
		if errors.Is(err, vault.ErrNotAttached) {
			return grantListLoadedMsg{err: renderNoVault("grants")}
		}
		if errors.Is(err, vault.ErrSessionEnded) {
			return grantListLoadedMsg{err: renderSessionEnded()}
		}
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
		v.flash = "grant removed · synced with team"
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
			// v1.13.0-rc6 — unified confirm keybindings:
			// y/Y/enter confirm · n/N/esc cancel.
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
		b.WriteString(helpSt.Render("y/enter confirm · n/esc cancel"))
	case 2:
		b.WriteString("removing…\n")
	}
	return b.String()
}
