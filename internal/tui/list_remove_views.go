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
	// v1.13.0-rc16 — token drill-down inside the integration list.
	// Enter on an integration row now opens integModeTokenList for
	// that integration. From there each token is pickable with its
	// own action menu (view / edit scope / rotate / remove), parity
	// with the grant list behavior.
	integModeTokenList          = 5
	integModeTokenAction        = 6
	integModeTokenDetail        = 7
	integModeTokenEditScope     = 8
	integModeTokenRotate        = 9
	integModeTokenRemoveConfirm = 10
	// Integration-level edit (kind / description / URL). Reached via
	// the `e` key on the integration list or the token-list footer.
	integModeIntEdit = 11
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

	// v1.13.0-rc16 — token drill-down state. Populated when the
	// operator presses enter on an integration row.
	tokenNames        []string
	tokenCursor       int
	tokenActionCursor int
	tokenEditBuf      strings.Builder // scope note edit OR rotation value
	tokenPending      string          // "remove-token" | "rotate" | "edit-scope"
	// v1.13.0-rc17 — scope-note edit uses the same preset picker shape
	// as add-integration (parity ask from the field report).
	// tokenScopeMode true = preset picker, false = free-text input.
	tokenScopeMode       bool
	tokenScopePickCursor int

	// Integration-level edit form state (integModeIntEdit).
	// v1.14.0-rc3 Phase 5 — field 0 is Name (rename), Phase 4 added
	// Projects/Tags; see intEditField* constants below.
	intEditField         int
	intEditNameBuf       strings.Builder
	intEditNameWas       string // snapshot at open time, so rename detection is cheap at save
	intEditKindCursor    int
	intEditKindChoice    string
	intEditDescBuf       strings.Builder
	intEditKindSlotBuf   strings.Builder
	intEditProjectsBuf   strings.Builder
	intEditTagsBuf       strings.Builder
	intEditProtectCursor int
	intEditProtectChoice bool // mirrors protectionPresets[cursor].value
	intEditProtectWas    bool // snapshot at enter time, used to decide if passphrase step is needed
	intEditPassBuf       strings.Builder
}

// Integration edit field constants.
// v1.14.0-rc3 Phase 4 added Projects/Tags; Phase 5 adds Name (rename).
// Name is field 0 so a rename is the first thing an operator sees.
const (
	intEditFieldName       = 0
	intEditFieldKind       = 1
	intEditFieldDesc       = 2
	intEditFieldKindSlot   = 3
	intEditFieldProjects   = 4
	intEditFieldTags       = 5
	intEditFieldProtection = 6
	intEditFieldPassphrase = 7
)

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
		case integModeTokenList:
			return v.updateTokenList(mm)
		case integModeTokenAction:
			return v.updateTokenAction(mm)
		case integModeTokenDetail:
			v.mode = integModeTokenList
		case integModeTokenEditScope:
			return v.updateTokenEditScope(mm)
		case integModeTokenRotate:
			return v.updateTokenRotate(mm)
		case integModeTokenRemoveConfirm:
			return v.updateTokenRemoveConfirm(mm)
		case integModeIntEdit:
			return v.updateIntEdit(mm)
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
		// v1.13.0-rc16 — enter drills down into the integration's
		// TOKEN picker (not the read-only detail — that's `d`). From
		// the token picker each token can be viewed / edited / rotated
		// / removed, parity with grant list.
		if len(v.names) == 0 {
			return v, nil
		}
		return v.enterTokenList(), nil
	case "d":
		if len(v.names) > 0 {
			v.mode = integModeDetail
		}
	case "e":
		if len(v.names) > 0 {
			return v.enterIntEdit(), nil
		}
	case "r":
		if len(v.names) > 0 {
			v.mode = integModeConfirm
			v.pending = "remove"
		}
	}
	return v, nil
}

// enterTokenList primes the token-drill-down state for the integration
// currently under the cursor and switches mode. Reads the integration's
// Tokens map, sorts the keys, resets cursors.
func (v *integrationListView) enterTokenList() *integrationListView {
	name := v.selectedName()
	if name == "" {
		return v
	}
	it := v.items[name]
	v.tokenNames = v.tokenNames[:0]
	for k := range it.Tokens {
		v.tokenNames = append(v.tokenNames, k)
	}
	sort.Strings(v.tokenNames)
	v.tokenCursor = 0
	v.tokenActionCursor = 0
	v.mode = integModeTokenList
	return v
}

// enterIntEdit primes the integration-level edit form with the current
// values of the selected integration.
func (v *integrationListView) enterIntEdit() *integrationListView {
	name := v.selectedName()
	if name == "" {
		return v
	}
	it := v.items[name]
	v.intEditField = intEditFieldName
	// v1.14.0-rc3 Phase 5 — Name field (rename support). Snapshot the
	// current key so doIntEdit can detect "operator typed a different
	// name" without re-reading the vault.
	v.intEditNameBuf.Reset()
	v.intEditNameBuf.WriteString(name)
	v.intEditNameWas = name
	v.intEditKindChoice = vault.IntegrationKindOf(it)
	// Pre-position the kind cursor on the current kind.
	for i, p := range kindPresets {
		if p.value == v.intEditKindChoice {
			v.intEditKindCursor = i
			break
		}
	}
	v.intEditDescBuf.Reset()
	v.intEditDescBuf.WriteString(it.Description)
	v.intEditKindSlotBuf.Reset()
	switch vault.IntegrationKindOf(it) {
	case vault.IntegrationKindCLI:
		v.intEditKindSlotBuf.WriteString(it.Metadata["cli_cmd"])
	case vault.IntegrationKindMCP:
		if it.Metadata["mcp_url"] != "" {
			v.intEditKindSlotBuf.WriteString(it.Metadata["mcp_url"])
		} else {
			v.intEditKindSlotBuf.WriteString(it.Metadata["mcp_cmd"])
		}
	default: // api, other
		v.intEditKindSlotBuf.WriteString(it.Metadata["base_url"])
	}
	// v1.14.0-rc3 — prime projects/tags buffers (Phase 4).
	v.intEditProjectsBuf.Reset()
	v.intEditProjectsBuf.WriteString(strings.Join(it.Projects, ","))
	v.intEditTagsBuf.Reset()
	v.intEditTagsBuf.WriteString(strings.Join(it.Tags, ","))
	// v1.14.0-rc3 — prime protection state + reset passphrase buffer.
	v.intEditProtectChoice = it.Protected
	v.intEditProtectWas = it.Protected
	for i, p := range protectionPresets {
		if p.value == it.Protected {
			v.intEditProtectCursor = i
			break
		}
	}
	v.intEditPassBuf.Reset()
	v.mode = integModeIntEdit
	return v
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
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
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
	// v1.13.0-rc20 — Mole-style title + muted count subtitle.
	b.WriteString(titleSt.Render("Integrations") + "   " +
		mutedSt.Render(fmt.Sprintf("%d total", len(v.names))) + "\n\n")
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
		return titleSt.Render("working…") + "\n\n" + mutedSt.Render("running dop CLI…")
	case integModeTokenList, integModeTokenAction:
		return v.viewTokenList()
	case integModeTokenDetail:
		return v.viewTokenDetail()
	case integModeTokenEditScope:
		return v.viewTokenEditScope()
	case integModeTokenRotate:
		return v.viewTokenRotate()
	case integModeTokenRemoveConfirm:
		return v.viewTokenRemoveConfirm()
	case integModeIntEdit:
		return v.viewIntEdit()
	}

	if len(v.names) == 0 {
		b.WriteString(mutedSt.Render("(no integrations yet — use `Add integration` from the main menu)"))
	}
	// v1.13.0-rc20 — dynamic label width (longest name + 2) so long
	// service names like `boiler_skills-registry` don't collide with
	// the description column.
	labelWidth := 12
	for _, n := range v.names {
		if w := lipgloss.Width(n); w > labelWidth {
			labelWidth = w
		}
	}
	labelWidth += 2
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
		// v1.14.0-rc3 — glyph slot pinned to a fixed cell width via
		// lipgloss.Width to defeat the "emoji is 2 cells, empty is 2
		// spaces, with-space is 3" misalignment. Row-to-row columns
		// now line up regardless of terminal emoji rendering.
		lockGlyph := ""
		if it.Protected {
			lockGlyph = mutedSt.Render("🔒")
		}
		lock := lipgloss.NewStyle().Width(3).Render(lockGlyph)
		desc := it.Description
		if desc == "" {
			desc = "-"
		}
		// v1.13.0-rc20 — row shows only `name + desc`. The
		// grants/tokens counts moved to the status bar below so each
		// row stays scannable.
		dispPad := lipgloss.NewStyle().Width(labelWidth).Render(disp)
		b.WriteString(prefix + lock + dispPad + "  " + mutedSt.Render(desc) + "\n")
	}

	// v1.13.0-rc20 — status bar: contextual details for the cursor row.
	// Shown ABOVE the help legend so it reads like "selected row info".
	if len(v.names) > 0 && v.cursor >= 0 && v.cursor < len(v.names) {
		selName := v.names[v.cursor]
		selIt := v.items[selName]
		nrefs := len(v.referrers(selName))
		bar := fmt.Sprintf("selected: %s  |  kind=%s  |  grants=%d  |  tokens=%d",
			selName, vault.IntegrationKindOf(selIt), nrefs, len(selIt.Tokens))
		if len(selIt.Tags) > 0 {
			bar += "  |  tags=" + strings.Join(selIt.Tags, ",")
		}
		if len(selIt.Projects) > 0 {
			bar += "  |  projects=" + strings.Join(selIt.Projects, ",")
		}
		if selIt.Protected {
			owner := selIt.Owner
			if len(owner) > 8 {
				owner = owner[:8] + "…"
			}
			bar += "  |  🔒 owner=" + owner
		}
		b.WriteString("\n" + mutedSt.Render(bar) + "\n")
	}

	// v1.13.0-rc4 — unified footer: help first, then flash/error.
	// v1.13.0-rc16 — enter drills into TOKENS list. Keys: d details,
	// e edit integration, r remove.
	if v.mode == integModeAction {
		b.WriteString("\n" + v.renderActionMenu())
	} else {
		b.WriteString("\n" + helpSt.Render("↑↓ move | enter manage tokens | d details | e edit | r remove | esc back"))
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
	b.WriteString("\n" + helpSt.Render("↑↓ move | enter run | backspace back"))
	return b.String()
}

func (v *integrationListView) viewDetail() string {
	name := v.selectedName()
	if name == "" {
		return "no selection"
	}
	it := v.items[name]
	var b strings.Builder
	b.WriteString(titleSt.Render("Integration: "+name) + "\n")
	// v1.13.0-rc17.1 — share the metadata block with the token
	// drill-down (viewTokenList) so both views look identical. Keeps
	// field order + "only non-empty" logic in one place.
	b.WriteString(integrationMetaBlock(it, len(it.Tokens)))
	b.WriteString("\n")
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
	b.WriteString(helpSt.Render("y/enter confirm | n/esc cancel"))
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
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
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
	// v1.13.0-rc20 — title + muted subtitle count, matching other
	// top-level list views.
	b.WriteString(titleSt.Render("Remove credentials") + "   " +
		mutedSt.Render(fmt.Sprintf("%d service(s)", len(v.names))) + "\n\n")
	if !v.loaded {
		return b.String() + "loading…"
	}
	if len(v.names) == 0 {
		b.WriteString(mutedSt.Render("(nothing to remove)") + "\n\n" + helpSt.Render("esc back"))
		return b.String()
	}
	switch v.step {
	case 0:
		// v1.13.0-rc20 — dynamic label width + 4-space indent to match
		// the rc20 Integrations list row shape.
		labelWidth := 12
		for _, n := range v.names {
			if w := lipgloss.Width(n); w > labelWidth {
				labelWidth = w
			}
		}
		labelWidth += 2
		for i, n := range v.names {
			it := v.items[n]
			prefix := "    "
			disp := n
			if i == v.cursor {
				prefix = "  " + cursorSt.Render("➤ ")
				disp = cursorSt.Render(n)
			}
			// v1.14.0-rc3 — Width(3)-pinned slot, same as the integration
			// list render above. Keeps rows aligned across terminal emoji
			// widths.
			lockGlyph := ""
			if it.Protected {
				lockGlyph = mutedSt.Render("🔒")
			}
			lock := lipgloss.NewStyle().Width(3).Render(lockGlyph)
			desc := it.Description
			if desc == "" {
				desc = "-"
			}
			dispPad := lipgloss.NewStyle().Width(labelWidth).Render(disp)
			b.WriteString(prefix + lock + dispPad + "  " + mutedSt.Render(desc) + "\n")
		}
		// Status bar for selected service (parity with Integrations list).
		if v.cursor >= 0 && v.cursor < len(v.names) {
			selName := v.names[v.cursor]
			selIt := v.items[selName]
			bar := fmt.Sprintf("selected: %s  |  kind=%s  |  tokens=%d",
				selName, vault.IntegrationKindOf(selIt), len(selIt.Tokens))
			b.WriteString("\n" + mutedSt.Render(bar) + "\n")
		}
		b.WriteString("\n" + helpSt.Render("↑↓ move | enter next | esc back"))
	case 1:
		target := v.names[v.cursor]
		// v1.13.0-rc20 — breadcrumb header (title + context + subtitle)
		// instead of the inline "Pick credentials under %q" sentence.
		// Mirrors the token drill-down header style.
		b.WriteString(mutedSt.Render(fmt.Sprintf("Service: %s   %d credential(s)", target, len(v.tokenNames))) + "\n\n")
		// Dynamic label width from longest token name.
		tokLabelWidth := 14
		for _, tn := range v.tokenNames {
			if w := lipgloss.Width(tn); w > tokLabelWidth {
				tokLabelWidth = w
			}
		}
		tokLabelWidth += 2
		for i, tn := range v.tokenNames {
			tok := v.items[target].Tokens[tn]
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
			scope := tok.ScopeNote
			if scope == "" {
				scope = "-"
			}
			labelPad := lipgloss.NewStyle().Width(tokLabelWidth).Render(label)
			b.WriteString(prefix + marker + "  " + labelPad + "  " + mutedSt.Render("("+scope+")") + "\n")
		}
		// Status bar with selected count.
		b.WriteString("\n" + mutedSt.Render(fmt.Sprintf("%d / %d selected", v.selectedTokenCount(), len(v.tokenNames))) + "\n")
		b.WriteString("\n" + helpSt.Render("↑↓ move | space toggle | a all | n none | enter next | esc back"))
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
		b.WriteString("\n" + helpSt.Render("y/enter confirm | n/esc cancel"))
	case 3:
		b.WriteString("removing…\n")
	}
	return b.String()
}

// ---------- v1.13.0-rc16 — Token drill-down (sub-view of integrationListView) ----------

// updateTokenList handles key input while in the token picker.
func (v *integrationListView) updateTokenList(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch mm.String() {
	case "esc", "backspace":
		v.mode = integModeList
	case "up", "k":
		if v.tokenCursor > 0 {
			v.tokenCursor--
		}
	case "down", "j":
		if v.tokenCursor < len(v.tokenNames)-1 {
			v.tokenCursor++
		}
	case "enter":
		if len(v.tokenNames) == 0 {
			return v, nil
		}
		v.mode = integModeTokenAction
		v.tokenActionCursor = 0
	case "e":
		return v.enterIntEdit(), nil
	case "r":
		v.mode = integModeConfirm
		v.pending = "remove"
	}
	return v, nil
}

// tokenActions returns the per-token menu, parity with grantListView.
func (v *integrationListView) tokenActions() []integAction {
	if v.tokenCursor < 0 || v.tokenCursor >= len(v.tokenNames) {
		return nil
	}
	return []integAction{
		{label: "View details", key: "d"},
		{label: "Edit scope note", key: "s"},
		{label: "Rotate value", key: "o"},
		{label: "Remove", key: "r", destructive: true},
		{label: "Back to tokens", key: "b"},
	}
}

func (v *integrationListView) updateTokenAction(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	acts := v.tokenActions()
	switch mm.String() {
	case "esc", "backspace":
		v.mode = integModeTokenList
	case "up", "k":
		if v.tokenActionCursor > 0 {
			v.tokenActionCursor--
		}
	case "down", "j":
		if v.tokenActionCursor < len(acts)-1 {
			v.tokenActionCursor++
		}
	case "enter":
		if v.tokenActionCursor < 0 || v.tokenActionCursor >= len(acts) {
			return v, nil
		}
		return v.runTokenAction(acts[v.tokenActionCursor])
	default:
		for _, a := range acts {
			if a.key == mm.String() {
				return v.runTokenAction(a)
			}
		}
	}
	return v, nil
}

func (v *integrationListView) runTokenAction(a integAction) (tea.Model, tea.Cmd) {
	tokenName := v.selectedTokenName()
	if tokenName == "" {
		return v, nil
	}
	switch a.key {
	case "d":
		v.mode = integModeTokenDetail
	case "s":
		// v1.13.0-rc17 — enter the scope editor in PICKER mode by
		// default, mirroring the add-integration flow. Position the
		// cursor on the matching preset if the current scope exactly
		// equals one; else land on "other…" (last entry) so the
		// operator sees "pick a preset OR drop to free-text."
		cur := v.items[v.selectedName()].Tokens[tokenName].ScopeNote
		v.tokenEditBuf.Reset()
		v.tokenEditBuf.WriteString(cur)
		v.tokenScopePickCursor = len(scopePresets) - 1
		for i, p := range scopePresets {
			if p.value != "" && p.value == cur {
				v.tokenScopePickCursor = i
				break
			}
		}
		v.tokenScopeMode = true
		v.mode = integModeTokenEditScope
	case "o":
		v.tokenEditBuf.Reset()
		v.mode = integModeTokenRotate
	case "r":
		v.mode = integModeTokenRemoveConfirm
		v.tokenPending = "remove-token"
	case "b":
		v.mode = integModeTokenList
	}
	return v, nil
}

func (v *integrationListView) selectedTokenName() string {
	if v.tokenCursor < 0 || v.tokenCursor >= len(v.tokenNames) {
		return ""
	}
	return v.tokenNames[v.tokenCursor]
}

// updateTokenEditScope handles the scope note editor. v1.13.0-rc17 —
// now with preset-picker parity to add-integration. Operator starts
// in picker mode; "other…" drops to free-text; empty + backspace
// returns to picker.
func (v *integrationListView) updateTokenEditScope(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	if v.tokenScopeMode {
		switch mm.String() {
		case "esc":
			v.mode = integModeTokenAction
		case "up", "k":
			if v.tokenScopePickCursor > 0 {
				v.tokenScopePickCursor--
			}
		case "down", "j":
			if v.tokenScopePickCursor < len(scopePresets)-1 {
				v.tokenScopePickCursor++
			}
		case "enter":
			sel := scopePresets[v.tokenScopePickCursor]
			if sel.value == "" {
				// "other…" — drop into free-text input, preserve
				// current buffer so the operator can tweak the value
				// they already have.
				v.tokenScopeMode = false
				return v, nil
			}
			v.tokenEditBuf.Reset()
			v.tokenEditBuf.WriteString(sel.value)
			v.mode = integModeRun
			return v, v.doTokenSetScope()
		}
		return v, nil
	}
	// Free-text mode.
	switch mm.String() {
	case "esc":
		v.mode = integModeTokenAction
	case "enter":
		v.mode = integModeRun
		return v, v.doTokenSetScope()
	case "backspace":
		s := v.tokenEditBuf.String()
		if len(s) > 0 {
			v.tokenEditBuf.Reset()
			v.tokenEditBuf.WriteString(s[:len(s)-1])
		} else {
			// Empty + backspace returns to the preset picker.
			v.tokenScopeMode = true
		}
	default:
		if len(mm.Runes) > 0 {
			v.tokenEditBuf.WriteString(string(mm.Runes))
		}
	}
	return v, nil
}

// updateTokenRotate handles the masked new-value editor.
func (v *integrationListView) updateTokenRotate(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch mm.String() {
	case "esc":
		v.mode = integModeTokenAction
	case "enter":
		if v.tokenEditBuf.Len() == 0 {
			v.err = "new value required"
			return v, nil
		}
		v.err = ""
		v.mode = integModeRun
		return v, v.doTokenRotate()
	case "backspace":
		s := v.tokenEditBuf.String()
		if len(s) > 0 {
			v.tokenEditBuf.Reset()
			v.tokenEditBuf.WriteString(s[:len(s)-1])
		}
	default:
		if len(mm.Runes) > 0 {
			v.tokenEditBuf.WriteString(string(mm.Runes))
		}
	}
	return v, nil
}

func (v *integrationListView) updateTokenRemoveConfirm(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch mm.String() {
	case "y", "Y", "enter":
		v.mode = integModeRun
		return v, v.doTokenRemove()
	case "n", "N", "esc":
		v.mode = integModeTokenAction
		v.tokenPending = ""
	}
	return v, nil
}

func (v *integrationListView) doTokenSetScope() tea.Cmd {
	integ := v.selectedName()
	tok := v.selectedTokenName()
	scope := v.tokenEditBuf.String()
	return func() tea.Msg {
		self, _ := os.Executable()
		cmd := exec.Command(self, "integration", "set-token",
			"--name", integ,
			"--token-name", tok,
			"--scope-note", scope)
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return integActionMsg{err: strings.TrimSpace(stderr.String())}
		}
		return integActionMsg{}
	}
}

func (v *integrationListView) doTokenRotate() tea.Cmd {
	integ := v.selectedName()
	tok := v.selectedTokenName()
	newValue := v.tokenEditBuf.String()
	return func() tea.Msg {
		self, _ := os.Executable()
		cmd := exec.Command(self, "integration", "set-token",
			"--name", integ,
			"--token-name", tok,
			"--value-stdin")
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
		cmd.Stdin = strings.NewReader(newValue + "\n")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return integActionMsg{err: strings.TrimSpace(stderr.String())}
		}
		return integActionMsg{}
	}
}

func (v *integrationListView) doTokenRemove() tea.Cmd {
	integ := v.selectedName()
	tok := v.selectedTokenName()
	return func() tea.Msg {
		self, _ := os.Executable()
		cmd := exec.Command(self, "integration", "remove-token",
			"--name", integ,
			"--token", tok)
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return integActionMsg{err: strings.TrimSpace(stderr.String())}
		}
		return integActionMsg{}
	}
}

// updateIntEdit handles the integration-level edit form.
// v1.14.0-rc3 — see field constants above intEditField declaration.
// Text fields: Desc, KindSlot, Projects, Tags, Passphrase.
// Picker fields: Kind (0), Protection (5).
// Passphrase (6) is conditional on flipping unprotected → protected.
func (v *integrationListView) updateIntEdit(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	needsPass := v.intEditProtectChoice && !v.intEditProtectWas

	// Field 1 — Kind picker (previously 0, shifted by Name).
	if v.intEditField == intEditFieldKind {
		switch mm.String() {
		case "esc":
			v.mode = integModeList
		case "up", "k":
			if v.intEditKindCursor > 0 {
				v.intEditKindCursor--
			}
		case "down", "j":
			if v.intEditKindCursor < len(kindPresets)-1 {
				v.intEditKindCursor++
			}
		case "enter":
			v.intEditKindChoice = kindPresets[v.intEditKindCursor].value
			v.intEditField = intEditFieldDesc
		case "shift+tab":
			v.intEditField = intEditFieldName
		}
		return v, nil
	}
	// Field 5 — Protection picker.
	if v.intEditField == intEditFieldProtection {
		switch mm.String() {
		case "esc":
			v.mode = integModeList
		case "up", "k":
			if v.intEditProtectCursor > 0 {
				v.intEditProtectCursor--
			}
		case "down", "j":
			if v.intEditProtectCursor < len(protectionPresets)-1 {
				v.intEditProtectCursor++
			}
		case "enter":
			v.intEditProtectChoice = protectionPresets[v.intEditProtectCursor].value
			if v.intEditProtectChoice && !v.intEditProtectWas {
				v.intEditField = intEditFieldPassphrase
			} else {
				v.mode = integModeRun
				return v, v.doIntEdit()
			}
		case "tab":
			v.intEditProtectChoice = protectionPresets[v.intEditProtectCursor].value
			if v.intEditProtectChoice && !v.intEditProtectWas {
				v.intEditField = intEditFieldPassphrase
			}
		case "shift+tab":
			v.intEditField = intEditFieldTags
		}
		return v, nil
	}
	// Text input fields: Name (0), Desc (2), KindSlot (3), Projects (4),
	// Tags (5), Passphrase (7).
	switch mm.String() {
	case "esc":
		v.mode = integModeList
	case "enter":
		switch v.intEditField {
		case intEditFieldName:
			v.intEditField = intEditFieldKind
		case intEditFieldDesc, intEditFieldKindSlot, intEditFieldProjects:
			v.intEditField++
		case intEditFieldTags:
			v.intEditField = intEditFieldProtection
		case intEditFieldPassphrase:
			if v.intEditPassBuf.Len() == 0 {
				v.err = "approval passphrase required to lock"
				return v, nil
			}
			v.err = ""
			v.mode = integModeRun
			return v, v.doIntEdit()
		}
	case "tab", "down":
		switch v.intEditField {
		case intEditFieldName:
			v.intEditField = intEditFieldKind
		case intEditFieldDesc, intEditFieldKindSlot, intEditFieldProjects:
			v.intEditField++
		case intEditFieldTags:
			v.intEditField = intEditFieldProtection
		}
	case "shift+tab", "up":
		switch v.intEditField {
		case intEditFieldPassphrase:
			v.intEditField = intEditFieldProtection
		case intEditFieldDesc:
			v.intEditField = intEditFieldKind
		case intEditFieldName:
			// top; no-op
		default:
			if v.intEditField > intEditFieldName {
				v.intEditField--
			}
		}
	case "backspace":
		buf := v.intEditCurBuf()
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
			if buf := v.intEditCurBuf(); buf != nil {
				buf.WriteString(string(mm.Runes))
			}
		}
	}
	_ = needsPass
	return v, nil
}

func (v *integrationListView) intEditCurBuf() *strings.Builder {
	switch v.intEditField {
	case intEditFieldName:
		return &v.intEditNameBuf
	case intEditFieldDesc:
		return &v.intEditDescBuf
	case intEditFieldKindSlot:
		return &v.intEditKindSlotBuf
	case intEditFieldProjects:
		return &v.intEditProjectsBuf
	case intEditFieldTags:
		return &v.intEditTagsBuf
	case intEditFieldPassphrase:
		return &v.intEditPassBuf
	}
	return nil
}

func (v *integrationListView) doIntEdit() tea.Cmd {
	nameWas := v.intEditNameWas
	nameNew := strings.TrimSpace(v.intEditNameBuf.String())
	// v1.14.0-rc3 Phase 5 — if the operator typed a different name,
	// rename FIRST, then update the renamed integration with every
	// other field. Rename runs through its own CLI subcommand with its
	// own audit event and coordinated grant rewrite.
	name := nameWas
	if nameNew != "" && nameNew != nameWas {
		name = nameNew
	}
	kind := v.intEditKindChoice
	desc := v.intEditDescBuf.String()
	slot := v.intEditKindSlotBuf.String()
	projects := strings.TrimSpace(v.intEditProjectsBuf.String())
	tags := strings.TrimSpace(v.intEditTagsBuf.String())
	protectChoice := v.intEditProtectChoice
	protectWas := v.intEditProtectWas
	passphrase := v.intEditPassBuf.String()
	return func() tea.Msg {
		self, _ := os.Executable()
		if nameNew != "" && nameNew != nameWas {
			rename := exec.Command(self, "integration", "rename", "--from", nameWas, "--to", nameNew)
			rename.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
			var rstderr bytes.Buffer
			rename.Stderr = &rstderr
			if err := rename.Run(); err != nil {
				return integActionMsg{err: "rename: " + strings.TrimSpace(rstderr.String())}
			}
		}
		args := []string{"integration", "add", "--name", name, "--kind", kind}
		if desc != "" {
			args = append(args, "--description", desc)
		}
		if slot != "" {
			switch kind {
			case vault.IntegrationKindCLI:
				args = append(args, "--cmd", slot)
			case vault.IntegrationKindMCP:
				if strings.HasPrefix(slot, "http://") || strings.HasPrefix(slot, "https://") {
					args = append(args, "--mcp-url", slot)
				} else {
					args = append(args, "--mcp-cmd", slot)
				}
			default:
				args = append(args, "--base-url", slot)
			}
		}
		// v1.14.0-rc3 Phase 4 — always pass projects + tags so the TUI
		// can edit them (empty string clears the field, nonempty replaces).
		args = append(args, "--projects", projects, "--tags", tags)
		switch {
		case protectChoice && !protectWas:
			args = append(args, "--protected", "--passphrase-stdin")
		case !protectChoice && protectWas:
			args = append(args, "--protected=false")
		}
		cmd := exec.Command(self, args...)
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
		if protectChoice && !protectWas {
			cmd.Stdin = strings.NewReader(passphrase + "\n")
		}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return integActionMsg{err: strings.TrimSpace(stderr.String())}
		}
		return integActionMsg{}
	}
}

// viewTokenList renders the token picker for the integration under
// the main cursor. When in integModeTokenAction the action menu
// renders below the list.
func (v *integrationListView) viewTokenList() string {
	name := v.selectedName()
	it := v.items[name]
	var b strings.Builder
	b.WriteString(titleSt.Render("Tokens on "+name) + "\n")
	// v1.13.0-rc17 — render the full metadata block right under the
	// title (kind, description, protection, kind-specific hints,
	// shared/advanced fields). Only non-empty rows render.
	b.WriteString(integrationMetaBlock(it, len(v.tokenNames)))
	b.WriteString("\n")
	if len(v.tokenNames) == 0 {
		b.WriteString(mutedSt.Render("(no tokens — add one with `dop integration add --token`)") + "\n")
	}
	// v1.13.0-rc20 — dynamic label width from longest token name so
	// names like `boiler_skills-registry` don't collide with scope.
	tokLabelWidth := 14
	for _, tn := range v.tokenNames {
		if w := lipgloss.Width(tn); w > tokLabelWidth {
			tokLabelWidth = w
		}
	}
	tokLabelWidth += 2
	for i, tn := range v.tokenNames {
		tok := it.Tokens[tn]
		prefix := "    "
		disp := tn
		if i == v.tokenCursor && v.mode == integModeTokenList {
			prefix = "  " + cursorSt.Render("➤ ")
			disp = cursorSt.Render(tn)
		}
		scope := tok.ScopeNote
		if scope == "" {
			scope = "-"
		}
		dispPad := lipgloss.NewStyle().Width(tokLabelWidth).Render(disp)
		b.WriteString(prefix + dispPad + "  " + mutedSt.Render("("+scope+")") + "\n")
	}
	if v.mode == integModeTokenAction {
		b.WriteString("\n" + v.renderTokenActionMenu())
	} else {
		b.WriteString("\n" + helpSt.Render("↑↓ move | enter actions | e edit integration | r remove integration | esc back"))
	}
	if v.flash != "" {
		b.WriteString("\n" + okSt.Render(v.flash))
		v.flash = ""
	}
	return b.String()
}

// integrationMetaBlock renders a compact metadata summary for an
// integration, shown both at the top of the token drill-down view
// AND inside the integration detail pane so the two places look
// identical. Only non-empty fields render; order is: kind, token
// count, description, protection, then kind-specific fields (base
// URL / endpoints / command / MCP URL / etc.), then shared advanced
// fields (server root, allowed, auth style, CLI install/help).
// v1.13.0-rc17 — folds Cam's field-report ask: operators drilling
// into a token want full context on the parent integration before
// picking a token. v1.13.0-rc17.1 — reused in viewDetail for
// visual parity.
func integrationMetaBlock(it vault.Integration, tokenCount int) string {
	var b strings.Builder
	// v1.13.0-rc18 — label-aligned via shared kvLine. The widest
	// label in the api/cli/mcp set is `endpoints_probed_at` at 19
	// chars; use that as the column width so every row aligns.
	const w = 19
	// Header: kind + token count on one line (no label, no padding).
	b.WriteString("  " + mutedSt.Render(fmt.Sprintf("kind=%s · %d token(s)", vault.IntegrationKindOf(it), tokenCount)) + "\n")
	b.WriteString(kvLine("description", it.Description, w))
	if it.Protected {
		owner := it.Owner
		if len(owner) > 8 {
			owner = owner[:8] + "…"
		}
		b.WriteString(kvLine("protection", "🔒 owner-locked (owner="+owner+")", w))
	}
	// Kind-specific primary fields.
	kind := vault.IntegrationKindOf(it)
	switch kind {
	case vault.IntegrationKindAPI:
		b.WriteString(kvLine("base_url", it.Metadata["base_url"], w))
		b.WriteString(kvLine("endpoints_url", it.Metadata["endpoints_url"], w))
		b.WriteString(kvLine("auth_header", it.Metadata["auth_header"], w))
		b.WriteString(kvLine("auth_style", it.Metadata["auth_style"], w))
	case vault.IntegrationKindCLI:
		b.WriteString(kvLine("cmd", it.Metadata["cli_cmd"], w))
		b.WriteString(kvLine("args_hint", it.Metadata["cli_args_hint"], w))
		b.WriteString(kvLine("cli_auth_env", it.Metadata["cli_auth_env"], w))
		b.WriteString(kvLine("cli_install", it.Metadata["cli_install"], w))
		b.WriteString(kvLine("cli_help", it.Metadata["cli_help"], w))
	case vault.IntegrationKindMCP:
		b.WriteString(kvLine("mcp_url", it.Metadata["mcp_url"], w))
		b.WriteString(kvLine("mcp_cmd", it.Metadata["mcp_cmd"], w))
	}
	// Any-kind advanced fields.
	b.WriteString(kvLine("server_root", it.Metadata["server_root"], w))
	b.WriteString(kvLine("allowed", it.Metadata["allowed"], w))
	// Free-form metadata that isn't promoted: dump under one line
	// so operators see what else was stored.
	promoted := map[string]bool{
		"base_url": true, "endpoints_url": true, "auth_header": true, "auth_style": true,
		"cli_cmd": true, "cli_args_hint": true, "cli_auth_env": true, "cli_install": true, "cli_help": true,
		"mcp_url": true, "mcp_cmd": true,
		"server_root": true, "allowed": true,
		// probe stamps — surface for transparency
		"endpoints_probed_at": true, "mcp_probed_at": true, "mcp_probe_result": true,
	}
	var extras []string
	for k, v := range it.Metadata {
		if promoted[k] || v == "" {
			continue
		}
		extras = append(extras, k+"="+v)
	}
	if len(extras) > 0 {
		sort.Strings(extras)
		b.WriteString(kvLine("metadata", strings.Join(extras, ", "), w))
	}
	// Probe stamps (if present) — small nod to the probe feature.
	b.WriteString(kvLine("endpoints_probed_at", it.Metadata["endpoints_probed_at"], w))
	if it.Metadata["mcp_probed_at"] != "" {
		b.WriteString(kvLine("mcp_probed_at", it.Metadata["mcp_probed_at"]+" ("+it.Metadata["mcp_probe_result"]+")", w))
	}
	return b.String()
}

func (v *integrationListView) renderTokenActionMenu() string {
	tok := v.selectedTokenName()
	if tok == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString(mutedSt.Render(fmt.Sprintf("─── actions for token %q ───", tok)) + "\n")
	for i, a := range v.tokenActions() {
		prefix := "    "
		lbl := a.label
		if i == v.tokenActionCursor {
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

func (v *integrationListView) viewTokenDetail() string {
	name := v.selectedName()
	tn := v.selectedTokenName()
	tok := v.items[name].Tokens[tn]
	var b strings.Builder
	b.WriteString(titleSt.Render("Token: "+name+"/"+tn) + "\n\n")
	val := tok.Value
	if len(val) > 4 {
		val = strings.Repeat("•", len(val)-4) + val[len(val)-4:]
	} else {
		val = strings.Repeat("•", len(val))
	}
	b.WriteString(fmt.Sprintf("  value:      %s\n", val))
	scope := tok.ScopeNote
	if scope == "" {
		scope = "-"
	}
	b.WriteString(fmt.Sprintf("  scope_note: %s\n", scope))
	b.WriteString("\n" + helpSt.Render("any key back"))
	return b.String()
}

func (v *integrationListView) viewTokenEditScope() string {
	tn := v.selectedTokenName()
	var b strings.Builder
	b.WriteString(titleSt.Render("Edit scope note: "+tn) + "\n\n")
	if v.tokenScopeMode {
		// Preset picker — mirrors add-integration scope step shape.
		b.WriteString(cursorSt.Render("Scope note") + "\n")
		for i, p := range scopePresets {
			prefix := "    "
			label := p.label
			if i == v.tokenScopePickCursor {
				prefix = "  " + cursorSt.Render("➤ ")
				label = cursorSt.Render(p.label)
			}
			b.WriteString(prefix + label + "\n")
		}
		b.WriteString("\n" + helpSt.Render("↑↓ move | enter select | esc cancel"))
	} else {
		b.WriteString(cursorSt.Render("Scope note") + ": " + v.tokenEditBuf.String() + cursorSt.Render("▎") + "\n")
		b.WriteString("    " + mutedSt.Render("free text · empty + backspace → return to presets") + "\n")
		b.WriteString("\n" + helpSt.Render("enter save | esc cancel"))
	}
	if v.err != "" {
		b.WriteString("\n" + failSt.Render(v.err))
	}
	return b.String()
}

func (v *integrationListView) viewTokenRotate() string {
	tn := v.selectedTokenName()
	var b strings.Builder
	b.WriteString(titleSt.Render("Rotate value: "+tn) + "\n\n")
	masked := strings.Repeat("•", v.tokenEditBuf.Len())
	b.WriteString(cursorSt.Render("New value") + ": " + masked + cursorSt.Render("▎") + "\n")
	b.WriteString("    " + mutedSt.Render("the new credential — never echoed; sent to the CLI via stdin") + "\n")
	b.WriteString("\n" + helpSt.Render("enter save | esc cancel"))
	if v.err != "" {
		b.WriteString("\n" + failSt.Render(v.err))
	}
	return b.String()
}

func (v *integrationListView) viewTokenRemoveConfirm() string {
	name := v.selectedName()
	tn := v.selectedTokenName()
	var b strings.Builder
	b.WriteString(titleSt.Render("Remove token "+name+"/"+tn+"?") + "\n\n")
	b.WriteString(failSt.Render("Grants referencing this token will be dropped and bearers resealed where possible.") + "\n")
	if v.err != "" {
		b.WriteString("\n" + failSt.Render(v.err) + "\n")
	}
	b.WriteString("\n" + helpSt.Render("y/enter confirm | n/esc cancel"))
	return b.String()
}

func (v *integrationListView) viewIntEdit() string {
	name := v.selectedName()
	var b strings.Builder
	b.WriteString(titleSt.Render("Edit integration: "+name) + "\n\n")

	// v1.14.0-rc3 Phase 5 — Name field (rename). Changing it triggers
	// `dop integration rename` at save time (coordinated grant rewrite).
	nameLbl := "Name"
	if v.intEditField == intEditFieldName {
		nameLbl = cursorSt.Render(nameLbl)
	} else {
		nameLbl = mutedSt.Render(nameLbl)
	}
	b.WriteString(nameLbl + ": " + v.intEditNameBuf.String())
	if v.intEditField == intEditFieldName {
		b.WriteString(cursorSt.Render("▎"))
	}
	b.WriteString("\n")
	if v.intEditField == intEditFieldName {
		b.WriteString("    " + mutedSt.Render("changing the name renames every referring grant") + "\n")
	}

	// Kind picker (field 1).
	kindLbl := "Kind"
	kindVal := v.intEditKindChoice
	if v.intEditField == 0 {
		kindLbl = cursorSt.Render("Kind")
	} else {
		kindLbl = mutedSt.Render("Kind")
	}
	b.WriteString(kindLbl + ": " + kindVal + "\n")
	if v.intEditField == 0 {
		for i, p := range kindPresets {
			prefix := "    "
			label := p.label
			if i == v.intEditKindCursor {
				prefix = "  " + cursorSt.Render("➤ ")
				label = cursorSt.Render(p.label)
			}
			b.WriteString(prefix + label + "    " + mutedSt.Render(p.hint) + "\n")
		}
	}

	// Description (field 1).
	descLbl := mutedSt.Render("What it's for")
	if v.intEditField == 1 {
		descLbl = cursorSt.Render("What it's for")
	}
	b.WriteString(descLbl + ": " + v.intEditDescBuf.String())
	if v.intEditField == 1 {
		b.WriteString(cursorSt.Render("▎"))
	}
	b.WriteString("\n")

	// KindSlot (field 2) — label depends on kind.
	slotLbl, slotHint := kindSlotLabel(v.intEditKindChoice)
	st := mutedSt
	if v.intEditField == intEditFieldKindSlot {
		st = cursorSt
	}
	b.WriteString(st.Render(slotLbl) + ": " + v.intEditKindSlotBuf.String())
	if v.intEditField == intEditFieldKindSlot {
		b.WriteString(cursorSt.Render("▎"))
	}
	b.WriteString("\n")
	if v.intEditField == intEditFieldKindSlot {
		b.WriteString("    " + mutedSt.Render(slotHint) + "\n")
	}

	// v1.14.0-rc3 — Projects + Tags rows (Phase 4). Grouping metadata,
	// no inheritance to grants. Comma-separated input.
	projLbl := mutedSt.Render("Projects (comma-separated)")
	if v.intEditField == intEditFieldProjects {
		projLbl = cursorSt.Render("Projects (comma-separated)")
	}
	b.WriteString(projLbl + ": " + v.intEditProjectsBuf.String())
	if v.intEditField == intEditFieldProjects {
		b.WriteString(cursorSt.Render("▎"))
	}
	b.WriteString("\n")
	tagsLbl := mutedSt.Render("Tags (comma-separated)")
	if v.intEditField == intEditFieldTags {
		tagsLbl = cursorSt.Render("Tags (comma-separated)")
	}
	b.WriteString(tagsLbl + ": " + v.intEditTagsBuf.String())
	if v.intEditField == intEditFieldTags {
		b.WriteString(cursorSt.Render("▎"))
	}
	b.WriteString("\n")

	// v1.14.0-rc3 — Protection picker (field 5).
	protectLbl := "Protection"
	protectVal := "default"
	if v.intEditProtectChoice {
		protectVal = "protected"
	}
	if v.intEditField == intEditFieldProtection {
		protectLbl = cursorSt.Render(protectLbl)
	} else {
		protectLbl = mutedSt.Render(protectLbl)
	}
	b.WriteString(protectLbl + ": " + protectVal + "\n")
	if v.intEditField == intEditFieldProtection {
		for i, p := range protectionPresets {
			prefix := "    "
			label := p.label
			hint := p.hint
			if i == v.intEditProtectCursor {
				prefix = "  " + cursorSt.Render("➤ ")
				label = cursorSt.Render(p.label)
			}
			b.WriteString(prefix + label + "    " + mutedSt.Render(hint) + "\n")
		}
	}

	// v1.14.0-rc3 — Passphrase (field 6). Rendered only when flipping
	// from unprotected → protected. For unlock + no-change, enter at
	// Protection commits directly without this row ever showing.
	needsPass := v.intEditProtectChoice && !v.intEditProtectWas
	if needsPass {
		passLbl := mutedSt.Render("Approval passphrase")
		if v.intEditField == intEditFieldPassphrase {
			passLbl = cursorSt.Render("Approval passphrase")
		}
		masked := strings.Repeat("•", v.intEditPassBuf.Len())
		b.WriteString(passLbl + ": " + masked)
		if v.intEditField == intEditFieldPassphrase {
			b.WriteString(cursorSt.Render("▎"))
		}
		b.WriteString("\n")
	}

	b.WriteString("\n" + helpSt.Render("enter next/save · tab/↑↓ jump · esc cancel"))
	if v.err != "" {
		b.WriteString("\n" + failSt.Render(v.err))
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

// Edit sub-steps: field selection is by row.
// v1.14.0-rc3 adds Protection + optional Passphrase; grant-level
// protection becomes independently settable (per rc3-plan.md Phase 3).
const (
	grantEditFieldProjects   = 0
	grantEditFieldTags       = 1
	grantEditFieldEnvPrefix  = 2
	grantEditFieldProtection = 3
	grantEditFieldPassphrase = 4
	grantEditFieldSave       = 5
)

type grantListView struct {
	client *admin.Client
	paths  *config.Paths
	loaded bool
	err    string
	ids    []string
	items  map[string]vault.Grant
	done   bool

	// rc6c — viewer pubkey primed at load so row renderer can draw
	// perspective-sensitive owner glyphs (👤 mine / 🔒 another admin's)
	// on protected grants. See rc3-smoke-retakes [S1].
	viewerPubkey string

	mode         int
	cursor       int
	actionCursor int
	flash        string
	pending      string

	editField   int
	editProject strings.Builder
	editTags    strings.Builder
	editPrefix  strings.Builder
	// v1.14.0-rc3 — grant-level protection toggle in edit form.
	editProtectCursor int
	editProtectChoice bool
	editProtectWas    bool
	editPassBuf       strings.Builder
}

func newGrantListView(c *admin.Client, p *config.Paths) *grantListView {
	return &grantListView{client: c, paths: p}
}
func (v *grantListView) Init() tea.Cmd { return v.load }
func (v *grantListView) Done() bool    { return v.done }
func (v *grantListView) Flash() string { return v.flash }

type grantListLoadedMsg struct {
	items        map[string]vault.Grant
	viewerPubkey string
	err          string
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
	// rc6c — viewer pubkey for perspective-sensitive owner glyphs on
	// protected grant rows. Best-effort — missing status just renders
	// without the icon instead of crashing.
	viewerPubkey := ""
	if st, serr := v.client.Status(); serr == nil {
		viewerPubkey = st.AdminPubkey
	}
	return grantListLoadedMsg{items: vlt.Grants, viewerPubkey: viewerPubkey}
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
		v.viewerPubkey = mm.viewerPubkey
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
	// v1.14.0-rc3 — prime protection + reset passphrase buffer.
	v.editProtectChoice = g.Protected
	v.editProtectWas = g.Protected
	for i, p := range protectionPresets {
		if p.value == g.Protected {
			v.editProtectCursor = i
			break
		}
	}
	v.editPassBuf.Reset()
	v.editField = grantEditFieldProjects
	v.mode = grantModeEdit
	v.err = ""
}

func (v *grantListView) updateEdit(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Passphrase field (4) is only visited when flipping unprotected →
	// protected. Everything else skips over it.
	needsPass := v.editProtectChoice && !v.editProtectWas

	// Field 3 — Protection preset picker.
	if v.editField == grantEditFieldProtection {
		switch mm.String() {
		case "esc":
			v.mode = grantModeAction
			return v, nil
		case "up", "k":
			if v.editProtectCursor > 0 {
				v.editProtectCursor--
			}
		case "down", "j":
			if v.editProtectCursor < len(protectionPresets)-1 {
				v.editProtectCursor++
			}
		case "enter":
			v.editProtectChoice = protectionPresets[v.editProtectCursor].value
			if v.editProtectChoice && !v.editProtectWas {
				v.editField = grantEditFieldPassphrase
			} else {
				v.editField = grantEditFieldSave
			}
		case "tab":
			v.editProtectChoice = protectionPresets[v.editProtectCursor].value
			if v.editProtectChoice && !v.editProtectWas {
				v.editField = grantEditFieldPassphrase
			} else {
				v.editField = grantEditFieldSave
			}
		case "shift+tab":
			v.editField = grantEditFieldEnvPrefix
		}
		return v, nil
	}
	switch mm.String() {
	case "esc":
		v.mode = grantModeAction
		return v, nil
	case "tab", "down":
		if v.editField == grantEditFieldPassphrase {
			if needsPass {
				v.editField = grantEditFieldSave
			}
		} else if v.editField < grantEditFieldSave {
			v.editField++
			// Skip passphrase row when it doesn't apply.
			if v.editField == grantEditFieldPassphrase && !needsPass {
				v.editField = grantEditFieldSave
			}
		}
		return v, nil
	case "shift+tab", "up":
		if v.editField == grantEditFieldSave && !needsPass {
			v.editField = grantEditFieldProtection
		} else if v.editField > grantEditFieldProjects {
			v.editField--
		}
		return v, nil
	case "enter":
		if v.editField == grantEditFieldSave {
			if needsPass && v.editPassBuf.Len() == 0 {
				v.editField = grantEditFieldPassphrase
				v.err = "approval passphrase required to lock"
				return v, nil
			}
			v.err = ""
			v.mode = grantModeRun
			return v, v.doEdit()
		}
		if v.editField == grantEditFieldPassphrase {
			if v.editPassBuf.Len() == 0 {
				v.err = "approval passphrase required to lock"
				return v, nil
			}
			v.err = ""
			v.editField = grantEditFieldSave
			return v, nil
		}
		// otherwise advance to next field (skipping passphrase if N/A).
		if v.editField < grantEditFieldSave {
			v.editField++
			if v.editField == grantEditFieldPassphrase && !needsPass {
				v.editField = grantEditFieldSave
			}
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
	case grantEditFieldPassphrase:
		return &v.editPassBuf
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
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
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
	// v1.14.0-rc3 — propagate grant-level protection choice through the
	// CLI's tri-state --protected. Only lock-flips feed a passphrase.
	protectChoice := v.editProtectChoice
	protectWas := v.editProtectWas
	passphrase := v.editPassBuf.String()
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
		switch {
		case protectChoice && !protectWas:
			args = append(args, "--protected", "--passphrase-stdin")
		case !protectChoice && protectWas:
			args = append(args, "--protected=false")
		}
		cmd := exec.Command(self, args...)
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
		if protectChoice && !protectWas {
			cmd.Stdin = strings.NewReader(passphrase + "\n")
		}
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
	// v1.13.0-rc20 — Mole-style title + muted count subtitle.
	b.WriteString(titleSt.Render("Grants") + "   " +
		mutedSt.Render(fmt.Sprintf("%d total", len(v.ids))) + "\n\n")
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
	// v1.13.0-rc20 — dynamic label width.
	labelWidth := 14
	for _, id := range v.ids {
		if w := lipgloss.Width(id); w > labelWidth {
			labelWidth = w
		}
	}
	labelWidth += 2
	for i, id := range v.ids {
		g := v.items[id]
		prefix := "    "
		disp := id
		if i == v.cursor && v.mode == grantModeList {
			prefix = "  " + cursorSt.Render("➤ ")
			disp = cursorSt.Render(id)
		}
		// rc6c — perspective-sensitive owner glyph. Protected grants
		// show 👤 (yours) when g.Owner matches the viewer's admin
		// pubkey, 🔒 (another admin's) otherwise. Unprotected grants
		// get a blank slot. Width-pinned via lipgloss per contract 14.
		ownerRaw := ""
		if g.Protected {
			if g.Owner != "" && v.viewerPubkey != "" && g.Owner == v.viewerPubkey {
				ownerRaw = "👤"
			} else {
				ownerRaw = mutedSt.Render("🔒")
			}
		}
		ownerGlyph := lipgloss.NewStyle().Width(3).Render(ownerRaw)
		// v1.13.0-rc20 — row shows id + target only. Projects moved to
		// the status bar so the row stays clean.
		dispPad := lipgloss.NewStyle().Width(labelWidth).Render(disp)
		b.WriteString(prefix + ownerGlyph + dispPad +
			fmt.Sprintf("  → %s.%s\n", g.Integration, g.Token))
	}

	// v1.13.0-rc20 — status bar for the cursor row.
	if len(v.ids) > 0 && v.cursor >= 0 && v.cursor < len(v.ids) {
		selID := v.ids[v.cursor]
		selG := v.items[selID]
		projTag := "(none)"
		if len(selG.Projects) > 0 {
			projTag = strings.Join(selG.Projects, ",")
		}
		tagTag := "(none)"
		if len(selG.Tags) > 0 {
			tagTag = strings.Join(selG.Tags, ",")
		}
		bar := fmt.Sprintf("selected: %s  |  projects=%s  |  tags=%s",
			selID, projTag, tagTag)
		if selG.Protected {
			owner := selG.Owner
			if len(owner) > 8 {
				owner = owner[:8] + "…"
			}
			bar += "  |  🔒 owner=" + owner
		}
		b.WriteString("\n" + mutedSt.Render(bar) + "\n")
	}

	// v1.13.0-rc4 — unified footer: help first, then flash/error.
	if v.mode == grantModeAction {
		b.WriteString("\n" + v.renderActionMenu())
	} else {
		b.WriteString("\n" + helpSt.Render("↑↓ move | enter actions | esc back") +
			"\n" + helpSt.Render("👤 yours · 🔒 another admin's"))
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
	b.WriteString("\n" + helpSt.Render("↑↓ move | enter run | backspace back"))
	return b.String()
}

func (v *grantListView) viewDetail() string {
	id := v.selectedID()
	g := v.items[id]
	var b strings.Builder
	b.WriteString(titleSt.Render("Grant: "+id) + "\n\n")
	// v1.13.0-rc18 — kvLine for alignment parity with integration
	// detail. Widest label here is `integration` (11 chars); keep the
	// column width consistent with the shared pattern.
	const w = 11
	b.WriteString(kvLine("integration", g.Integration, w))
	b.WriteString(kvLine("token", g.Token, w))
	prefix := g.EnvPrefix
	if prefix == "" {
		prefix = mutedSt.Render(fmt.Sprintf("(default: %s)", g.EffectivePrefix()))
	}
	b.WriteString(kvLine("env_prefix", prefix, w))
	// v1.13.0-rc12 — surface owner-lock state when protected.
	if g.Protected {
		owner := g.Owner
		if len(owner) > 8 {
			owner = owner[:8] + "…"
		}
		b.WriteString(kvLine("protection", "🔒 owner-locked (owner="+owner+")", w))
	}
	// Projects + tags: always render; absence is informative.
	b.WriteString(kvLineAlways("projects", strings.Join(g.Projects, ", "), "(none — press `e` to add)", w))
	b.WriteString(kvLineAlways("tags", strings.Join(g.Tags, ", "), "(none)", w))
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
	b.WriteString("\n" + helpSt.Render("y confirm | n cancel"))
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

	// v1.14.0-rc3 — Protection preset picker (field 3).
	protectLbl := "Protection"
	protectVal := "default"
	if v.editProtectChoice {
		protectVal = "protected"
	}
	if v.editField == grantEditFieldProtection {
		protectLbl = cursorSt.Render(protectLbl)
	} else {
		protectLbl = mutedSt.Render(protectLbl)
	}
	b.WriteString(protectLbl + ": " + protectVal + "\n")
	if v.editField == grantEditFieldProtection {
		for i, p := range protectionPresets {
			prefix := "    "
			label := p.label
			hint := p.hint
			if i == v.editProtectCursor {
				prefix = "  " + cursorSt.Render("➤ ")
				label = cursorSt.Render(p.label)
			}
			b.WriteString(prefix + label + "    " + mutedSt.Render(hint) + "\n")
		}
	}

	// v1.14.0-rc3 — Passphrase (field 4). Only rendered when flipping
	// unprotected → protected (same shape as integration edit).
	needsPass := v.editProtectChoice && !v.editProtectWas
	if needsPass {
		passLbl := mutedSt.Render("Approval passphrase")
		if v.editField == grantEditFieldPassphrase {
			passLbl = cursorSt.Render("Approval passphrase")
		}
		masked := strings.Repeat("•", v.editPassBuf.Len())
		b.WriteString(passLbl + ": " + masked)
		if v.editField == grantEditFieldPassphrase {
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
	b.WriteString("\n" + helpSt.Render("tab/↑↓ field · enter save (on [Save]) · esc cancel"))
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
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
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
		b.WriteString("\n" + helpSt.Render("↑↓ move | enter next | esc cancel"))
	case 1:
		b.WriteString(fmt.Sprintf("Remove grant %q?\n\n", v.ids[v.cursor]))
		if v.err != "" {
			b.WriteString(failSt.Render(v.err) + "\n\n")
		}
		b.WriteString(helpSt.Render("y/enter confirm | n/esc cancel"))
	case 2:
		b.WriteString("removing…\n")
	}
	return b.String()
}
