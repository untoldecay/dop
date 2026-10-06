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

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

// ---------- Integration list ----------

// Integrations list modes. The detail has tabs Info / Credentials /
// Grants (v.tab); Info carries the integration actions, the credential
// actions open under the Credentials rows (integModeTokenAction).
const (
	integModeList               = 0
	integModeDetail             = 1
	integModeConfirm            = 2 // remove integration
	integModeRun                = 3
	integModeDone               = 4
	integModeTokenAction        = 5
	integModeTokenEditScope     = 6
	integModeTokenRotate        = 7
	integModeTokenRemoveConfirm = 8
	integModeIntEdit            = 9
)

type integrationListView struct {
	client  *admin.Client
	paths   *config.Paths
	loaded  bool
	loadErr string
	err     string // last action's failure, on the status line
	names   []string
	items   map[string]vault.Integration
	grants  map[string]vault.Grant // for referrer counts
	done    bool

	mode         int
	tab          int  // detail tab: 0 Info, 1 Credentials, 2 Grants
	help         bool // ? expanded help
	cursor       int
	actionCursor int
	grantCursor  int
	list         list.Model // list-mode renderer; v.cursor stays the source of truth
	width        int
	height       int
	flash        string
	pending      string // action in flight / done: remove, scope, rotate, remove-cred, edit
	from         int    // mode a confirm or the edit form returns to
	back         int    // mode a failed action returns to
	keep         string // integration to put the cursor on after the next load
	sub          tea.Model

	tokenNames        []string
	tokenCursor       int
	tokenActionCursor int
	tokenEditBuf      strings.Builder // scope note edit OR rotation value
	// tokenScopeMode true = preset picker, false = free-text input.
	tokenScopeMode       bool
	tokenScopePickCursor int

	// Integration-level edit form state (integModeIntEdit).
	intEditField         int
	intEditNameBuf       textField
	intEditNameWas       string // snapshot at open time, so rename detection is cheap at save
	intEditKindCursor    int
	intEditKindChoice    string
	intEditDescBuf       textField
	intEditKindSlotBuf   textField
	intEditProjectsBuf   textField
	intEditTagsBuf       textField
	intEditProtectCursor int
	intEditProtectChoice bool // mirrors protectionPresets[cursor].value
	intEditProtectWas    bool // snapshot at enter time, used to decide if passphrase step is needed
	intEditPassBuf       textField
}

// Integration edit field constants. Name is field 0 so a rename is the
// first thing an operator sees.
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
	return &integrationListView{client: c, paths: p, list: newNameList()}
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

var integInfoActions = []listAction{
	{label: "Edit", key: "e", desc: "name, kind, description, URL, projects, tags, protection"},
	{label: "Remove", key: "r", desc: "removes the integration and the grants that use it"},
}

var credActions = []listAction{
	{label: "Edit scope note", key: "s", desc: "the note that says what this credential can do"},
	{label: "Rotate value", key: "o", desc: "replace the upstream secret with a new value"},
	{label: "Remove credential", key: "x", desc: "removes it and the grants that use it"},
}

func (v *integrationListView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if v.sub != nil {
		// An embedded view (add credential, grant detail) owns the screen
		// until it is done; then the integration reloads.
		if ws, ok := msg.(tea.WindowSizeMsg); ok {
			v.width, v.height = ws.Width, ws.Height
		}
		m, cmd := v.sub.Update(msg)
		if d, ok := m.(doner); ok && d.Done() {
			if f, ok := m.(flasher); ok && f.Flash() != "" {
				v.flash = f.Flash()
			}
			v.sub, v.keep = nil, v.selectedName()
			return v, v.load
		}
		v.sub = m
		return v, cmd
	}
	switch mm := msg.(type) {
	case integListLoadedMsg:
		v.loaded = true
		v.loadErr = mm.err
		v.items = mm.items
		v.grants = mm.grants
		v.names = v.names[:0]
		for n := range mm.items {
			v.names = append(v.names, n)
		}
		sort.Strings(v.names)
		for i, n := range v.names {
			if n == v.keep {
				v.cursor = i
			}
		}
		v.keep = ""
		v.cursor = max(min(v.cursor, len(v.names)-1), 0)
		items := make([]list.Item, len(v.names))
		for i, n := range v.names {
			items[i] = nameItem{n, v.items[n].Description}
		}
		v.list.SetItems(items)
		v.refreshTokens()
	case tea.WindowSizeMsg:
		v.width, v.height = mm.Width, mm.Height
	case integActionMsg:
		if mm.err != "" {
			// Errors stay on the screen that caused them, in plain words.
			v.err = map[string]string{"remove": "Remove", "scope": "Scope note", "rotate": "Rotate",
				"remove-cred": "Remove credential", "edit": "Save"}[v.pending] + " failed: " + cliErr(mm.err)
			v.mode = v.back
			return v, nil
		}
		v.mode = integModeDone
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
		case integModeList:
			if toggleHelp(&v.help, mm) {
				return v, nil
			}
			return v.updateList(mm)
		case integModeDetail:
			if toggleHelp(&v.help, mm) {
				return v, nil
			}
			return v.updateDetail(mm)
		case integModeConfirm:
			return v.updateConfirm(mm)
		case integModeDone:
			if mm.String() != "enter" {
				return v, nil // done screens leave on enter only
			}
			v.mode = integModeDetail
			if v.pending == "remove" {
				v.mode = integModeList
			}
			v.pending = ""
			return v, v.load
		case integModeTokenAction:
			if toggleHelp(&v.help, mm) {
				return v, nil
			}
			return v.updateTokenAction(mm)
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

// startRun puts pending in flight; a failure returns to back.
func (v *integrationListView) startRun(pending string, back int, cmd tea.Cmd) (tea.Model, tea.Cmd) {
	v.pending, v.back, v.mode, v.err, v.help = pending, back, integModeRun, "", false
	if v.keep == "" {
		v.keep = v.selectedName()
	}
	return v, cmd
}

func (v *integrationListView) updateList(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	v.err = ""
	switch mm.String() {
	case "esc", "ctrl+c", "q":
		v.done = true
	case "up", "k":
		stepCursor(&v.cursor, len(v.names), -1)
	case "down", "j":
		stepCursor(&v.cursor, len(v.names), 1)
	case "enter":
		if len(v.names) > 0 {
			v.refreshTokens()
			v.mode, v.tab, v.actionCursor, v.tokenCursor, v.grantCursor = integModeDetail, 0, 0, 0, 0
		}
	case "e", "r":
		if len(v.names) > 0 {
			return v.runInfoAction(mm.String())
		}
	}
	return v, nil
}

// refreshTokens reloads the credential names of the integration under
// the cursor.
func (v *integrationListView) refreshTokens() {
	v.tokenNames = v.tokenNames[:0]
	for k := range v.items[v.selectedName()].Tokens {
		v.tokenNames = append(v.tokenNames, k)
	}
	sort.Strings(v.tokenNames)
	v.tokenCursor = max(min(v.tokenCursor, len(v.tokenNames)-1), 0)
	v.grantCursor = max(min(v.grantCursor, len(v.referrers(v.selectedName()))-1), 0)
}

func (v *integrationListView) updateDetail(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	v.err = ""
	refs := v.referrers(v.selectedName())
	switch k := mm.String(); k {
	case "esc", "backspace":
		v.mode = integModeList
	case "q", "ctrl+c":
		v.done = true
	case "tab":
		v.tab = (v.tab + 1) % 3
	case "shift+tab":
		v.tab = (v.tab + 2) % 3
	case "up", "k", "down", "j":
		d := 1
		if k == "up" || k == "k" {
			d = -1
		}
		switch v.tab {
		case 0:
			stepCursor(&v.actionCursor, len(integInfoActions), d)
		case 1:
			stepCursor(&v.tokenCursor, len(v.tokenNames), d)
		default:
			stepCursor(&v.grantCursor, len(refs), d)
		}
	case "enter":
		switch {
		case v.tab == 0:
			return v.runInfoAction(integInfoActions[v.actionCursor].key)
		case v.tab == 1 && len(v.tokenNames) > 0:
			v.mode, v.tokenActionCursor = integModeTokenAction, 0
		case v.tab == 2 && len(refs) > 0:
			g := newGrantListView(v.client, v.paths)
			g.Update(grantListLoadedMsg{items: v.grants})
			g.Update(tea.WindowSizeMsg{Width: v.width, Height: v.height})
			g.cursor = sort.SearchStrings(g.ids, refs[v.grantCursor])
			g.mode, g.solo = grantModeDetail, true
			v.sub = g
		}
	case "e", "r":
		return v.runInfoAction(k)
	case "a":
		// Credentials tab: add a credential (and its grant) to this
		// integration; Grants tab: add a grant on it.
		var a tea.Model
		switch v.tab {
		case 1:
			a = newAddCredentialView(v.client, v.paths, v.selectedName())
		case 2:
			a = newAddGrantFor(v.client, v.paths, v.selectedName())
		default:
			return v, nil
		}
		a, _ = a.Update(tea.WindowSizeMsg{Width: v.width, Height: v.height})
		v.sub = a
	}
	return v, nil
}

// runInfoAction runs an integration-level action: e edit, r remove.
func (v *integrationListView) runInfoAction(k string) (tea.Model, tea.Cmd) {
	v.from, v.help = v.mode, false
	if k == "e" {
		return v.enterIntEdit(), nil
	}
	v.mode = integModeConfirm
	return v, nil
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
	v.intEditNameBuf.SetString(name)
	v.intEditNameWas = name
	v.intEditKindChoice = vault.IntegrationKindOf(it)
	for i, p := range kindPresets {
		if p.value == v.intEditKindChoice {
			v.intEditKindCursor = i
			break
		}
	}
	v.intEditDescBuf.SetString(it.Description)
	switch vault.IntegrationKindOf(it) {
	case vault.IntegrationKindCLI:
		v.intEditKindSlotBuf.SetString(it.Metadata["cli_cmd"])
	case vault.IntegrationKindMCP:
		if it.Metadata["mcp_url"] != "" {
			v.intEditKindSlotBuf.SetString(it.Metadata["mcp_url"])
		} else {
			v.intEditKindSlotBuf.SetString(it.Metadata["mcp_cmd"])
		}
	default: // api, other
		v.intEditKindSlotBuf.SetString(it.Metadata["base_url"])
	}
	v.intEditProjectsBuf.SetString(strings.Join(it.Projects, ","))
	v.intEditTagsBuf.SetString(strings.Join(it.Tags, ","))
	v.intEditProtectChoice = it.Protected
	v.intEditProtectWas = it.Protected
	for i, p := range protectionPresets {
		if p.value == it.Protected {
			v.intEditProtectCursor = i
			break
		}
	}
	v.intEditPassBuf.Reset()
	v.err = ""
	v.mode = integModeIntEdit
	return v
}

func (v *integrationListView) updateConfirm(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch mm.String() {
	case "y", "Y", "enter":
		return v.startRun("remove", v.from, v.doRemove())
	case "n", "N", "esc":
		v.mode = v.from
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
	if v.sub != nil {
		return v.sub.View()
	}
	width, height := v.width, v.height
	if width == 0 || height == 0 {
		width, height = 80, 24
	}
	switch {
	case !v.loaded:
		return frame(width, height, "Integrations", nil, "", []string{mutedSt.Render("  loading…")}, "", "")
	case v.loadErr != "":
		return frame(width, height, "Integrations", nil, "", []string{v.loadErr}, "", footer(width, keyBack))
	}
	switch v.mode {
	case integModeDetail, integModeTokenAction:
		return v.viewDetail(width, height)
	case integModeConfirm:
		return v.viewConfirm(width, height)
	case integModeRun:
		return v.viewRun(width, height)
	case integModeDone:
		return v.viewDone(width, height)
	case integModeTokenEditScope:
		return v.viewTokenEditScope(width, height)
	case integModeTokenRotate:
		return v.viewTokenRotate(width, height)
	case integModeTokenRemoveConfirm:
		return v.viewTokenRemoveConfirm(width, height)
	case integModeIntEdit:
		return v.viewIntEdit(width, height)
	}

	km := integListKeys
	st := status{err: v.err, flash: v.flash}
	var body []string
	if len(v.names) == 0 {
		body = []string{bodySt.Render("  No integrations yet. Add one from the menu: Add › Integration.")}
		km.short = km.short[1:] // nothing to open
	} else {
		rows := frameRows(height)
		if v.help {
			rows -= len(km.helpLines(width)) + 1
		}
		body = nameListBody(&v.list, "description", v.cursor, width, rows)
		st.setHint(v.rowHint(v.selectedName()))
	}
	body = km.overlay(body, width, frameRows(height), v.help)
	return frame(width, height, "Integrations", nil, fmt.Sprintf("%d total", len(v.names)), body, st.String(), km.footerLine(width, v.help))
}

// rowHint is the status line for an integration row: full name when
// truncated, kind, credentials, grants, protected.
func (v *integrationListView) rowHint(name string) string {
	it := v.items[name]
	var parts []string
	if lipgloss.Width(name) > nameColW {
		parts = append(parts, name)
	}
	parts = append(parts, "kind "+vault.IntegrationKindOf(it), plural(len(it.Tokens), "credential"), plural(len(v.referrers(name)), "grant"))
	if it.Protected {
		parts = append(parts, "protected")
	}
	return strings.Join(parts, " · ")
}

var integListKeys = keyMap{
	short: []key.Binding{keyOpen, keyBack},
	full: [][]key.Binding{
		{keyMove, hint("enter", "open integration"), hint("e", "edit"), hint("r", "remove")},
		{keyBack, keyQuit},
	},
}

// integDetailKeys is the detail's expanded help; short is per tab.
var integDetailKeys = keyMap{
	full: [][]key.Binding{
		{keyMove, hint("enter", "run / open"), hint("tab", "next tab"), hint("shift+tab", "previous tab")},
		{hint("e", "edit"), hint("r", "remove"), hint("a", "add credential / grant"), keyBack, keyQuit},
	},
	notes: []string{
		"Projects and tags group integrations and grants; they are not permissions.",
		"Edit every credential value at once with dop vault edit.",
	},
}

// infoBody is the Info tab's kv block: primary fields, then the rest of
// the metadata in muted.
func (v *integrationListView) infoBody(name string, it vault.Integration, width int) []string {
	var rows [][2]string
	add := func(l, val string) {
		if val != "" {
			rows = append(rows, [2]string{l, val})
		}
	}
	if lipgloss.Width(name) > max(width-46, 12) {
		add("name", name) // the title is truncated
	}
	add("kind", vault.IntegrationKindOf(it))
	m := it.Metadata
	add("description", it.Description)
	add("base URL", m["base_url"])
	add("command", m["cli_cmd"])
	add("MCP URL", m["mcp_url"])
	add("MCP command", m["mcp_cmd"])
	add("protection", protectWord(it.Protected))
	add("projects", strings.Join(it.Projects, ", "))
	add("tags", strings.Join(it.Tags, ", "))
	primary := len(rows)
	var keys []string
	for k, val := range m {
		switch k {
		case "base_url", "cli_cmd", "mcp_url", "mcp_cmd", "mcp_probe_result":
		default:
			if val != "" {
				keys = append(keys, k)
			}
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		val := m[k]
		if k == "mcp_probed_at" && m["mcp_probe_result"] != "" {
			val += " (" + m["mcp_probe_result"] + ")"
		}
		add(strings.ReplaceAll(k, "_", " "), mutedSt.Render(val))
	}
	lines := strings.Split(strings.TrimRight(kv(rows...), "\n"), "\n")
	if len(lines) > primary {
		lines = append(append(append([]string{}, lines[:primary]...), ""), lines[primary:]...)
	}
	return lines
}

// maskLen hides a credential value and shows only its length.
func maskLen(s string) string { return "•••• " + plural(len([]rune(s)), "char") }

func (v *integrationListView) viewDetail(width, height int) string {
	name := v.selectedName()
	it := v.items[name]
	refs := v.referrers(name)
	tabs := []tab{{"Info", -1, v.tab == 0}, {"Credentials", len(v.tokenNames), v.tab == 1}, {"Grants", len(refs), v.tab == 2}}
	st := status{err: v.err, flash: v.flash}
	km := integDetailKeys
	var body []string
	switch v.tab {
	case 0:
		body = append(append(v.infoBody(name, it, width), ""), actionRows(integInfoActions, v.actionCursor, &st)...)
		km.short = []key.Binding{hint("enter", "run"), hint("tab", "credentials"), keyBack}
	case 1:
		km.short = []key.Binding{hint("enter", "open"), hint("a", "add"), hint("tab", "grants"), keyBack}
		if len(v.tokenNames) == 0 {
			body = []string{bodySt.Render("  No credentials yet. Press a to add one.")}
			km.short = km.short[1:]
			break
		}
		acting := v.mode == integModeTokenAction
		body = []string{"  " + mutedSt.Render(padTrunc("name", 24)+"  "+padTrunc("value", 14)+"  scope note")}
		for i, tn := range v.tokenNames {
			t := it.Tokens[tn]
			cells, note := padTrunc(tn, 24)+"  "+padTrunc(maskLen(t.Value), 14), "  "+t.ScopeNote
			switch {
			case i == v.tokenCursor && !acting:
				body = append(body, focusSt.Render("› "+cells+note))
			case i == v.tokenCursor:
				body = append(body, "  "+bodySt.Render(cells+note))
			case acting:
				body = append(body, "  "+mutedSt.Render(cells+note))
			default:
				body = append(body, "  "+bodySt.Render(cells)+mutedSt.Render(note))
			}
		}
		tn := v.tokenNames[v.tokenCursor]
		hintParts := []string{}
		if lipgloss.Width(tn) > 24 {
			hintParts = append(hintParts, tn)
		}
		if it.Protected {
			hintParts = append(hintParts, "protected")
		}
		st.setHint(strings.Join(hintParts, " · "))
		if isPlaceholderTokenValue(it.Tokens[tn].Value) && st.err == "" {
			st.setError("This value looks like a placeholder. Rotate in the real one.")
		}
		if acting {
			body = append(append(body, ""), actionRows(credActions, v.tokenActionCursor, &st)...)
			km.short = []key.Binding{hint("enter", "run"), keyBack}
		}
	default:
		km.short = []key.Binding{hint("enter", "open"), hint("a", "add"), hint("tab", "info"), keyBack}
		if len(refs) == 0 {
			body = []string{bodySt.Render("  No grant uses it yet. Press a to add one.")}
			km.short = km.short[1:]
			break
		}
		body = []string{"  " + mutedSt.Render(padTrunc("name", nameColW)+"  credential")}
		for i, gid := range refs {
			cred := v.grants[gid].Token
			if i == v.grantCursor {
				body = append(body, focusSt.Render("› "+padTrunc(gid, nameColW)+"  "+cred))
			} else {
				body = append(body, "  "+bodySt.Render(padTrunc(gid, nameColW))+"  "+mutedSt.Render(cred))
			}
		}
		st.setHint(grantHint(refs[v.grantCursor], v.grants[refs[v.grantCursor]]))
	}
	ctx := ""
	if it.Protected {
		ctx = "protected"
	}
	body = km.overlay(body, width, frameRows(height), v.help)
	title := ansi.Truncate(name, max(width-46, 12), "…")
	return frame(width, height, title, tabs, ctx, body, st.String(), km.footerLine(width, v.help))
}

func (v *integrationListView) viewConfirm(width, height int) string {
	name := v.selectedName()
	it := v.items[name]
	body := strings.Split(kv([2]string{"kind", vault.IntegrationKindOf(it)},
		[2]string{"credentials", fmt.Sprint(len(it.Tokens))}), "\n")
	if refs := v.referrers(name); len(refs) > 0 {
		body = append(append(body, mutedSt.Render("  Removed with it")), upTo5(refs)...)
	}
	return frame(width, height, "Remove "+name+"?", nil, "", body, "", confirmFoot("remove"))
}

// viewRun is the in-flight screen: one present-tense title, no footer
// (the subprocess can't be cancelled).
func (v *integrationListView) viewRun(width, height int) string {
	what := v.selectedTokenName()
	verb := map[string]string{"remove": "Removing %s…", "scope": "Saving the scope note of %s…",
		"rotate": "Rotating %s…", "remove-cred": "Removing %s…", "edit": "Saving %s…"}[v.pending]
	if v.pending == "remove" || v.pending == "edit" {
		what = v.selectedName()
	}
	return frame(width, height, fmt.Sprintf(verb, what), nil, "", nil, "", "")
}

// viewDone is the ✓ outcome of an integration action; any key returns.
func (v *integrationListView) viewDone(width, height int) string {
	title := map[string]string{"remove": "✓ Integration removed", "scope": "✓ Scope note saved",
		"rotate": "✓ Credential rotated", "remove-cred": "✓ Credential removed", "edit": "✓ Integration saved"}[v.pending]
	rows := [][2]string{{"integration", v.keep}}
	switch v.pending {
	case "scope":
		rows = append(rows, [2]string{"credential", v.selectedTokenName()}, [2]string{"scope note", v.tokenEditBuf.String()})
	case "rotate", "remove-cred":
		rows = append(rows, [2]string{"credential", v.selectedTokenName()})
	}
	body := append(strings.Split(kv(rows...), "\n"), mutedSt.Render("  The vault is synced with the team."))
	return frame(width, height, title, nil, "", body, "", footer(width, hint("enter", "done")))
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
	wiz
	client *admin.Client
	paths  *config.Paths

	// v1.13.0-rc8 — flow now goes:
	//   0 pick service
	//   1 multi-select tokens within the service
	//   2 confirm (shows cascade preview: grants dropped + bearers affected)
	//   3 running
	//   4 done
	step      int
	loaded    bool
	err       string
	names     []string
	items     map[string]vault.Integration
	grants    map[string]vault.Grant
	caps      map[string]vault.Capability
	cursor    int
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
	flash         string
	done          bool
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
	if ok, cmd := v.wizMsg(msg, false); ok {
		return v, cmd
	}
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
			v.err = "Remove failed: " + firstLine(mm.err)
			v.step = 2
			return v, nil
		}
		v.flash = "Credentials removed"
		v.step = 4
	case tea.KeyMsg:
		switch mm.String() {
		case "esc", "ctrl+c":
			if v.step == 4 || mm.String() == "ctrl+c" {
				v.done = true
				return v, nil
			}
			if v.step == 3 {
				return v, nil
			}
			if v.step == 0 {
				v.done = true
				return v, nil
			}
			// v1.13.0-rc8 — nested esc: step back one level.
			v.step--
			v.err = ""
			return v, nil
		}
		if v.step == 4 {
			v.done = true
			return v, nil
		}
		if !v.loaded || v.step == 3 {
			return v, nil
		}
		if v.step == 1 && mm.String() != "enter" {
			v.err = ""
		}
		switch v.step {
		case 0:
			switch mm.String() {
			case "up", "k":
				stepCursor(&v.cursor, len(v.names), -1)
			case "down", "j":
				stepCursor(&v.cursor, len(v.names), 1)
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
				stepCursor(&v.tokenCursor, len(v.tokenNames), -1)
			case "down", "j":
				stepCursor(&v.tokenCursor, len(v.tokenNames), 1)
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
					v.err = "Select at least one credential with space"
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
				v.step, v.err = 3, ""
				return v, tea.Batch(v.spinStart(), v.doRemove())
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
	const title = "Remove credentials"
	switch {
	case !v.loaded:
		return v.notice(title, "  loading…")
	case v.err != "" && len(v.names) == 0:
		return v.notice(title, v.err)
	case len(v.names) == 0:
		return v.notice(title, mutedSt.Render("  No integrations yet. Add one from the menu: Add › Integration."))
	}
	target := v.names[v.cursor]
	integ := v.items[target]
	switch v.step {
	case 0:
		var opts [][2]string
		for _, n := range v.names {
			opts = append(opts, [2]string{ansi.Truncate(n, 40, "…"), v.items[n].Description})
		}
		return v.pick(title, plural(len(v.names), "service"), opts, v.cursor,
			strings.Join([]string{target, vault.IntegrationKindOf(integ), plural(len(integ.Tokens), "credential")}, " · "), "", pickKeys("next"))
	case 1:
		body := []string{mutedSt.Render("  Credentials of " + ansi.Truncate(target, 50, "…"))}
		for i, tn := range v.tokenNames {
			mark, name := mutedSt.Render("○"), bodySt.Render(padTrunc(tn, 28))
			if v.tokenSelected[tn] {
				mark = okSt.Render("●")
			}
			scope := mutedSt.Render("  " + integ.Tokens[tn].ScopeNote)
			if i == v.tokenCursor {
				body = append(body, focusSt.Render("› ")+mark+" "+focusSt.Render(padTrunc(tn, 28))+scope)
			} else {
				body = append(body, "  "+mark+" "+name+scope)
			}
		}
		st := status{err: v.err}
		st.setHint(fmt.Sprintf("%d of %d selected · space toggles", v.selectedTokenCount(), len(v.tokenNames)))
		km := keyMap{short: []key.Binding{hint("enter", "next"), keyBack},
			full: [][]key.Binding{{keySpace, hint("enter", "next"), keyBack}, {keyMove, hint("a", "all"), hint("n", "none")}}}
		body = km.overlay(body, v.width, frameRows(v.height), v.help)
		return frame(v.width, v.height, title, nil, ansi.Truncate(target, 30, "…"), body, st.String(), km.footerLine(v.width, v.help))
	case 2:
		picked := []string{}
		for _, tn := range v.tokenNames {
			if v.tokenSelected[tn] {
				picked = append(picked, tn)
			}
		}
		var body []string
		section := func(st lipgloss.Style, glyph, head string, names []string) {
			if len(names) > 0 {
				body = append(append(append(body, st.Render(glyph+" "+head)), upTo5(names)...), "")
			}
		}
		section(dangerSt, "!", plural(len(v.previewGrants), "grant")+" will be removed", v.previewGrants)
		section(okSt, "✓", plural(len(v.previewReseal), "bearer")+" will be resealed (env updated live)", v.previewReseal)
		section(dangerSt, "!", plural(len(v.previewStale), "bearer")+" will keep a stale env (bundle cannot be rewritten)", v.previewStale)
		section(dangerSt, "!", plural(len(v.previewEmpty), "bearer")+" will have no grants left and be revoked", v.previewEmpty)
		if len(picked) == len(integ.Tokens) {
			body = append(body, dangerSt.Render("! The integration is removed too: all its credentials are selected."))
		}
		if len(body) == 0 {
			body = []string{mutedSt.Render("  Nothing else changes.")}
		}
		return v.confirmScreen("Remove "+plural(len(picked), "credential")+" from "+ansi.Truncate(target, 36, "…")+"?", body, "remove", v.err)
	case 3:
		return v.running(title, "Removing credentials from "+target)
	}
	return v.doneScreen("Credentials removed", [][2]string{{"integration", target}}, "The vault is synced with the team.", "")
}

// ---------- Credentials (Credentials tab of the integration detail) ----------

func (v *integrationListView) updateTokenAction(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	v.err = ""
	switch mm.String() {
	case "esc", "backspace":
		v.mode = integModeDetail
	case "q", "ctrl+c":
		v.done = true
	case "up", "k":
		stepCursor(&v.tokenActionCursor, len(credActions), -1)
	case "down", "j":
		stepCursor(&v.tokenActionCursor, len(credActions), 1)
	case "enter":
		return v.runTokenAction(credActions[v.tokenActionCursor])
	}
	return v, nil
}

func (v *integrationListView) runTokenAction(a listAction) (tea.Model, tea.Cmd) {
	tokenName := v.selectedTokenName()
	if tokenName == "" {
		return v, nil
	}
	v.help = false
	switch a.key {
	case "s":
		// Scope editor opens on the preset picker, on the current note's
		// preset, else on "other…".
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
	case "x":
		v.mode = integModeTokenRemoveConfirm
	}
	return v, nil
}

func (v *integrationListView) selectedTokenName() string {
	if v.tokenCursor < 0 || v.tokenCursor >= len(v.tokenNames) {
		return ""
	}
	return v.tokenNames[v.tokenCursor]
}

// updateTokenEditScope: preset picker first; "other…" drops to free
// text; empty + backspace returns to the picker.
func (v *integrationListView) updateTokenEditScope(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	v.err = ""
	if v.tokenScopeMode {
		switch mm.String() {
		case "esc":
			v.mode = integModeTokenAction
		case "up", "k":
			stepCursor(&v.tokenScopePickCursor, len(scopePresets), -1)
		case "down", "j":
			stepCursor(&v.tokenScopePickCursor, len(scopePresets), 1)
		case "enter":
			sel := scopePresets[v.tokenScopePickCursor]
			if sel.value == "" {
				// "other…" — free text, starting from the current note.
				v.tokenScopeMode = false
				return v, nil
			}
			v.tokenEditBuf.Reset()
			v.tokenEditBuf.WriteString(sel.value)
			return v.startRun("scope", integModeTokenEditScope, v.doTokenSetScope())
		}
		return v, nil
	}
	switch mm.String() {
	case "esc":
		v.tokenScopeMode = true // back to the preset picker
	case "enter":
		return v.startRun("scope", integModeTokenEditScope, v.doTokenSetScope())
	case "backspace":
		s := v.tokenEditBuf.String()
		if len(s) > 0 {
			v.tokenEditBuf.Reset()
			v.tokenEditBuf.WriteString(s[:len(s)-1])
		} else {
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
	v.err = ""
	switch mm.String() {
	case "esc":
		v.mode = integModeTokenAction
	case "enter":
		if v.tokenEditBuf.Len() == 0 {
			v.err = "Enter the new value."
			return v, nil
		}
		return v.startRun("rotate", integModeTokenRotate, v.doTokenRotate())
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
		return v.startRun("remove-cred", integModeTokenAction, v.doTokenRemove())
	case "n", "N", "esc":
		v.mode = integModeTokenAction
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
// Text fields: Name, Desc, KindSlot, Projects, Tags, Passphrase.
// Picker fields: Kind, Protection. Passphrase only when flipping
// unprotected → protected.
func (v *integrationListView) updateIntEdit(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	v.err = ""
	if v.intEditField == intEditFieldKind {
		switch mm.String() {
		case "esc":
			v.mode = v.from
		case "up", "k":
			stepCursor(&v.intEditKindCursor, len(kindPresets), -1)
		case "down", "j":
			stepCursor(&v.intEditKindCursor, len(kindPresets), 1)
		case "enter", "tab":
			v.intEditKindChoice = kindPresets[v.intEditKindCursor].value
			v.intEditField = intEditFieldDesc
		case "shift+tab":
			v.intEditField = intEditFieldName
		}
		return v, nil
	}
	if v.intEditField == intEditFieldProtection {
		switch mm.String() {
		case "esc":
			v.mode = v.from
		case "up", "k":
			stepCursor(&v.intEditProtectCursor, len(protectionPresets), -1)
		case "down", "j":
			stepCursor(&v.intEditProtectCursor, len(protectionPresets), 1)
		case "enter":
			v.intEditProtectChoice = protectionPresets[v.intEditProtectCursor].value
			if v.intEditProtectChoice && !v.intEditProtectWas {
				v.intEditField = intEditFieldPassphrase
			} else {
				return v.saveIntEdit()
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
	// Text fields: caret keys and runes go to the field; navigation
	// keys fall through.
	key := mm.String()
	if buf := v.intEditCurBuf(); buf != nil {
		switch key {
		case "left", "right", "home", "end", "ctrl+a", "ctrl+e", "backspace", "delete", "ctrl+d":
			buf.handleKey(key, mm.Runes)
			return v, nil
		default:
			if len(mm.Runes) > 0 && key != "enter" && key != "tab" && key != "shift+tab" && key != "up" && key != "down" && key != "esc" {
				buf.InsertRunes(mm.Runes)
				return v, nil
			}
		}
	}
	switch key {
	case "esc":
		v.mode = v.from
	case "enter", "tab", "down":
		switch v.intEditField {
		case intEditFieldName:
			v.intEditField = intEditFieldKind
		case intEditFieldDesc, intEditFieldKindSlot, intEditFieldProjects:
			v.intEditField++
		case intEditFieldTags:
			v.intEditField = intEditFieldProtection
		case intEditFieldPassphrase:
			if key != "enter" {
				break
			}
			if v.intEditPassBuf.Len() == 0 {
				v.err = "Enter the approval passphrase to protect this integration."
				return v, nil
			}
			return v.saveIntEdit()
		}
	case "shift+tab", "up":
		switch v.intEditField {
		case intEditFieldPassphrase:
			v.intEditField = intEditFieldProtection
		case intEditFieldDesc:
			v.intEditField = intEditFieldKind
		case intEditFieldName:
		default:
			v.intEditField--
		}
	}
	return v, nil
}

func (v *integrationListView) saveIntEdit() (tea.Model, tea.Cmd) {
	if n := strings.TrimSpace(v.intEditNameBuf.String()); n != "" {
		v.keep = n // cursor follows a rename
	}
	return v.startRun("edit", integModeIntEdit, v.doIntEdit())
}

func (v *integrationListView) intEditCurBuf() *textField {
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
	// A different name renames FIRST (its own CLI subcommand, audit
	// event and grant rewrite), then the renamed integration is updated.
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
				return integActionMsg{err: strings.TrimSpace(rstderr.String())}
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
		// Always pass projects + tags (empty clears, nonempty replaces).
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

func (v *integrationListView) viewTokenEditScope(width, height int) string {
	var body []string
	if v.tokenScopeMode {
		var opts [][2]string
		for _, p := range scopePresets {
			opts = append(opts, [2]string{p.label, ""})
		}
		body = pickRows("scope note", opts, v.tokenScopePickCursor)
	} else {
		body = []string{formRow(true, "scope note", v.tokenEditBuf.String(), ""),
			mutedSt.Render("  Free text. Empty + backspace returns to the presets.")}
	}
	foot := footer(width, hint("enter", "save"), keyBack)
	return frame(width, height, "Scope note of "+v.selectedTokenName(), nil, v.selectedName(), body, status{err: v.err}.String(), foot)
}

func (v *integrationListView) viewTokenRotate(width, height int) string {
	body := []string{formRow(true, "new value", strings.Repeat("•", v.tokenEditBuf.Len()), ""),
		mutedSt.Render("  Sent to the CLI on stdin, never shown.")}
	foot := footer(width, hint("enter", "save"), keyBack)
	return frame(width, height, "Rotate "+v.selectedTokenName(), nil, v.selectedName(), body, status{err: v.err}.String(), foot)
}

func (v *integrationListView) viewTokenRemoveConfirm(width, height int) string {
	name, tn := v.selectedName(), v.selectedTokenName()
	body := strings.Split(kv([2]string{"integration", name},
		[2]string{"scope note", v.items[name].Tokens[tn].ScopeNote}), "\n")
	var refs []string
	for _, gid := range v.referrers(name) {
		if v.grants[gid].Token == tn {
			refs = append(refs, gid)
		}
	}
	if len(refs) > 0 {
		body = append(append(body, mutedSt.Render("  Removed with it")), upTo5(refs)...)
		body = append(body, "", mutedSt.Render("  Bearers holding these grants are resealed where possible."))
	}
	return frame(width, height, "Remove credential "+tn+"?", nil, "", body, status{err: v.err}.String(), confirmFoot("remove"))
}

// viewIntEdit is the integration edit form: one row per field, the
// focused one with › and the caret; pickers open in place.
func (v *integrationListView) viewIntEdit(width, height int) string {
	f := v.intEditField
	text := func(field int, label string, buf *textField) string {
		if f != field {
			return formRow(false, label, buf.String(), "")
		}
		b, a := buf.Split()
		return formRow(true, label, b, a)
	}
	body := []string{text(intEditFieldName, "name", &v.intEditNameBuf)}
	if f == intEditFieldName {
		body = append(body, mutedSt.Render("  Renaming also renames the grants that use it."))
	}
	if f == intEditFieldKind {
		var opts [][2]string
		for _, p := range kindPresets {
			opts = append(opts, [2]string{p.label, p.hint})
		}
		body = append(body, pickRows("kind", opts, v.intEditKindCursor)...)
	} else {
		body = append(body, formRow(false, "kind", v.intEditKindChoice, ""))
	}
	slotLbl := map[string]string{vault.IntegrationKindCLI: "command", vault.IntegrationKindMCP: "MCP URL or command",
		vault.IntegrationKindOther: "extra config"}[v.intEditKindChoice]
	if slotLbl == "" {
		slotLbl = "base URL"
	}
	body = append(body, text(intEditFieldDesc, "description", &v.intEditDescBuf), text(intEditFieldKindSlot, slotLbl, &v.intEditKindSlotBuf))
	if f == intEditFieldKindSlot {
		_, h := kindSlotLabel(v.intEditKindChoice)
		body = append(body, mutedSt.Render("  "+h))
	}
	body = append(body, text(intEditFieldProjects, "projects", &v.intEditProjectsBuf), text(intEditFieldTags, "tags", &v.intEditTagsBuf))
	if f == intEditFieldProjects || f == intEditFieldTags {
		body = append(body, mutedSt.Render("  Comma-separated."))
	}
	if f == intEditFieldProtection {
		body = append(body, pickRows("protection", protectOpts(), v.intEditProtectCursor)...)
	} else {
		body = append(body, formRow(false, "protection", protectWord(v.intEditProtectChoice), ""))
	}
	if v.intEditProtectChoice && !v.intEditProtectWas {
		if f == intEditFieldPassphrase {
			b, a := v.intEditPassBuf.SplitMasked("•")
			body = append(body, formRow(true, "approval passphrase", b, a))
		} else {
			body = append(body, formRow(false, "approval passphrase", strings.Repeat("•", v.intEditPassBuf.Len()), ""))
		}
	}
	verb := "next"
	if f == intEditFieldPassphrase || (f == intEditFieldProtection && !(protectionPresets[v.intEditProtectCursor].value && !v.intEditProtectWas)) {
		verb = "save"
	}
	foot := footer(width, hint("enter", verb), hint("tab", "field"), keyBack)
	return frame(width, height, "Edit "+v.selectedName(), nil, "", body, status{err: v.err}.String(), foot)
}

// ---------- Grant list ----------

const (
	grantModeList    = 0
	grantModeDetail  = 1 // detail + actions
	grantModeConfirm = 2
	grantModeRun     = 3
	grantModeDone    = 4
	grantModeEdit    = 5
)

// Edit fields; the passphrase only when flipping unprotected → protected.
const (
	grantEditFieldProjects   = 0
	grantEditFieldTags       = 1
	grantEditFieldEnvPrefix  = 2
	grantEditFieldProtection = 3
	grantEditFieldPassphrase = 4
)

type grantListView struct {
	client  *admin.Client
	paths   *config.Paths
	loaded  bool
	loadErr string
	err     string // last action's failure, on the status line
	ids     []string
	items   map[string]vault.Grant
	done    bool
	solo    bool // opened from an integration's Grants tab: esc from the detail is done

	mode          int
	cursor        int
	actionCursor  int
	help          bool
	flash         string
	pending       string // remove, edit
	from          int    // mode a confirm or the edit form returns to
	list          list.Model
	width, height int

	editField   int
	editProject strings.Builder
	editTags    strings.Builder
	editPrefix  strings.Builder
	// grant-level protection toggle in the edit form.
	editProtectCursor int
	editProtectChoice bool
	editProtectWas    bool
	editPassBuf       strings.Builder
}

func newGrantListView(c *admin.Client, p *config.Paths) *grantListView {
	return &grantListView{client: c, paths: p, list: newNameList()}
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

var grantActions = []listAction{
	{label: "Edit", key: "e", desc: "projects, tags, env prefix, protection"},
	{label: "Remove", key: "r", desc: "bearers holding it fail on their next exec"},
}

// grantHint is the status line for a grant: full id when truncated,
// integration · credential · env prefix · projects · protected.
func grantHint(id string, g vault.Grant) string {
	var parts []string
	if lipgloss.Width(id) > nameColW {
		parts = append(parts, id)
	}
	parts = append(parts, g.Integration, g.Token, g.EffectivePrefix())
	if len(g.Projects) > 0 {
		parts = append(parts, strings.Join(g.Projects, ", "))
	}
	if g.Protected {
		parts = append(parts, "protected")
	}
	return strings.Join(parts, " · ")
}

func (v *grantListView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch mm := msg.(type) {
	case tea.WindowSizeMsg:
		v.width, v.height = mm.Width, mm.Height
	case grantListLoadedMsg:
		v.loaded = true
		v.loadErr = mm.err
		v.items = mm.items
		v.ids = v.ids[:0]
		for id := range v.items {
			v.ids = append(v.ids, id)
		}
		sort.Strings(v.ids)
		v.cursor = max(min(v.cursor, len(v.ids)-1), 0)
		items := make([]list.Item, len(v.ids))
		for i, id := range v.ids {
			items[i] = nameItem{id, v.items[id].Integration}
		}
		v.list.SetItems(items)
	case grantActionMsg:
		if mm.err != "" {
			// Errors stay on the screen that caused them, in plain words.
			if mm.kind == "edit" {
				v.err, v.mode = "Save failed: "+cliErr(mm.err), grantModeEdit
			} else {
				v.err, v.mode = "Remove failed: "+cliErr(mm.err), v.from
			}
			return v, nil
		}
		v.pending, v.mode = mm.kind, grantModeDone
	case tea.KeyMsg:
		if !v.loaded || v.loadErr != "" {
			if mm.String() == "esc" || mm.String() == "ctrl+c" {
				v.done = true
			}
			return v, nil
		}
		v.flash = ""
		switch v.mode {
		case grantModeList:
			if toggleHelp(&v.help, mm) {
				return v, nil
			}
			return v.updateList(mm)
		case grantModeDetail:
			if toggleHelp(&v.help, mm) {
				return v, nil
			}
			return v.updateDetail(mm)
		case grantModeConfirm:
			return v.updateConfirm(mm)
		case grantModeEdit:
			return v.updateEdit(mm)
		case grantModeDone:
			if mm.String() != "enter" {
				return v, nil // done screens leave on enter only
			}
			v.done = v.solo
			v.mode, v.pending = grantModeList, ""
			return v, v.load
		}
	}
	return v, nil
}

func (v *grantListView) updateList(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	v.err = ""
	switch k := mm.String(); k {
	case "esc", "ctrl+c", "q":
		v.done = true
	case "up", "k":
		stepCursor(&v.cursor, len(v.ids), -1)
	case "down", "j":
		stepCursor(&v.cursor, len(v.ids), 1)
	case "enter":
		if len(v.ids) > 0 {
			v.mode, v.actionCursor = grantModeDetail, 0
		}
	case "e", "r":
		if len(v.ids) > 0 {
			return v.runAction(k)
		}
	}
	return v, nil
}

func (v *grantListView) updateDetail(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	v.err = ""
	switch k := mm.String(); k {
	case "esc", "backspace":
		v.mode = grantModeList
		v.done = v.solo
	case "q", "ctrl+c":
		v.done = true
	case "up", "k":
		stepCursor(&v.actionCursor, len(grantActions), -1)
	case "down", "j":
		stepCursor(&v.actionCursor, len(grantActions), 1)
	case "enter":
		return v.runAction(grantActions[v.actionCursor].key)
	case "e", "r":
		return v.runAction(k)
	}
	return v, nil
}

// runAction: e opens the edit form, r the remove confirm.
func (v *grantListView) runAction(k string) (tea.Model, tea.Cmd) {
	v.from, v.help = v.mode, false
	if k == "e" {
		v.openEditor()
	} else {
		v.mode = grantModeConfirm
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
	v.err = ""
	needsPass := v.editProtectChoice && !v.editProtectWas
	last := grantEditFieldProtection
	if needsPass {
		last = grantEditFieldPassphrase
	}
	k := mm.String()
	if v.editField == grantEditFieldProtection && (k == "up" || k == "down" || k == "k" || k == "j") {
		d := 1
		if k == "up" || k == "k" {
			d = -1
		}
		stepCursor(&v.editProtectCursor, len(protectionPresets), d)
		v.editProtectChoice = protectionPresets[v.editProtectCursor].value
		return v, nil
	}
	switch k {
	case "esc":
		v.mode = v.from
	case "tab", "down":
		if v.editField < last {
			v.editField++
		}
	case "shift+tab", "up":
		if v.editField > grantEditFieldProjects {
			v.editField--
		}
	case "enter":
		if v.editField < last {
			v.editField++
			return v, nil
		}
		if needsPass && v.editPassBuf.Len() == 0 {
			v.err = "Enter the approval passphrase to protect this grant."
			return v, nil
		}
		v.mode, v.help, v.pending = grantModeRun, false, "edit"
		return v, v.doEdit()
	case "backspace":
		if buf := v.editBuf(); buf != nil && buf.Len() > 0 {
			s := buf.String()
			buf.Reset()
			buf.WriteString(s[:len(s)-1])
		}
	default:
		if buf := v.editBuf(); buf != nil && len(mm.Runes) > 0 {
			buf.WriteString(string(mm.Runes))
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
		v.mode, v.err, v.pending = grantModeRun, "", "remove"
		return v, v.doRemove()
	case "n", "N", "esc":
		v.mode = v.from
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
	// Grant-level protection rides the CLI's tri-state --protected; only
	// lock-flips feed a passphrase.
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

var grantListKeys = keyMap{
	short: []key.Binding{keyOpen, keyBack},
	full: [][]key.Binding{
		{keyMove, hint("enter", "open grant"), hint("e", "edit"), hint("r", "remove")},
		{keyBack, keyQuit},
	},
	notes: []string{"Projects and tags group grants; they are not permissions."},
}

var grantDetailKeys = keyMap{
	short: []key.Binding{hint("enter", "run"), hint("e", "edit"), keyBack},
	full: [][]key.Binding{
		{keyMove, hint("enter", "run action"), hint("e", "edit"), hint("r", "remove")},
		{keyBack, keyQuit},
	},
	notes: []string{"Projects and tags group grants; they are not permissions."},
}

func (v *grantListView) View() string {
	width, height := v.width, v.height
	if width == 0 || height == 0 {
		width, height = 80, 24
	}
	switch {
	case !v.loaded:
		return frame(width, height, "Grants", nil, "", []string{mutedSt.Render("  loading…")}, "", "")
	case v.loadErr != "":
		return frame(width, height, "Grants", nil, "", []string{v.loadErr}, "", footer(width, keyBack))
	}
	id := v.selectedID()
	g := v.items[id]
	switch v.mode {
	case grantModeDetail:
		return v.viewDetail(width, height)
	case grantModeConfirm:
		body := strings.Split(kv([2]string{"integration", g.Integration}, [2]string{"credential", g.Token}), "\n")
		body = append(body, mutedSt.Render("  Bearers holding it fail on their next exec."))
		return frame(width, height, "Remove "+id+"?", nil, "", body, "", confirmFoot("remove"))
	case grantModeRun:
		verb := "Removing %s…"
		if v.pending == "edit" {
			verb = "Saving %s…"
		}
		return frame(width, height, fmt.Sprintf(verb, id), nil, "", nil, "", "")
	case grantModeDone:
		title := map[string]string{"remove": "✓ Grant removed", "edit": "✓ Grant saved"}[v.pending]
		body := append(strings.Split(kv([2]string{"grant", id}), "\n"), mutedSt.Render("  The vault is synced with the team."))
		return frame(width, height, title, nil, "", body, "", footer(width, hint("enter", "done")))
	case grantModeEdit:
		return v.viewEdit(width, height)
	}

	km := grantListKeys
	st := status{err: v.err, flash: v.flash}
	var body []string
	if len(v.ids) == 0 {
		body = []string{bodySt.Render("  No grants yet. Add one from the menu: Add › Grant.")}
		km.short = km.short[1:]
	} else {
		rows := frameRows(height)
		if v.help {
			rows -= len(km.helpLines(width)) + 1
		}
		body = nameListBody(&v.list, "integration", v.cursor, width, rows)
		st.setHint(grantHint(id, g))
	}
	body = km.overlay(body, width, frameRows(height), v.help)
	return frame(width, height, "Grants", nil, fmt.Sprintf("%d total", len(v.ids)), body, st.String(), km.footerLine(width, v.help))
}

// viewDetail is the grant detail with its actions merged in.
func (v *grantListView) viewDetail(width, height int) string {
	id := v.selectedID()
	g := v.items[id]
	none := mutedSt.Render("none")
	or := func(s string) string {
		if s == "" {
			return none
		}
		return s
	}
	prefix := g.EffectivePrefix()
	if g.EnvPrefix == "" {
		prefix += mutedSt.Render("  default")
	}
	title := ansi.Truncate(id, max(width-13, 12), "…")
	var rows [][2]string
	if title != id {
		rows = append(rows, [2]string{"name", id}) // the title is truncated
	}
	body := strings.Split(kv(append(rows,
		[2]string{"integration", g.Integration}, [2]string{"credential", g.Token},
		[2]string{"env prefix", prefix}, [2]string{"projects", or(strings.Join(g.Projects, ", "))},
		[2]string{"tags", or(strings.Join(g.Tags, ", "))}, [2]string{"protection", protectWord(g.Protected)},
	)...), "\n")
	st := status{err: v.err, flash: v.flash}
	body = append(body, actionRows(grantActions, v.actionCursor, &st)...)
	ctx := ""
	if g.Protected {
		ctx = "protected"
	}
	km := grantDetailKeys
	body = km.overlay(body, width, frameRows(height), v.help)
	return frame(width, height, title, nil, ctx, body, st.String(), km.footerLine(width, v.help))
}

// viewEdit is the grant edit form: one row per field, › and the caret
// on the focused one; the protection picker opens in place.
func (v *grantListView) viewEdit(width, height int) string {
	f := v.editField
	body := []string{
		formRow(f == grantEditFieldProjects, "projects", v.editProject.String(), ""),
		formRow(f == grantEditFieldTags, "tags", v.editTags.String(), ""),
		formRow(f == grantEditFieldEnvPrefix, "env prefix", v.editPrefix.String(), ""),
	}
	switch f {
	case grantEditFieldProjects, grantEditFieldTags:
		body = append(body, mutedSt.Render("  Comma-separated."))
	case grantEditFieldEnvPrefix:
		body = append(body, mutedSt.Render("  Blank keeps the default, "+v.items[v.selectedID()].EffectivePrefix()+"."))
	}
	if f == grantEditFieldProtection {
		body = append(body, pickRows("protection", protectOpts(), v.editProtectCursor)...)
	} else {
		body = append(body, formRow(false, "protection", protectWord(v.editProtectChoice), ""))
	}
	needsPass := v.editProtectChoice && !v.editProtectWas
	if needsPass {
		body = append(body, formRow(f == grantEditFieldPassphrase, "approval passphrase", strings.Repeat("•", v.editPassBuf.Len()), ""))
	}
	verb := "next"
	if f == grantEditFieldPassphrase || (f == grantEditFieldProtection && !needsPass) {
		verb = "save"
	}
	foot := footer(width, hint("enter", verb), hint("tab", "field"), keyBack)
	return frame(width, height, "Edit "+v.selectedID(), nil, "", body, status{err: v.err}.String(), foot)
}

// ---------- Grant remove ----------

type grantRemoveView struct {
	wiz
	client *admin.Client
	paths  *config.Paths

	step   int // 0 = pick, 1 = confirm, 2 = running, 3 = done
	loaded bool
	err    string
	ids    []string
	grants map[string]vault.Grant
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
	if ok, cmd := v.wizMsg(msg, false); ok {
		return v, cmd
	}
	switch mm := msg.(type) {
	case grantListLoadedMsg:
		v.loaded = true
		v.err = mm.err
		v.grants = mm.items
		for id := range mm.items {
			v.ids = append(v.ids, id)
		}
		sort.Strings(v.ids)
	case grantRemoveResultMsg:
		if mm.err != "" {
			v.err = "Remove failed: " + firstLine(mm.err)
			v.step = 1
			return v, nil
		}
		v.flash = "Grant removed"
		v.step = 3
	case tea.KeyMsg:
		k := mm.String()
		switch {
		case k == "ctrl+c", v.step == 3:
			v.done = true
			return v, nil
		case !v.loaded, v.step == 2:
			return v, nil
		case k == "esc" && v.step == 1:
			v.step, v.err = 0, ""
			return v, nil
		case k == "esc":
			v.done = true
			return v, nil
		}
		switch v.step {
		case 0:
			switch k {
			case "up", "k":
				stepCursor(&v.cursor, len(v.ids), -1)
			case "down", "j":
				stepCursor(&v.cursor, len(v.ids), 1)
			case "enter":
				if len(v.ids) > 0 {
					v.step = 1
				}
			}
		case 1:
			switch k {
			case "y", "Y", "enter":
				v.step = 2
				return v, tea.Batch(v.spinStart(), v.doRemove())
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
	const title = "Remove grant"
	switch {
	case !v.loaded:
		return v.notice(title, "  loading…")
	case v.err != "" && len(v.ids) == 0:
		return v.notice(title, v.err)
	case len(v.ids) == 0:
		return v.notice(title, mutedSt.Render("  No grants yet. Add one from the menu: Add › Grant."))
	}
	id := v.ids[v.cursor]
	g := v.grants[id]
	switch v.step {
	case 0:
		var opts [][2]string
		for _, id := range v.ids {
			opts = append(opts, [2]string{ansi.Truncate(id, 40, "…"), v.grants[id].Integration})
		}
		hintTxt := ""
		if lipgloss.Width(id) > 40 {
			hintTxt = id
		}
		return v.pick(title, fmt.Sprintf("%d total", len(v.ids)), opts, v.cursor, hintTxt, "", pickKeys("remove"))
	case 1:
		body := strings.Split(strings.TrimRight(kv([2]string{"grant", midTrunc(id, 60)},
			[2]string{"integration", g.Integration}, [2]string{"credential", g.Token}), "\n"), "\n")
		return v.confirmScreen("Remove this grant?", body, "remove", v.err)
	case 2:
		return v.running(title, "Removing "+midTrunc(id, 50))
	}
	return v.doneScreen("Grant removed", [][2]string{{"grant", midTrunc(id, 60)}}, "The vault is synced with the team.", "")
}
