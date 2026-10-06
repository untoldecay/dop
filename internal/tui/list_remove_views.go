// Integration + grant list/remove TUI views (Batch 3).

package tui

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
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
	integModeIntReview          = 10
	integModeTokenRename        = 11
)

type integrationListView struct {
	sessionGuard
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

	// Integration edit: a dense form (Normal / Advanced tabs), then a
	// review of the changed rows.
	ieForm                                                      denseForm
	ieName, ieDesc, ieURL, ieKind, ieScan, ieProj, ieTags, iePr *formField
	iePass                                                      *formField
	ieAdv                                                       []*formField
	ieAdvTab                                                    bool
	ieWas                                                       map[*formField]string
	ieNameWas                                                   string
	ieProtectWas                                                bool

	renameIn, renamePass textinput.Model // credential rename step
	renameAt             int             // 1: the passphrase input has the caret
}

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
	{label: "Rename", key: "n", desc: "a new name; the grants that use it follow"},
	{label: "Remove credential", key: "x", desc: "removes it and the grants that use it"},
}

func (v *integrationListView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if ok, cmd := v.unlocked(msg); ok {
		return v, cmd
	}
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
				"remove-cred": "Remove credential", "edit": "Save", "rename-cred": "Rename"}[v.pending] + " failed: " + cliErr(mm.err)
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
			if v.pending == "edit" {
				v.tab = 0
			}
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
		case integModeIntEdit, integModeIntReview:
			if !v.ieForm.typing() && toggleHelp(&v.help, mm) {
				return v, nil
			}
			return v.updateIntEdit(mm)
		case integModeTokenRename:
			return v.updateTokenRename(mm)
		}
	}
	return v, nil
}

// startRun puts pending in flight; a failure returns to back.
// startRun runs an action's CLI call; enter is replayed after an unlock.
func (v *integrationListView) startRun(pending string, back int, cmd tea.Cmd) (tea.Model, tea.Cmd) {
	if c := v.locked(tea.KeyMsg{Type: tea.KeyEnter}, &v.err); c != nil {
		return v, c
	}
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
	case "n":
		if v.tab == 1 && len(v.tokenNames) > 0 {
			return v.runTokenAction(listAction{key: "n"})
		}
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

// enterIntEdit builds the integration edit form from the selected
// integration and snapshots it for the review.
func (v *integrationListView) enterIntEdit() *integrationListView {
	name := v.selectedName()
	if name == "" {
		return v
	}
	it := v.items[name]
	v.ieName, v.ieDesc, v.ieURL, v.ieKind, v.ieScan, v.ieAdv = integRows()
	v.ieProj, v.ieTags = textRow("projects", "docs, wiki", false, false), textRow("tags", "ro, ci", false, false)
	v.iePr, v.iePass = pickRow("protection", protectOpts()), textRow("approval passphrase", "", true, true)
	kind := vault.IntegrationKindOf(it)
	for i, p := range kindPresets {
		if p.value == kind {
			v.ieKind.pick = i
		}
	}
	if it.Protected {
		v.iePr.pick = 1
	}
	v.ieName.in.SetValue(name)
	v.ieDesc.in.SetValue(it.Description)
	v.ieURL.in.SetValue(slotValue(kind, it.Metadata))
	v.ieProj.in.SetValue(strings.Join(it.Projects, ","))
	v.ieTags.in.SetValue(strings.Join(it.Tags, ","))
	for i, a := range advFieldSpecs {
		v.ieAdv[i].in.SetValue(it.Metadata[a.metaKey])
	}
	v.ieNameWas, v.ieProtectWas, v.ieAdvTab, v.ieForm = name, it.Protected, false, denseForm{}
	v.ieWas = snap(append(v.ieAdv, v.ieName, v.ieDesc, v.ieURL, v.ieKind, v.ieScan, v.ieProj, v.ieTags, v.iePr))
	v.err, v.mode = "", integModeIntEdit
	return v
}

func (v *integrationListView) ieKindVal() string { return kindPresets[v.ieKind.pick].value }

// ieRows are the edit form's rows on the current tab (adv) for the
// picked kind; the passphrase only when switching to protected.
func (v *integrationListView) ieRows(adv bool) []*formField {
	if adv {
		return advRows(v.ieAdv, v.ieKindVal())
	}
	r := append([]*formField{v.ieName, v.ieKind, v.ieDesc}, slotRows(v.ieKindVal(), v.ieURL, v.ieScan)...)
	r = append(r, v.ieProj, v.ieTags, v.iePr)
	if v.iePr.pick == 1 && !v.ieProtectWas {
		r = append(r, v.iePass)
	}
	return r
}

// ieChanges are the review rows: every changed row on both tabs.
func (v *integrationListView) ieChanges() [][2]string {
	var rows []*formField
	for _, f := range append(v.ieRows(false), v.ieRows(true)...) {
		if f != v.iePass {
			rows = append(rows, f)
		}
	}
	return changes(rows, v.ieWas)
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
	case integModeIntEdit, integModeIntReview:
		return v.viewIntEdit(width, height)
	case integModeTokenRename:
		return v.viewTokenRename(width, height)
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
		{hint("e", "edit"), hint("r", "remove"), hint("a", "add credential / grant"), hint("n", "rename credential"), keyBack, keyQuit},
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
		"rotate": "Rotating %s…", "remove-cred": "Removing %s…"}[v.pending]
	if v.pending == "remove" {
		what = v.selectedName()
	}
	title := fmt.Sprintf(verb, what)
	switch v.pending {
	case "edit":
		title = "Saving integration…"
	case "rename-cred":
		title = "Renaming credential…"
	}
	return frame(width, height, title, nil, "", nil, "", "")
}

// viewDone is the ✓ outcome of an integration action; any key returns.
func (v *integrationListView) viewDone(width, height int) string {
	title := map[string]string{"remove": "✓ Integration removed", "scope": "✓ Scope note saved",
		"rotate": "✓ Credential rotated", "remove-cred": "✓ Credential removed", "edit": "✓ Integration saved",
		"rename-cred": "✓ Credential renamed"}[v.pending]
	rows := [][2]string{{"integration", v.keep}}
	switch v.pending {
	case "scope":
		rows = append(rows, [2]string{"credential", v.selectedTokenName()}, [2]string{"scope note", v.tokenEditBuf.String()})
	case "rotate", "remove-cred":
		rows = append(rows, [2]string{"credential", v.selectedTokenName()})
	case "rename-cred":
		rows = append(rows, [2]string{"credential", strings.TrimSpace(v.renameIn.Value())}, [2]string{"was", v.selectedTokenName()})
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
				if cmd := v.locked(mm, &v.err); cmd != nil {
					return v, cmd
				}
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
	case "n":
		return v.runTokenAction(listAction{key: "n"})
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
	case "n":
		v.renameIn, v.renamePass, v.renameAt = newFormInput(false), newFormInput(true), 0
		v.renameIn.SetValue(tokenName)
		v.renameIn.CursorEnd()
		v.err, v.mode = "", integModeTokenRename
	}
	return v, nil
}

// updateTokenRename is the rename step: enter saves; a protected
// integration asks its approval passphrase on the same screen first.
func (v *integrationListView) updateTokenRename(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	v.err = ""
	integ, from := v.selectedName(), v.selectedTokenName()
	to := strings.TrimSpace(v.renameIn.Value())
	switch mm.String() {
	case "esc":
		if v.renameAt == 1 {
			v.renameAt = 0
			return v, nil
		}
		v.mode = integModeTokenAction
	case "enter":
		_, taken := v.items[integ].Tokens[to]
		switch {
		case to == "":
			v.err = "Enter a name."
		case to == from:
			v.err = "That is its current name."
		case taken:
			v.err = integ + " already has a credential " + to
		case v.items[integ].Protected && v.renameAt == 0:
			v.renameAt = 1
		case v.items[integ].Protected && v.renamePass.Value() == "":
			v.err = "Enter the approval passphrase."
		default:
			args, pass := []string{"integration", "rename-token", "--integration", integ, "--from", from, "--to", to}, ""
			if v.items[integ].Protected {
				args, pass = append(args, "--passphrase-stdin"), v.renamePass.Value()
			}
			return v.startRun("rename-cred", integModeTokenRename, func() tea.Msg {
				_, err := runDop(pass, args...)
				return integActionMsg{err: err}
			})
		}
	default:
		if v.renameAt == 1 {
			edit(&v.renamePass, mm)
		} else {
			edit(&v.renameIn, mm)
		}
	}
	return v, nil
}

func (v *integrationListView) viewTokenRename(width, height int) string {
	w := wiz{width: width, height: height}
	in := []string{inputRow(&v.renameIn)}
	if v.renameAt == 1 {
		v.renameIn.Blur()
		in = []string{"  " + v.renameIn.View(), "", mutedSt.Render("Approval passphrase"), inputRow(&v.renamePass)}
	}
	return w.screen("Rename credential", v.selectedName(), "New name for "+v.selectedTokenName(), in,
		"The grants that use it follow the new name.", v.err, "", keyMap{short: []key.Binding{hint("enter", "save"), keyBack}})
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

// updateIntEdit: the dense form (tab flips Normal / Advanced), then the
// review; enter there saves, or closes when nothing changed.
func (v *integrationListView) updateIntEdit(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	k := mm.String()
	if v.mode == integModeIntReview {
		switch k {
		case "enter":
			if len(v.ieChanges()) == 0 {
				v.mode, v.tab = integModeDetail, 0
				return v, nil
			}
			v.keep = vault.NormalizeIntegrationName(v.ieName.val()) // cursor follows a rename
			return v.startRun("edit", integModeIntReview, v.doIntEdit())
		case "esc", "shift+tab":
			v.mode, v.err = integModeIntEdit, ""
		}
		return v, nil
	}
	v.err = ""
	f := &v.ieForm
	if f.open == 0 && (k == "tab" || k == "shift+tab") {
		v.ieAdvTab, f.cur = !v.ieAdvTab, 0
		return v, nil
	}
	kindWas := v.ieKind.pick
	r := f.key(v.ieRows(v.ieAdvTab), mm)
	if v.ieKind.pick != kindWas {
		v.ieURL.in.SetValue("") // a base URL is never sent as --cmd
	}
	switch r {
	case formBack:
		v.mode = v.from
	case formNext:
		v.ieAdvTab = false
		if v.err = f.missing(v.ieRows(false)); v.err == "" {
			v.mode = integModeIntReview
		}
	}
	return v, nil
}

// doIntEdit renames first when the name changed (its own subcommand,
// audit event and grant rewrite), then `integration add` with every
// row. The CLI merges and keeps metadata it is not given, so an
// Advanced row goes only when changed (cleared: an empty metadata key).
func (v *integrationListView) doIntEdit() tea.Cmd {
	from, to := v.ieNameWas, v.ieName.val()
	kind := v.ieKindVal()
	args := []string{"integration", "add", "--name", to, "--kind", kind}
	if d := v.ieDesc.val(); d != "" {
		args = append(args, "--description", d)
	}
	args = append(args, slotArgs(kind, v.ieURL.val())...)
	if v.ieScan.pick == 1 && (kind == vault.IntegrationKindAPI || kind == vault.IntegrationKindMCP) {
		args = append(args, "--probe-endpoints")
	}
	// Always pass projects + tags (empty clears, nonempty replaces).
	args = append(args, "--projects", v.ieProj.val(), "--tags", v.ieTags.val())
	for _, i := range advFieldsForKind(kind) {
		if f := v.ieAdv[i]; f.val() != v.ieWas[f] {
			if f.val() == "" {
				args = append(args, "--metadata", advFieldSpecs[i].metaKey+"=")
			} else {
				args = append(args, advFieldSpecs[i].cliFlag, f.val())
			}
		}
	}
	protect, pass := v.iePr.pick == 1, ""
	switch {
	case protect && !v.ieProtectWas:
		args, pass = append(args, "--protected", "--passphrase-stdin"), v.iePass.in.Value()
	case !protect && v.ieProtectWas:
		args = append(args, "--protected=false")
	}
	return func() tea.Msg {
		if to != from {
			if _, err := runDop("", "integration", "rename", "--from", from, "--to", to); err != "" {
				return integActionMsg{err: err}
			}
		}
		_, err := runDop(pass, args...)
		return integActionMsg{err: err}
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

// viewIntEdit is the integration edit form: dense rows, tabs Normal /
// Advanced on the title row, the review after it.
func (v *integrationListView) viewIntEdit(width, height int) string {
	title := "Edit " + ansi.Truncate(v.ieNameWas, max(width-40, 12), "…")
	w := wiz{width: width, height: height, help: v.help}
	if v.mode == integModeIntReview {
		if ch := v.ieChanges(); len(ch) > 0 {
			return w.review(title, "Save "+v.ieName.val()+"?", ch, "save", false, v.err)
		}
		return w.review(title, "No changes.", nil, "close", false, v.err)
	}
	rows, f := v.ieRows(v.ieAdvTab), &v.ieForm
	tabs := []tab{{"Normal", -1, !v.ieAdvTab}, {"Advanced", -1, v.ieAdvTab}}
	km := f.formKeys(rows, "Review", hint("tab", map[bool]string{true: "normal", false: "advanced"}[v.ieAdvTab]))
	hintTxt := ""
	switch {
	case v.ieAdvTab:
		hintTxt = "Optional, stored on the integration."
	case f.cur < len(rows) && rows[f.cur] == v.ieName:
		hintTxt = "Renaming also renames the grants that use it."
	case f.cur < len(rows) && (rows[f.cur] == v.ieProj || rows[f.cur] == v.ieTags):
		hintTxt = "Comma-separated."
	}
	body := km.overlay(f.view(rows, width, "Review"), width, frameRows(height), v.help)
	return frame(width, height, title, tabs, "", body, status{err: v.err, hint: hintTxt}.String(), km.footerLine(width, v.help))
}

// ---------- Grant list ----------

const (
	grantModeList    = 0
	grantModeDetail  = 1 // detail + actions
	grantModeConfirm = 2
	grantModeRun     = 3
	grantModeDone    = 4
	grantModeEdit    = 5
	grantModeReview  = 6
	grantModeRename  = 7
)

type grantListView struct {
	sessionGuard
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

	// edit: a dense form, then a review of the changed rows.
	editForm                            denseForm
	edProj, edTags, edEnv, edPr, edPass *formField
	edWas                               map[*formField]string

	// rename: one input; a protected grant asks the passphrase after it.
	renameIn, renamePass textinput.Model
	renameAt             int    // 1: the passphrase input has the caret
	keep                 string // id the cursor lands on after the next load
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
	{label: "Rename", key: "n", desc: "bearers carrying it follow"},
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
	if ok, cmd := v.unlocked(msg); ok {
		return v, cmd
	}
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
		if i := slices.Index(v.ids, v.keep); i >= 0 {
			v.cursor = i
		}
		v.keep = ""
		v.cursor = max(min(v.cursor, len(v.ids)-1), 0)
		items := make([]list.Item, len(v.ids))
		for i, id := range v.ids {
			items[i] = nameItem{id, v.items[id].Integration}
		}
		v.list.SetItems(items)
	case grantActionMsg:
		if mm.err != "" {
			// Errors stay on the screen that caused them, in plain words.
			switch mm.kind {
			case "edit":
				v.err, v.mode = "Save failed: "+cliErr(mm.err), grantModeReview
			case "rename":
				v.err, v.mode = "Rename failed: "+cliErr(mm.err), grantModeRename
			default:
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
		case grantModeRename:
			return v.updateRename(mm)
		case grantModeEdit, grantModeReview:
			if !v.editForm.typing() && toggleHelp(&v.help, mm) {
				return v, nil
			}
			return v.updateEdit(mm)
		case grantModeDone:
			if mm.String() != "enter" {
				return v, nil // done screens leave on enter only
			}
			v.done, v.mode = v.solo, grantModeList
			switch v.pending {
			case "edit":
				v.done, v.mode = false, grantModeDetail
			case "rename":
				v.keep = strings.TrimSpace(v.renameIn.Value())
			}
			v.pending = ""
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
	case "e", "n", "r":
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
	case "e", "n", "r":
		return v.runAction(k)
	}
	return v, nil
}

// runAction: e opens the edit form, n the rename, r the remove confirm.
func (v *grantListView) runAction(k string) (tea.Model, tea.Cmd) {
	v.from, v.help = v.mode, false
	switch k {
	case "e":
		v.openEditor()
	case "n":
		v.renameIn, v.renamePass, v.renameAt = newFormInput(false), newFormInput(true), 0
		v.renameIn.SetValue(v.selectedID())
		v.renameIn.CursorEnd()
		v.err, v.mode = "", grantModeRename
	default:
		v.mode = grantModeConfirm
	}
	return v, nil
}

// updateRename is the rename step: enter saves; a protected grant asks
// its approval passphrase on the same screen first.
func (v *grantListView) updateRename(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	v.err = ""
	from, to := v.selectedID(), strings.TrimSpace(v.renameIn.Value())
	prot := v.items[from].Protected
	switch mm.String() {
	case "esc":
		if v.renameAt == 1 {
			v.renameAt = 0
			return v, nil
		}
		v.mode = v.from
	case "enter":
		_, taken := v.items[to]
		switch {
		case to == "":
			v.err = "Enter a name."
		case to == from:
			v.err = "That is its current name."
		case taken:
			v.err = "A grant named " + to + " already exists."
		case prot && v.renameAt == 0:
			v.renameAt = 1
		case prot && v.renamePass.Value() == "":
			v.err = "Enter the approval passphrase."
		default:
			if cmd := v.locked(mm, &v.err); cmd != nil {
				return v, cmd
			}
			args, pass := []string{"grant", "rename", "--from", from, "--to", to}, ""
			if prot {
				args, pass = append(args, "--passphrase-stdin"), v.renamePass.Value()
			}
			v.mode, v.pending = grantModeRun, "rename"
			return v, func() tea.Msg {
				_, err := runDop(pass, args...)
				return grantActionMsg{kind: "rename", err: err}
			}
		}
	default:
		if v.renameAt == 1 {
			edit(&v.renamePass, mm)
		} else {
			edit(&v.renameIn, mm)
		}
	}
	return v, nil
}

func (v *grantListView) viewRename(width, height int) string {
	w := wiz{width: width, height: height}
	in := []string{inputRow(&v.renameIn)}
	if v.renameAt == 1 {
		v.renameIn.Blur()
		in = []string{"  " + v.renameIn.View(), "", mutedSt.Render("Approval passphrase"), inputRow(&v.renamePass)}
	}
	return w.screen("Rename grant", "", "New id for "+v.selectedID(), in,
		"Bearers carrying it follow the new id.", v.err, "", keyMap{short: []key.Binding{hint("enter", "save"), keyBack}})
}

func (v *grantListView) openEditor() {
	g := v.items[v.selectedID()]
	v.edProj, v.edTags = textRow("projects", "docs, wiki", false, false), textRow("tags", "ro, ci", false, false)
	v.edEnv, v.edPr = textRow("env prefix", g.EffectivePrefix(), false, false), pickRow("protection", protectOpts())
	v.edPass = textRow("approval passphrase", "", true, true)
	v.edProj.in.SetValue(strings.Join(g.Projects, ","))
	v.edTags.in.SetValue(strings.Join(g.Tags, ","))
	v.edEnv.in.SetValue(g.EnvPrefix)
	if g.Protected {
		v.edPr.pick = 1
	}
	v.editForm, v.edWas = denseForm{}, snap([]*formField{v.edProj, v.edTags, v.edEnv, v.edPr})
	v.mode, v.err = grantModeEdit, ""
}

// editRows: the passphrase only when switching to protected.
func (v *grantListView) editRows() []*formField {
	r := []*formField{v.edProj, v.edTags, v.edEnv, v.edPr}
	if v.edPr.pick == 1 && !v.items[v.selectedID()].Protected {
		r = append(r, v.edPass)
	}
	return r
}

func (v *grantListView) editChanges() [][2]string {
	return changes(v.editRows()[:4], v.edWas)
}

// updateEdit: the dense form, then the review; enter there saves, or
// closes when nothing changed.
func (v *grantListView) updateEdit(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	if v.mode == grantModeReview {
		switch mm.String() {
		case "enter":
			if len(v.editChanges()) == 0 {
				v.mode = grantModeDetail
				return v, nil
			}
			if cmd := v.locked(mm, &v.err); cmd != nil {
				return v, cmd
			}
			v.mode, v.help, v.pending, v.err = grantModeRun, false, "edit", ""
			return v, v.doEdit()
		case "esc", "shift+tab":
			v.mode, v.err = grantModeEdit, ""
		}
		return v, nil
	}
	v.err = ""
	switch v.editForm.key(v.editRows(), mm) {
	case formBack:
		v.mode = v.from
	case formNext:
		if v.err = v.editForm.missing(v.editRows()); v.err == "" {
			v.mode = grantModeReview
		}
	}
	return v, nil
}

func (v *grantListView) updateConfirm(mm tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch mm.String() {
	case "y", "Y", "enter":
		if cmd := v.locked(mm, &v.err); cmd != nil {
			return v, cmd
		}
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
	// `dop grant add` is upsert: the same id + integration + credential
	// with new fields overwrites the record in place.
	args := []string{"grant", "add", "--id", id, "--integration", g.Integration, "--token", g.Token,
		"--projects", v.edProj.val(), "--tags", v.edTags.val()}
	if p := v.edEnv.val(); p != "" {
		args = append(args, "--env-prefix", p)
	}
	// Grant-level protection rides the CLI's tri-state --protected; only
	// a switch to protected feeds a passphrase.
	protect, pass := v.edPr.pick == 1, ""
	switch {
	case protect && !g.Protected:
		args, pass = append(args, "--protected", "--passphrase-stdin"), v.edPass.in.Value()
	case !protect && g.Protected:
		args = append(args, "--protected=false")
	}
	return func() tea.Msg {
		_, err := runDop(pass, args...)
		return grantActionMsg{kind: "edit", err: err}
	}
}

var grantListKeys = keyMap{
	short: []key.Binding{keyOpen, keyBack},
	full: [][]key.Binding{
		{keyMove, hint("enter", "open grant"), hint("e", "edit"), hint("n", "rename"), hint("r", "remove")},
		{keyBack, keyQuit},
	},
	notes: []string{"Projects and tags group grants; they are not permissions."},
}

var grantDetailKeys = keyMap{
	short: []key.Binding{hint("enter", "run"), hint("e", "edit"), keyBack},
	full: [][]key.Binding{
		{keyMove, hint("enter", "run action"), hint("e", "edit"), hint("n", "rename"), hint("r", "remove")},
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
		title := map[string]string{"edit": "Saving grant…", "rename": "Renaming grant…"}[v.pending]
		if title == "" {
			title = "Removing " + id + "…"
		}
		return frame(width, height, title, nil, "", nil, "", "")
	case grantModeDone:
		title := map[string]string{"remove": "✓ Grant removed", "edit": "✓ Grant saved", "rename": "✓ Grant renamed"}[v.pending]
		rows := [][2]string{{"grant", id}}
		if v.pending == "rename" {
			rows = [][2]string{{"grant", strings.TrimSpace(v.renameIn.Value())}, {"was", id}}
		}
		body := append(strings.Split(kv(rows...), "\n"), mutedSt.Render("  The vault is synced with the team."))
		return frame(width, height, title, nil, "", body, "", footer(width, hint("enter", "done")))
	case grantModeEdit, grantModeReview:
		return v.viewEdit(width, height)
	case grantModeRename:
		return v.viewRename(width, height)
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

// viewEdit is the grant edit form (dense rows), then its review.
func (v *grantListView) viewEdit(width, height int) string {
	title := "Edit " + ansi.Truncate(v.selectedID(), max(width-20, 12), "…")
	if v.mode == grantModeReview {
		w := wiz{width: width, height: height, help: v.help}
		if ch := v.editChanges(); len(ch) > 0 {
			return w.review(title, "Save "+v.selectedID()+"?", ch, "save", false, v.err)
		}
		return w.review(title, "No changes.", nil, "close", false, v.err)
	}
	rows, f := v.editRows(), &v.editForm
	hintTxt := ""
	if f.cur < len(rows) {
		switch rows[f.cur] {
		case v.edProj, v.edTags:
			hintTxt = "Comma-separated."
		case v.edEnv:
			hintTxt = "Blank keeps the default, " + v.edEnv.in.Placeholder + "."
		}
	}
	km := f.formKeys(rows, "Review")
	body := km.overlay(f.view(rows, width, "Review"), width, frameRows(height), v.help)
	return frame(width, height, title, nil, "", body, status{err: v.err, hint: hintTxt}.String(), km.footerLine(width, v.help))
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
				if cmd := v.locked(mm, &v.err); cmd != nil {
					return v, cmd
				}
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
