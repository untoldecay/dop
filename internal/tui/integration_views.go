// Add-integration and add-grant TUI flows: dense forms (detail_helpers
// denseForm), a review, running and done screen.

package tui

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/cursor"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

// ---------- grant form (Add integration step 3, Add grant) ----------

// grantForm is the grant's dense form: id, integration, credential,
// env prefix, projects, tags. The id and env prefix follow the
// integration / credential until the operator edits them.
type grantForm struct {
	id, integ, cred, env, projects, tags *formField
	sugID, sugEnv                        string // last suggestions, to tell an edit from a default
	vlt                                  *vault.Vault
}

func newGrantForm(vlt *vault.Vault, fixedInteg bool) grantForm {
	g := grantForm{vlt: vlt,
		id: textRow("grant", "notion.read-only", true, false), env: textRow("env prefix", "", true, false),
		projects: textRow("projects", "docs, wiki", false, false), tags: textRow("tags", "ro, ci", false, false)}
	if fixedInteg {
		g.integ, g.cred = fixedRow("integration", ""), fixedRow("credential", "")
	} else {
		var o [][2]string
		for _, n := range sortedKeys(vlt.Integrations) {
			o = append(o, [2]string{n, ""})
		}
		g.integ, g.cred = pickRow("integration", o), pickRow("credential", nil)
		g.integ.req, g.cred.req = true, true
	}
	return g
}

func sortedKeys[T any](m map[string]T) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (g *grantForm) rows() []*formField {
	return []*formField{g.id, g.integ, g.cred, g.env, g.projects, g.tags}
}

// sync refreshes the credential choices of a picked integration and the
// suggested id / env prefix. scope is the credential's scope note.
// The id is <integration>.<scope> for read-only / read-write / admin,
// else <integration>, with -2, -3… when taken; the env prefix is what
// `dop grant add` derives when none is given: <INTEGRATION>_<CREDENTIAL>,
// sanitized (Grant.EffectivePrefix).
func (g *grantForm) sync(scope string) {
	integ := g.integ.val()
	if g.cred.opts != nil || !g.cred.fixed {
		var o [][2]string
		if it, ok := g.vlt.Integrations[integ]; ok {
			for _, t := range sortedKeys(it.Tokens) {
				o = append(o, [2]string{t, it.Tokens[t].ScopeNote})
			}
		}
		g.cred.opts, g.cred.pick = o, min(g.cred.pick, max(len(o)-1, 0))
		if len(o) == 0 {
			g.cred.opts = nil
		}
		if it, ok := g.vlt.Integrations[integ]; ok && g.cred.val() != "" {
			scope = it.Tokens[g.cred.val()].ScopeNote
		}
	}
	if integ == "" {
		return
	}
	base := integ
	switch scope {
	case "read-only", "read-write", "admin":
		base += "." + scope
	}
	id := base
	for n := 2; g.vlt.Grants[id].Integration != ""; n++ {
		id = fmt.Sprintf("%s-%d", base, n)
	}
	if v := g.id.val(); v == "" || v == g.sugID {
		g.id.in.SetValue(id)
	}
	env := vault.SanitizeEnvKey(integ + "_" + g.cred.val())
	if v := g.env.val(); v == "" || v == g.sugEnv {
		g.env.in.SetValue(env)
	}
	g.sugID, g.sugEnv = id, env
}

// check is the grant's validation error, "" when it can be saved.
func (g *grantForm) check(d *denseForm) string {
	if e := d.missing(g.rows()); e != "" {
		return e
	}
	if g.vlt.Grants[g.id.val()].Integration != "" {
		d.cur = 0
		return "Grant " + g.id.val() + " already exists"
	}
	return ""
}

func (g *grantForm) args() []string {
	args := []string{"grant", "add", "--id", g.id.val(), "--integration", g.integ.val(), "--token", g.cred.val()}
	// Leave env_prefix empty on the record when it is the default, the
	// way `dop grant add` does.
	if env := g.env.val(); env != vault.SanitizeEnvKey(g.integ.val()+"_"+g.cred.val()) {
		args = append(args, "--env-prefix", env)
	}
	if p := g.projects.val(); p != "" {
		args = append(args, "--projects", p)
	}
	if t := g.tags.val(); t != "" {
		args = append(args, "--tags", t)
	}
	return args
}

func (g *grantForm) summary() [][2]string {
	return [][2]string{{"grant", g.id.val()}, {"env prefix", g.env.val()},
		{"projects", displayOr(g.projects.val(), "none")}, {"tags", displayOr(g.tags.val(), "none")}}
}

// runDop runs `dop args…` without a TUI, stdin as given; the error is
// the trimmed stderr.
func runDop(stdin string, args ...string) (string, string) {
	self, _ := os.Executable()
	cmd := exec.Command(self, args...)
	cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin + "\n")
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stderr.String(), displayOr(strings.TrimSpace(stderr.String()), err.Error())
	}
	return stderr.String(), ""
}

// ---------- Add integration ----------
//
// Three steps, Integration › Credential › Grant, after a first screen
// that picks a new or an existing integration. An existing integration
// (picked, or `a` on its Credentials tab) starts at the credential and
// is never mutated: its integration-level fields are not asked.

const (
	integStagePick   = -1
	integStageInteg  = 0
	integStageCred   = 1
	integStageGrant  = 2
	integStageReview = 3
	integStageRun    = 4
	integStageDone   = 5
)

type addIntegrationView struct {
	wiz
	client *admin.Client
	paths  *config.Paths
	vlt    *vault.Vault

	stage   int
	pickCur int
	form    [3]denseForm

	name, kind, desc, url, scan *formField
	cred, value, scope, protect *formField
	pass                        *formField
	adv                         []*formField // by advFieldSpecs index
	advTab                      bool
	grant                       grantForm

	existingIntegration bool
	fromTab             bool // opened on the Credentials tab: esc on the credential leaves
	credPrefilled       bool
	integSaved          bool   // the integration + credential call succeeded; a retry only adds the grant
	probeSummary        string // scan outcome from the CLI stderr
	saving              string // the running screen's line, per CLI call

	err   string
	flash string
	done  bool
}

type integrationAddedMsg struct {
	err          string
	integSaved   bool   // the integration + credential were saved (the grant call failed)
	probeSummary string // scan outcome, when asked for
}

func newAddIntegrationView(c *admin.Client, p *config.Paths) *addIntegrationView {
	vlt, _, err := loadVaultForListing(c, p)
	if err != nil || vlt == nil {
		vlt = &vault.Vault{}
	}
	v := &addIntegrationView{client: c, paths: p, vlt: vlt, stage: integStagePick}
	var scopes [][2]string
	for _, s := range scopePresets {
		scopes = append(scopes, [2]string{s.label, map[bool]string{true: "type your own"}[s.value == ""]})
	}
	v.name, v.desc, v.url, v.kind, v.scan, v.adv = integRows()
	v.cred, v.value = textRow("credential", "notion", true, false), textRow("value", "the API key or password", true, true)
	v.scope, v.protect = pickRow("scope note", scopes), pickRow("protection", protectOpts())
	v.scope.other = true
	v.scope.in.Placeholder = "read-only on /docs"
	v.pass = textRow("approval passphrase", "", true, true)
	v.grant = newGrantForm(vlt, true)
	return v
}

// newAddCredentialView is the flow on an existing integration, from its
// Credentials tab: it starts at the credential step.
func newAddCredentialView(c *admin.Client, p *config.Paths, svc string) *addIntegrationView {
	v := newAddIntegrationView(c, p)
	v.useExisting(svc)
	v.fromTab = true
	return v
}

// useExisting points the flow at the existing integration svc.
func (v *addIntegrationView) useExisting(svc string) {
	v.existingIntegration = true
	v.name.in.SetValue(svc)
	it := v.vlt.Integrations[svc]
	for i, k := range kindPresets {
		if k.value == vault.IntegrationKindOf(it) {
			v.kind.pick = i
		}
	}
	v.stage = integStageCred
	v.prefillCred()
}

func (v *addIntegrationView) Init() tea.Cmd { return nil }
func (v *addIntegrationView) Done() bool    { return v.done }
func (v *addIntegrationView) Flash() string { return v.flash }

func (v *addIntegrationView) kindVal() string { return kindPresets[v.kind.pick].value }

// integName is the integration key the CLI saves under.
func (v *addIntegrationView) integName() string {
	return vault.NormalizeIntegrationName(v.name.val())
}

// rows are the current step's form rows (they follow the answers).
func (v *addIntegrationView) rows() []*formField {
	switch v.stage {
	case integStageInteg:
		return append([]*formField{v.name, v.kind, v.desc}, slotRows(v.kindVal(), v.url, v.scan)...)
	case integStageCred:
		if v.advTab {
			return advRows(v.adv, v.kindVal())
		}
		r := []*formField{v.cred, v.value, v.scope}
		if !v.existingIntegration {
			r = append(r, v.protect)
			if v.protected() {
				r = append(r, v.pass)
			}
		}
		return r
	case integStageGrant:
		return v.grant.rows()
	}
	return nil
}

func (v *addIntegrationView) protected() bool {
	return !v.existingIntegration && protectionPresets[v.protect.pick].value
}

// prefillCred seeds the credential name with the integration's once.
func (v *addIntegrationView) prefillCred() {
	if !v.credPrefilled && v.cred.val() == "" {
		v.cred.in.SetValue(v.integName())
	}
	v.credPrefilled = true
}

// typing: an open text row holds text (? is a character there).
func (v *addIntegrationView) typing() bool {
	return v.stage >= 0 && v.stage < 3 && v.form[v.stage].typing()
}

func (v *addIntegrationView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if ok, cmd := v.wizMsg(msg, v.typing()); ok {
		return v, cmd
	}
	switch mm := msg.(type) {
	case integrationAddedMsg:
		v.integSaved = v.integSaved || mm.integSaved
		if mm.probeSummary != "" {
			v.probeSummary = mm.probeSummary
		}
		if mm.err != "" {
			v.err, v.stage = "Save failed: "+cliErr(firstLine(mm.err)), integStageReview
			if mm.integSaved {
				v.err = "Integration and credential saved; grant failed: " + cliErr(firstLine(mm.err))
			}
			return v, nil
		}
		if mm.integSaved { // first call done: now the grant
			v.saving = "Saving grant…"
			return v, v.save()
		}
		v.stage = integStageDone
	case tea.KeyMsg:
		k := mm.String()
		switch {
		case v.stage == integStageRun:
			return v, nil
		case v.stage == integStageDone:
			if k == "enter" {
				v.done, v.flash = true, "integration saved · synced with team"
			}
			return v, nil
		case k == "ctrl+c":
			v.done = true
			return v, nil
		}
		if k != "enter" {
			v.err = ""
		}
		switch v.stage {
		case integStagePick:
			return v.updatePick(k)
		case integStageReview:
			switch k {
			case "enter":
				if cmd := v.locked(mm, &v.err); cmd != nil {
					return v, cmd
				}
				v.stage, v.err = integStageRun, ""
				v.saving = map[bool]string{true: "Saving credential…", false: "Saving integration and credential…"}[v.existingIntegration]
				if v.integSaved {
					v.saving = "Saving grant…"
				}
				return v, tea.Batch(v.spinStart(), v.save())
			case "esc", "shift+tab":
				v.stage = integStageGrant
			}
			return v, nil
		}
		f := &v.form[v.stage]
		if v.stage == integStageCred && !v.existingIntegration && f.open == 0 && (k == "tab" || k == "shift+tab") {
			v.advTab, f.cur = !v.advTab, 0
			return v, nil
		}
		switch f.key(v.rows(), mm) {
		case formBack:
			v.back()
		case formNext:
			v.next()
		}
	}
	return v, nil
}

// pickOpts is the first screen: New integration, then each existing one.
func (v *addIntegrationView) pickOpts() [][2]string {
	o := [][2]string{{"New integration", "an API, CLI, MCP server or other service"}}
	for _, n := range sortedKeys(v.vlt.Integrations) {
		o = append(o, [2]string{ansi.Truncate(n, nameColW, "…"), v.vlt.Integrations[n].Description})
	}
	return o
}

func (v *addIntegrationView) updatePick(k string) (tea.Model, tea.Cmd) {
	o := v.pickOpts()
	switch k {
	case "up", "down":
		stepCursor(&v.pickCur, len(o), map[string]int{"up": -1, "down": 1}[k])
	case "esc":
		v.done = true
	case "enter":
		if v.pickCur == 0 {
			v.existingIntegration, v.stage = false, integStageInteg
			v.name.in.SetValue("")
			return v, nil
		}
		v.credPrefilled = false
		v.cred.in.SetValue("")
		v.useExisting(sortedKeys(v.vlt.Integrations)[v.pickCur-1])
	}
	return v, nil
}

// back is esc on a closed form: one step back, or out where the flow
// was entered from.
func (v *addIntegrationView) back() {
	switch {
	case v.stage == integStageGrant:
		v.stage = integStageCred
	case v.stage == integStageCred && v.existingIntegration && v.fromTab:
		v.done = true
	case v.stage == integStageCred && v.existingIntegration:
		v.stage = integStagePick
	case v.stage == integStageCred:
		v.stage = integStageInteg
	default:
		v.stage = integStagePick
	}
}

// next validates the current step and moves to the following one.
func (v *addIntegrationView) next() {
	f := &v.form[v.stage]
	switch v.stage {
	case integStageInteg:
		if v.err = f.missing(v.rows()); v.err != "" {
			return
		}
		if _, ok := v.vlt.FindIntegrationKey(v.integName()); ok {
			f.cur, v.err = 0, v.integName()+" already exists: pick it on the first screen to add a credential"
			return
		}
		v.prefillCred()
		v.stage = integStageCred
	case integStageCred:
		v.advTab = false
		if v.err = f.missing(v.rows()); v.err != "" {
			return
		}
		if _, ok := v.vlt.Integrations[v.integName()].Tokens[v.cred.val()]; ok {
			// integration add would overwrite it: a new credential needs a new name.
			f.cur, v.err = 0, v.integName()+" already has a credential "+v.cred.val()
			return
		}
		v.grant.integ.in.SetValue(v.integName())
		v.grant.cred.in.SetValue(v.cred.val())
		v.grant.sync(v.scope.val())
		v.stage = integStageGrant
	case integStageGrant:
		if v.err = v.grant.check(f); v.err != "" {
			return
		}
		v.stage = integStageReview
	}
}

// integArgs is the `dop integration add` call: integration and
// credential in one, the passphrase on stdin when protected.
func (v *addIntegrationView) integArgs() []string {
	args := []string{"integration", "add", "--name", v.integName()}
	if !v.existingIntegration {
		if d := v.desc.val(); d != "" {
			args = append(args, "--description", d)
		}
		args = append(append(args, "--kind", v.kindVal()), slotArgs(v.kindVal(), v.url.val())...)
		if (v.kindVal() == vault.IntegrationKindAPI || v.kindVal() == vault.IntegrationKindMCP) && v.scan.pick == 1 {
			args = append(args, "--probe-endpoints")
		}
		for _, i := range advFieldsForKind(v.kindVal()) {
			if val := v.adv[i].val(); val != "" {
				args = append(args, advFieldSpecs[i].cliFlag, val)
			}
		}
		if v.protected() {
			args = append(args, "--protected", "--passphrase-stdin")
		}
	}
	return append(args, "--token", fmt.Sprintf("%s=%s:%s", v.cred.val(), v.value.val(), displayOr(v.scope.val(), "-")))
}

// save is the next CLI call: integration add (integration and
// credential), then grant add once that is saved.
func (v *addIntegrationView) save() tea.Cmd {
	integArgs, grantArgs := v.integArgs(), v.grant.args()
	pass, scan := "", v.scan.pick == 1 && !v.existingIntegration
	if v.protected() {
		pass = v.pass.in.Value()
	}
	if v.integSaved {
		return func() tea.Msg {
			if _, err := runDop("", grantArgs...); err != "" {
				return integrationAddedMsg{err: err, integSaved: true}
			}
			return integrationAddedMsg{}
		}
	}
	return func() tea.Msg {
		stderr, err := runDop(pass, integArgs...)
		if err != "" {
			return integrationAddedMsg{err: err}
		}
		// The scan outcome is on the CLI's stderr (runProbe).
		summary := ""
		for _, line := range strings.Split(stderr, "\n") {
			if line = strings.TrimSpace(line); scan && (strings.Contains(line, "probe →") || strings.Contains(line, "probe-endpoints skipped")) {
				summary = displayOr(summary, line)
			}
		}
		return integrationAddedMsg{integSaved: true, probeSummary: summary}
	}
}

// summaryRows are the review's answers: integration, credential, grant.
func (v *addIntegrationView) summaryRows() [][2]string {
	rows := [][2]string{{"integration", v.integName()}}
	if !v.existingIntegration {
		rows = append(rows, [2]string{"kind", v.kindVal()})
		if d := v.desc.val(); d != "" {
			rows = append(rows, [2]string{"description", d})
		}
		if u := v.url.val(); u != "" && v.kindVal() != vault.IntegrationKindOther {
			rows = append(rows, [2]string{v.url.label, u})
		}
		if k := v.kindVal(); k == vault.IntegrationKindAPI || k == vault.IntegrationKindMCP {
			rows = append(rows, [2]string{"scan for docs", v.scan.val()})
		}
		for _, i := range advFieldsForKind(v.kindVal()) {
			if val := v.adv[i].val(); val != "" {
				rows = append(rows, [2]string{advFieldSpecs[i].label, val})
			}
		}
	}
	rows = append(rows, [2]string{"credential", v.cred.val()}, [2]string{"value", maskLen(v.value.val())},
		[2]string{"scope note", displayOr(v.scope.val(), "none")})
	if !v.existingIntegration {
		rows = append(rows, [2]string{"protection", protectWord(v.protected())})
	}
	return append(rows, v.grant.summary()...)
}

// stepper is the Integration › Credential › Grant line: done steps in
// body, the current one in brand, upcoming muted.
func stepper(cur int, names ...string) string {
	var parts []string
	for i, n := range names {
		st := mutedSt
		switch {
		case i < cur:
			st = bodySt
		case i == cur:
			st = focusSt
		}
		parts = append(parts, st.Render(n))
	}
	return strings.Join(parts, mutedSt.Render(" › "))
}

func (v *addIntegrationView) View() string {
	const title = "Add integration"
	switch v.stage {
	case integStagePick:
		// New integration, a blank line, then the existing ones.
		rows, km := optRows(v.pickOpts(), v.pickCur), pickKeys("open")
		if len(rows) > 1 {
			rows = append(rows[:1], append([]string{""}, rows[1:]...)...)
		}
		body := km.overlay(rows, v.width, frameRows(v.height), v.help)
		return frame(v.width, v.height, title, nil, "", body, status{err: v.err}.String(), km.footerLine(v.width, v.help))
	case integStageRun:
		return v.running(title, v.saving)
	case integStageDone:
		rows := [][2]string{{"integration", v.integName()}, {"credential", v.cred.val()}, {"grant", v.grant.id.val()}}
		if v.probeSummary != "" {
			rows = append(rows, [2]string{"scan", strings.TrimPrefix(firstLine(v.probeSummary), "probe → ")})
		}
		return v.doneScreen(map[bool]string{true: "Credential added", false: "Integration added"}[v.existingIntegration],
			rows, "Next: issue a bearer with this grant.", "")
	case integStageReview:
		q := "Save " + v.integName() + "?"
		if v.existingIntegration {
			q = "Add this credential to " + v.integName() + "?"
		}
		return v.review(title, q, v.summaryRows(), "save", false, v.err)
	}
	rows := v.rows()
	f := &v.form[v.stage]
	action := map[bool]string{true: "Review", false: "Next"}[v.stage == integStageGrant]
	var extra []key.Binding
	var tabs []tab
	hintTxt := ""
	if v.stage == integStageCred && !v.existingIntegration {
		tabs = []tab{{"Normal", -1, !v.advTab}, {"Advanced", -1, v.advTab}}
		extra = []key.Binding{hint("tab", map[bool]string{true: "normal", false: "advanced"}[v.advTab])}
		if v.advTab {
			hintTxt = "Optional, stored on the integration."
		}
	}
	if v.stage == integStageInteg && f.cur == 0 {
		if n := v.name.val(); n != "" && v.integName() != n {
			hintTxt = "Saved as " + v.integName() + "."
		}
	}
	km := f.formKeys(rows, action, extra...)
	body := append([]string{stepper(v.stage, "Integration", "Credential", "Grant"), ""}, f.view(rows, v.width, action)...)
	body = km.overlay(body, v.width, frameRows(v.height), v.help)
	return frame(v.width, v.height, title, tabs, counter(v.stage, 3), body, status{err: v.err, hint: hintTxt}.String(), km.footerLine(v.width, v.help))
}

// ---- integration rows shared by Add integration and the integration edit form ----

// integRows builds the integration-level rows: name, description, the
// kind slot, kind and scan pickers, one Advanced row per advFieldSpecs.
func integRows() (name, desc, url, kind, scan *formField, adv []*formField) {
	var kinds, probe [][2]string
	for _, k := range kindPresets {
		kinds = append(kinds, [2]string{k.label, k.hint})
	}
	for _, s := range probePresets {
		probe = append(probe, [2]string{s.label, s.hint})
	}
	for _, a := range advFieldSpecs {
		adv = append(adv, textRow(a.label, a.placeholder, false, false))
	}
	return textRow("name", "notion, github, db-primary", true, false), textRow("description", "Team wiki and docs", false, false),
		textRow("base URL", "", false, false), pickRow("kind", kinds), pickRow("scan for docs", probe), adv
}

// slotRows are the kind's own rows: base URL + scan (api), command
// (cli), URL or launcher + scan (mcp), none (other).
func slotRows(kind string, url, scan *formField) []*formField {
	switch kind {
	case vault.IntegrationKindAPI:
		url.label, url.in.Placeholder = "base URL", "https://api.example.com/v1"
		return []*formField{url, scan}
	case vault.IntegrationKindCLI:
		url.label, url.in.Placeholder = "command", "gh"
		return []*formField{url}
	case vault.IntegrationKindMCP:
		url.label, url.in.Placeholder = "URL or launcher", "https://mcp.example.com/sse or npx my-mcp"
		return []*formField{url, scan}
	}
	return nil
}

// slotValue is the kind slot's stored value (the metadata slotArgs writes).
func slotValue(kind string, m map[string]string) string {
	switch kind {
	case vault.IntegrationKindCLI:
		return m["cli_cmd"]
	case vault.IntegrationKindMCP:
		return displayOr(m["mcp_url"], m["mcp_cmd"])
	}
	return m["base_url"]
}

// slotArgs is the kind slot as `dop integration add` flags.
func slotArgs(kind, u string) []string {
	if u == "" {
		return nil
	}
	switch kind {
	case vault.IntegrationKindCLI:
		return []string{"--cmd", u}
	case vault.IntegrationKindMCP:
		// An http(s) URL is the MCP URL; anything else a stdio launcher.
		if strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://") {
			return []string{"--mcp-url", u}
		}
		return []string{"--mcp-cmd", u}
	case vault.IntegrationKindAPI:
		return []string{"--base-url", u}
	}
	return nil
}

// advRows are the Advanced rows that apply to kind.
func advRows(adv []*formField, kind string) []*formField {
	var r []*formField
	for _, i := range advFieldsForKind(kind) {
		r = append(r, adv[i])
	}
	return r
}

// ---------- Add grant ----------

const (
	grantStageForm = iota
	grantStageReview
	grantStageRun
	grantStageDone
)

// addGrantView is the grant form on its own: Add › Grant, or a on an
// integration's Grants tab (integration pre-filled).
type addGrantView struct {
	wiz
	stage int
	form  denseForm
	grant grantForm

	err   string
	flash string
	done  bool
}

func newAddGrantView(c *admin.Client, p *config.Paths) *addGrantView {
	vlt, _, err := loadVaultForListing(c, p)
	if err != nil || vlt == nil {
		vlt = &vault.Vault{}
	}
	v := &addGrantView{grant: newGrantForm(vlt, false)}
	v.grant.sync("")
	return v
}

// newAddGrantFor is the grant form with integ picked.
func newAddGrantFor(c *admin.Client, p *config.Paths, integ string) *addGrantView {
	v := newAddGrantView(c, p)
	for i, o := range v.grant.integ.opts {
		if o[0] == integ {
			v.grant.integ.pick = i
		}
	}
	v.grant.sync("")
	return v
}

func (v *addGrantView) Init() tea.Cmd { return nil }
func (v *addGrantView) Done() bool    { return v.done }
func (v *addGrantView) Flash() string { return v.flash }

type grantAddedMsg struct{ err string }

func (v *addGrantView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if ok, cmd := v.wizMsg(msg, v.form.typing()); ok {
		return v, cmd
	}
	switch mm := msg.(type) {
	case grantAddedMsg:
		if mm.err != "" {
			v.err, v.stage = firstLine(mm.err), grantStageReview
			return v, nil
		}
		v.stage = grantStageDone
	case tea.KeyMsg:
		k := mm.String()
		switch {
		case v.stage == grantStageRun:
			return v, nil
		case v.stage == grantStageDone:
			if k == "enter" {
				v.done, v.flash = true, "grant saved · synced with team"
			}
			return v, nil
		case k == "ctrl+c":
			v.done = true
			return v, nil
		}
		if k != "enter" {
			v.err = ""
		}
		if v.stage == grantStageReview {
			switch k {
			case "enter":
				if cmd := v.locked(mm, &v.err); cmd != nil {
					return v, cmd
				}
				args := v.grant.args()
				v.stage, v.err = grantStageRun, ""
				return v, tea.Batch(v.spinStart(), func() tea.Msg {
					_, err := runDop("", args...)
					return grantAddedMsg{err: err}
				})
			case "esc", "shift+tab":
				v.stage = grantStageForm
			}
			return v, nil
		}
		if len(v.grant.integ.opts) == 0 {
			if k == "esc" {
				v.done = true
			}
			return v, nil
		}
		switch v.form.key(v.grant.rows(), mm) {
		case formBack:
			v.done = true
		case formNext:
			if v.err = v.grant.check(&v.form); v.err == "" {
				v.stage = grantStageReview
			}
		}
		v.grant.sync("")
	}
	return v, nil
}

func (v *addGrantView) View() string {
	const title = "Add grant"
	g := &v.grant
	switch v.stage {
	case grantStageRun:
		return v.running(title, "Saving grant…")
	case grantStageDone:
		return v.doneScreen("Grant added", [][2]string{{"grant", g.id.val()}, {"integration", g.integ.val()},
			{"credential", g.cred.val()}}, "Next: issue a bearer with this grant.", "")
	case grantStageReview:
		rows := append([][2]string{{"integration", g.integ.val()}, {"credential", g.cred.val()}}, g.summary()...)
		return v.review(title, "Save "+g.id.val()+"?", rows, "save", false, v.err)
	}
	if len(g.integ.opts) == 0 {
		return v.notice(title, bodySt.Render("  No integrations yet. Add one first: Add › Integration."))
	}
	rows := g.rows()
	km := v.form.formKeys(rows, "Review")
	body := km.overlay(v.form.view(rows, v.width, "Review"), v.width, frameRows(v.height), v.help)
	return frame(v.width, v.height, title, nil, "", body, status{err: v.err}.String(), km.footerLine(v.width, v.help))
}

// advFieldSpec is one row of the credential step's Advanced tab. Every
// one is integration metadata (`dop integration add` stores each flag
// under its metadata key); hiddenFor lists the kinds it does not apply to.
type advFieldSpec struct {
	label, placeholder string
	cliFlag            string // flag passed to `dop integration add`
	metaKey            string // where the CLI stores it in Integration.Metadata
	hiddenFor          []string
}

var advFieldSpecs = []advFieldSpec{
	{"auth env template", "KEY=$TOKEN;KEY2=$SERVER_ROOT", "--cli-auth-env", "cli_auth_env", []string{"api", "mcp", "other"}},
	{"server root", "https://host, when it differs from the URL", "--server-root", "server_root", nil},
	{"allowed scope hint", "Agent_Collab,Skills_Registry", "--allowed", "allowed", nil},
	{"auth style", "bearer-header, basic, query-param", "--auth-style", "auth_style", []string{"cli", "mcp", "other"}},
	{"install hint", "go install example.com/mycli@latest", "--cli-install", "cli_install", []string{"api", "mcp", "other"}},
	{"help entry", "mycli --help", "--cli-help", "cli_help", []string{"api", "mcp", "other"}},
	{"endpoints URL", "https://api.example.com/openapi.json", "--endpoints-url", "endpoints_url", []string{"cli", "mcp", "other"}},
	{"auth header", "Bearer", "--auth-header", "auth_header", []string{"cli", "mcp", "other"}},
	{"args hint", "exec --inherit-env", "--args-hint", "cli_args_hint", []string{"api", "mcp", "other"}},
}

// advFieldsForKind returns the subset of advFieldSpecs applicable to
// the given kind (so the sub-form hides irrelevant rows).
func advFieldsForKind(kind string) []int {
	out := []int{}
	for i, s := range advFieldSpecs {
		hidden := false
		for _, k := range s.hiddenFor {
			if k == kind {
				hidden = true
				break
			}
		}
		if !hidden {
			out = append(out, i)
		}
	}
	return out
}

// into the free-text input via scopeMode.
var scopePresets = []struct {
	label string
	value string
}{
	{"read-only", "read-only"},
	{"read-write", "read-write"},
	{"admin", "admin"},
	{"other…", ""},
}

// v1.13.0-rc12 — protectionPresets mirrors scopePresets shape for the
// new "Protection" step. Picking "protected" marks the integration
// as owner-locked and forces the passphrase step before Save.
var protectionPresets = []struct {
	label string
	value bool
	hint  string
}{
	{"default", false, "any admin can modify"},
	{"protected", true, "only you can modify, requires your approval passphrase"},
}

// v1.13.0-rc13 — kindPresets drives the new Kind step. Order matters:
// api is first (the default + most common). Changing a kind post-save
// is handled by `dop integration add --kind <new>` (mutable).
var kindPresets = []struct {
	label string
	value string // vault.IntegrationKind* constant
	hint  string
}{
	{"api", vault.IntegrationKindAPI, "HTTP service, credential sent to a base URL (default)"},
	{"cli", vault.IntegrationKindCLI, "command-line tool, credential exported to its env"},
	{"mcp", vault.IntegrationKindMCP, "Model Context Protocol server, URL or stdio launcher"},
	{"other", vault.IntegrationKindOther, "unspecified, only the credential is exported"},
}

// v1.13.0-rc15 — probePresets drives the opt-in endpoints discovery
// step. "no" default — DOP never auto-fetches without an explicit yes.
var probePresets = []struct {
	label string
	value bool
	hint  string
}{
	{"no", false, "store only the URL you entered (default)"},
	{"yes", true, "scan common OpenAPI paths or MCP tools/list"},
}

// pos is the current step's index in fl; the review step is len(fl).
func stepPos(fl []int, step int) int {
	for i, s := range fl {
		if s == step {
			return i
		}
	}
	return len(fl)
}

// firstLine is the first line of a subprocess error.
func firstLine(s string) string {
	s, _, _ = strings.Cut(strings.TrimSpace(s), "\n")
	return s
}

// newFormInput — prompt-less textinput with a static (non-blinking)
// cursor and the muted italic placeholder; mask echoes • for secrets.
// ponytail: static cursor so no blink Cmd/msg needs routing.
func newFormInput(mask bool) textinput.Model {
	t := textinput.New()
	t.Prompt = ""
	t.Cursor.SetMode(cursor.CursorStatic)
	t.Cursor.Style = cursorSt
	t.TextStyle, t.PlaceholderStyle = bodySt, placeholderSt
	t.Width = 72 // ponytail: fixed; longer values scroll inside the field
	if mask {
		t.EchoMode = textinput.EchoPassword
		t.EchoCharacter = '•'
	}
	return t
}

// edit hands one key to a form input. Focus first: textinput ignores
// keys while blurred. ponytail: returned Cmd dropped (only paste/blink).
func edit(t *textinput.Model, mm tea.KeyMsg) {
	t.Focus()
	*t, _ = t.Update(mm)
}

// displayOr returns s unless it's empty, in which case fallback is used
// (for compact labels in the review line of multi-step forms).
func displayOr(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
