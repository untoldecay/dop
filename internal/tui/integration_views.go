// Add-integration and add-grant TUI forms.

package tui

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/cursor"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

// ---------- Add integration ----------
//
// A wizard: one question per screen (flow() lists the steps the
// answers lead through), then a review, running and done screen.
// One credential per run; more come from the integration's
// Credentials tab (newAddCredentialView).

const (
	integAddStepName       = 0
	integAddStepKind       = 1
	integAddStepDesc       = 2
	integAddStepKindSlot   = 3 // kind-adaptive: base URL / command / MCP URL
	integAddStepProbe      = 4 // api / mcp only
	integAddStepCred       = 5
	integAddStepValue      = 6
	integAddStepScope      = 7
	integAddStepProtect    = 8
	integAddStepPassphrase = 9 // protected only
	integAddStepAdvanced   = 10
	integAddStepSave       = 12 // review
	integAddStepRun        = 13
	integAddStepDone       = 100
)

// advFieldSpec defines one row in the Advanced sub-form. hiddenFor
// lists integration kinds for which the row is hidden entirely (so
// e.g. cli_auth_env doesn't appear on an api integration).
type advFieldSpec struct {
	label     string
	hint      string
	bufIdx    int    // index into addIntegrationView.advBufs
	cliFlag   string // flag passed to `dop integration add`
	hiddenFor []string
}

var advFieldSpecs = []advFieldSpec{
	{"CLI auth env template", "KEY1=$TOKEN;KEY2=$SERVER_ROOT · expanded + exported directly", 0, "--cli-auth-env", []string{"api", "mcp", "other"}},
	{"Server root (CLI/API)", "distinct from base URL when they differ · e.g. https://host (no path)", 1, "--server-root", []string{}},
	{"Allowed scope hint", "free text · e.g. Agent_Collab,Skills_Registry · agent reads to avoid 403-probing", 2, "--allowed", []string{}},
	{"Auth style (API)", "e.g. bearer-header · basic · query-param", 3, "--auth-style", []string{"cli", "mcp", "other"}},
	{"CLI install hint", "e.g. go install github.com/you/mycli/cmd/mycli@latest", 4, "--cli-install", []string{"api", "mcp", "other"}},
	{"CLI help entry", "e.g. mycli --help", 5, "--cli-help", []string{"api", "mcp", "other"}},
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

// Wizard-only steps: the custom scope note after "other…", and one
// step per kind-applicable advanced field (integAddStepAdv0 + i).
const (
	integAddStepScopeText = 14
	integAddStepAdv0      = 20
)

type addIntegrationView struct {
	wiz
	client *admin.Client
	paths  *config.Paths

	step       int
	nameBuf    textinput.Model
	descBuf    textinput.Model
	urlBuf     textinput.Model
	credBuf    textinput.Model
	valueBuf   textinput.Model
	scopeBuf   textinput.Model
	credEdited bool // true once the operator changed the prefill

	// Picker cursors; each choice is committed on enter.
	kindPickCursor     int
	probePickCursor    int
	scopePickCursor    int
	protectPickCursor  int
	advancedPickCursor int

	kindChoice      string // IntegrationKind* value
	probeChoice     bool   // --probe-endpoints
	scopeMode       bool   // true = scope preset; false = custom text ("other…")
	protectedChoice bool
	advancedChoice  bool
	passphraseBuf   textinput.Model
	advBufs         [6]textinput.Model

	// probe outcome from the CLI stderr, shown on the done screen.
	probeSummary string

	// existingIntegration: the "add a credential to <service>" entry
	// (Credentials tab, a). Integration-level steps are skipped so they
	// can't mutate the existing integration.
	existingIntegration bool

	err   string
	flash string
	done  bool
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

// probeApplicable reports whether the probe step should be VISIBLE
// for the current kind. v1.13.0-rc16 — widened: always true for
// api/mcp regardless of URL contents. The silent "URL has no scheme"
// skip from rc15 was confusing — operators who typed
// `boiler-alpha.decaylab.com` without https:// never saw the step
// and couldn't tell whether the probe would have run.
//
// Now the step is always offered for api/mcp; if the operator picks
// "yes" but the URL is missing or has no scheme, the CLI prints a
// clear "probe-endpoints skipped (no --base-url set)" and the save
// still succeeds. Loud > silent.
func probeApplicable(kind, urlBuf string) bool {
	switch kind {
	case vault.IntegrationKindAPI, vault.IntegrationKindMCP:
		return true
	}
	return false
}

// kindSlotLabel returns the row label + hint for the kind-adaptive
// step 3 based on which kind the operator picked at step 1.
func kindSlotLabel(kind string) (label, hint string) {
	switch kind {
	case vault.IntegrationKindCLI:
		return "Command (binary name)", "e.g. dop, boiler — must be on the agent's PATH"
	case vault.IntegrationKindMCP:
		return "MCP URL (or stdio cmd)", "an HTTP URL or a launcher command like npx my-mcp"
	case vault.IntegrationKindOther:
		return "(no extra config)", "other kind — this row is skipped"
	default: // api, empty
		return "Base URL", "optional — sets an env var like NOTION_BASE_URL"
	}
}

func newAddIntegrationView(c *admin.Client, p *config.Paths) *addIntegrationView {
	v := &addIntegrationView{client: c, paths: p, scopeMode: true, kindChoice: vault.IntegrationKindAPI}
	for _, t := range []*textinput.Model{&v.nameBuf, &v.descBuf, &v.urlBuf, &v.credBuf, &v.scopeBuf} {
		*t = newFormInput(false)
	}
	for i := range v.advBufs {
		v.advBufs[i] = newFormInput(false)
	}
	v.valueBuf, v.passphraseBuf = newFormInput(true), newFormInput(true)
	v.nameBuf.Placeholder = "notion, github, db-primary"
	v.descBuf.Placeholder = "Team wiki and docs"
	v.credBuf.Placeholder = "notion"
	v.scopeBuf.Placeholder = "read-only on /docs"
	return v
}

// newAddCredentialView is the add form on an existing integration:
// kind, description and URL come from the vault and are not asked.
func newAddCredentialView(c *admin.Client, p *config.Paths, svc string) *addIntegrationView {
	v := newAddIntegrationView(c, p)
	v.existingIntegration = true
	v.nameBuf.SetValue(svc)
	if vlt, _, err := loadVaultForListing(c, p); err == nil && vlt != nil {
		if integ, ok := vlt.Integrations[svc]; ok {
			v.kindChoice = vault.IntegrationKindOf(integ)
			v.descBuf.SetValue(integ.Description)
			switch v.kindChoice {
			case vault.IntegrationKindCLI:
				v.urlBuf.SetValue(integ.Metadata["cli_cmd"])
			case vault.IntegrationKindMCP:
				v.urlBuf.SetValue(displayOr(integ.Metadata["mcp_url"], integ.Metadata["mcp_cmd"]))
			default:
				v.urlBuf.SetValue(integ.Metadata["base_url"])
			}
		}
	}
	v.step = integAddStepCred
	v.prefillIfNeeded()
	return v
}

func (v *addIntegrationView) Init() tea.Cmd { return nil }
func (v *addIntegrationView) Done() bool    { return v.done }
func (v *addIntegrationView) Flash() string { return v.flash }

type integrationAddedMsg struct {
	err string
	// probe outcome summary extracted from the subprocess stderr when
	// the operator opted into probing; empty otherwise.
	probeSummary string
}

// flow is the ordered list of steps the current answers lead through
// (the review step, integAddStepSave, comes after the last one).
func (v *addIntegrationView) flow() []int {
	var s []int
	if !v.existingIntegration {
		s = append(s, integAddStepName, integAddStepKind, integAddStepDesc)
		if v.kindChoice != vault.IntegrationKindOther {
			s = append(s, integAddStepKindSlot)
		}
		if probeApplicable(v.kindChoice, "") {
			s = append(s, integAddStepProbe)
		}
	}
	s = append(s, integAddStepCred, integAddStepValue, integAddStepScope)
	if !v.scopeMode {
		s = append(s, integAddStepScopeText)
	}
	s = append(s, integAddStepProtect)
	if v.protectedChoice {
		s = append(s, integAddStepPassphrase)
	}
	if !v.existingIntegration {
		s = append(s, integAddStepAdvanced)
		if v.advancedChoice {
			for i := range advFieldsForKind(v.kindChoice) {
				s = append(s, integAddStepAdv0+i)
			}
		}
	}
	return s
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

// picker is the current step's options and cursor (nil on text steps).
func (v *addIntegrationView) picker() ([][2]string, *int) {
	var o [][2]string
	switch v.step {
	case integAddStepKind:
		for _, p := range kindPresets {
			o = append(o, [2]string{p.label, p.hint})
		}
		return o, &v.kindPickCursor
	case integAddStepProbe:
		for _, p := range probePresets {
			o = append(o, [2]string{p.label, p.hint})
		}
		return o, &v.probePickCursor
	case integAddStepScope:
		for _, p := range scopePresets {
			o = append(o, [2]string{p.label, map[bool]string{true: "type your own"}[p.value == ""]})
		}
		return o, &v.scopePickCursor
	case integAddStepProtect:
		return protectOpts(), &v.protectPickCursor
	case integAddStepAdvanced:
		return [][2]string{{"no", "skip (default)"}, {"yes", "CLI auth env, server root, allowed scope, auth style"}}, &v.advancedPickCursor
	}
	return nil, nil
}

func (v *addIntegrationView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	in := v.curBuf()
	if ok, cmd := v.wizMsg(msg, in != nil && in.Value() != ""); ok {
		return v, cmd
	}
	switch mm := msg.(type) {
	case integrationAddedMsg:
		if mm.err != "" {
			v.err, v.step = firstLine(mm.err), integAddStepSave
			return v, nil
		}
		v.probeSummary = mm.probeSummary
		v.step = integAddStepDone
	case tea.KeyMsg:
		switch {
		case v.step == integAddStepRun:
			return v, nil
		case v.step == integAddStepDone || mm.String() == "ctrl+c":
			v.done = true
			v.flash = map[bool]string{true: "integration saved · synced with team"}[v.step == integAddStepDone]
			return v, nil
		}
		if mm.String() != "enter" {
			v.err = ""
		}
		fl := v.flow()
		i := stepPos(fl, v.step)
		switch mm.String() {
		case "enter":
			return v.advance()
		case "esc", "shift+tab":
			if wizBack(mm, &i) < 0 {
				v.done = true
			} else {
				v.step = fl[i]
			}
			return v, nil
		case "up", "down":
			if opts, cur := v.picker(); opts != nil {
				stepCursor(cur, len(opts), map[string]int{"up": -1, "down": 1}[mm.String()])
				return v, nil
			}
		}
		if in != nil {
			edit(in, mm)
			v.credEdited = v.credEdited || v.step == integAddStepCred
		}
	}
	return v, nil
}

// curBuf is the current step's text input (nil on pickers / review).
func (v *addIntegrationView) curBuf() *textinput.Model {
	switch v.step {
	case integAddStepName:
		return &v.nameBuf
	case integAddStepDesc:
		return &v.descBuf
	case integAddStepKindSlot:
		return &v.urlBuf
	case integAddStepCred:
		return &v.credBuf
	case integAddStepValue:
		return &v.valueBuf
	case integAddStepScopeText:
		return &v.scopeBuf
	case integAddStepPassphrase:
		return &v.passphraseBuf
	}
	if f := advFieldsForKind(v.kindChoice); v.step >= integAddStepAdv0 && v.step-integAddStepAdv0 < len(f) {
		return &v.advBufs[advFieldSpecs[f[v.step-integAddStepAdv0]].bufIdx]
	}
	return nil
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

// prefillIfNeeded seeds the credential-name buffer with the service
// name the first time we arrive at that step. The operator can still
// edit it — but the default is what most single-credential services
// need, and it makes the redundancy ("why two names?") obvious.
func (v *addIntegrationView) prefillIfNeeded() {
	if v.step == integAddStepCred && v.credBuf.Value() == "" && !v.credEdited {
		v.credBuf.SetValue(strings.TrimSpace(v.nameBuf.Value()))
	}
}

// advance validates and commits the current step, then moves to the
// next step of the (possibly changed) flow, or saves from the review.
func (v *addIntegrationView) advance() (tea.Model, tea.Cmd) {
	required := func(t *textinput.Model, what string) bool {
		if strings.TrimSpace(t.Value()) == "" {
			v.err = what + " is required"
			return false
		}
		return true
	}
	switch v.step {
	case integAddStepName:
		if !required(&v.nameBuf, "Service name") {
			return v, nil
		}
	case integAddStepKind:
		v.kindChoice = kindPresets[v.kindPickCursor].value
	case integAddStepProbe:
		v.probeChoice = probePresets[v.probePickCursor].value
	case integAddStepCred:
		if !required(&v.credBuf, "Credential name") {
			return v, nil
		}
	case integAddStepValue:
		if !required(&v.valueBuf, "Credential value") {
			return v, nil
		}
	case integAddStepScope:
		sel := scopePresets[v.scopePickCursor]
		if sel.value == "" && v.scopeMode {
			v.scopeBuf.Reset()
		} else if sel.value != "" {
			v.scopeBuf.SetValue(sel.value)
		}
		v.scopeMode = sel.value != ""
	case integAddStepProtect:
		v.protectedChoice = protectionPresets[v.protectPickCursor].value
	case integAddStepPassphrase:
		if !required(&v.passphraseBuf, "Approval passphrase") {
			return v, nil
		}
	case integAddStepAdvanced:
		v.advancedChoice = v.advancedPickCursor == 1
	case integAddStepSave:
		v.step, v.err = integAddStepRun, ""
		return v, tea.Batch(v.spinStart(), v.save())
	}
	v.err = ""
	fl := v.flow()
	if i := stepPos(fl, v.step) + 1; i < len(fl) {
		v.step = fl[i]
	} else {
		v.step = integAddStepSave
	}
	v.prefillIfNeeded()
	return v, nil
}

func (v *addIntegrationView) save() tea.Cmd {
	name := strings.TrimSpace(v.nameBuf.Value())
	desc := strings.TrimSpace(v.descBuf.Value())
	url := strings.TrimSpace(v.urlBuf.Value())
	cred := strings.TrimSpace(v.credBuf.Value())
	value := strings.TrimSpace(v.valueBuf.Value())
	scope := strings.TrimSpace(v.scopeBuf.Value())
	if scope == "" {
		scope = "-"
	}
	// v1.13.0-rc12 — capture protected state + passphrase for the
	// subprocess invocation. Passphrase travels via stdin (never on
	// the command line) and only when protection is actually on.
	protected := v.protectedChoice
	passphrase := v.passphraseBuf.Value()
	// v1.13.0-rc13 — capture kind + route the KindSlot buffer (urlBuf)
	// into the right CLI flag per kind.
	kind := v.kindChoice
	// v1.13.0-rc15 — snapshot the probe choice. Append --probe-endpoints
	// to the subprocess call when the operator said yes.
	wantProbe := v.probeChoice
	return func() tea.Msg {
		self, _ := os.Executable()
		args := []string{"integration", "add", "--name", name}
		if desc != "" {
			args = append(args, "--description", desc)
		}
		if kind != "" {
			args = append(args, "--kind", kind)
		}
		// Kind-specific slot — urlBuf semantics depend on kind.
		if url != "" {
			switch kind {
			case vault.IntegrationKindCLI:
				args = append(args, "--cmd", url)
			case vault.IntegrationKindMCP:
				// If it starts with http it's a URL; otherwise treat as
				// stdio launcher command. Simple heuristic; operator can
				// override via `integration add` on the CLI.
				if strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://") {
					args = append(args, "--mcp-url", url)
				} else {
					args = append(args, "--mcp-cmd", url)
				}
			default: // api, other
				args = append(args, "--base-url", url)
			}
		}
		args = append(args, "--token", fmt.Sprintf("%s=%s:%s", cred, value, scope))
		if wantProbe {
			args = append(args, "--probe-endpoints")
		}
		// v1.13.0-rc17 — advanced fields. Each non-empty buffer maps
		// to its CLI flag; empty buffers are silently skipped.
		for _, s := range advFieldSpecs {
			if val := strings.TrimSpace(v.advBufs[s.bufIdx].Value()); val != "" {
				args = append(args, s.cliFlag, val)
			}
		}
		if protected {
			args = append(args, "--protected", "--passphrase-stdin")
		}
		cmd := exec.Command(self, args...)
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
		if protected {
			cmd.Stdin = strings.NewReader(passphrase + "\n")
		}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return integrationAddedMsg{err: strings.TrimSpace(stderr.String())}
		}
		// v1.13.0-rc17 — extract probe summary from stderr so the Done
		// screen can surface "probe → <url>" / "probe → no match" /
		// "probe-endpoints skipped (…)" instead of leaving the operator
		// to wonder whether the probe ran. Grep for the stderr lines the
		// CLI emits in runProbe.
		summary := ""
		if wantProbe {
			for _, line := range strings.Split(stderr.String(), "\n") {
				line = strings.TrimSpace(line)
				if strings.Contains(line, "probe →") || strings.Contains(line, "probe-endpoints skipped") {
					if summary != "" {
						summary += "\n"
					}
					summary += line
				}
			}
			if summary == "" {
				summary = "(no probe output — flag may be unsupported in this dop version)"
			}
		}
		return integrationAddedMsg{probeSummary: summary}
	}
}

// summaryRows are the review step's answers.
func (v *addIntegrationView) summaryRows() [][2]string {
	name := vault.NormalizeIntegrationName(strings.TrimSpace(v.nameBuf.Value()))
	rows := [][2]string{{"integration", name}}
	if !v.existingIntegration {
		rows = append(rows, [2]string{"kind", v.kindChoice})
		if d := strings.TrimSpace(v.descBuf.Value()); d != "" {
			rows = append(rows, [2]string{"description", d})
		}
		if u := strings.TrimSpace(v.urlBuf.Value()); u != "" && v.kindChoice != vault.IntegrationKindOther {
			l, _ := kindSlotLabel(v.kindChoice)
			rows = append(rows, [2]string{strings.ToLower(l), u})
		}
		if probeApplicable(v.kindChoice, "") {
			rows = append(rows, [2]string{"scan", map[bool]string{true: "yes", false: "no"}[v.probeChoice]})
		}
	}
	val := v.valueBuf.Value()
	tail := maskLen(val)
	rows = append(rows, [2]string{"credential", strings.TrimSpace(v.credBuf.Value())}, [2]string{"value", tail},
		[2]string{"scope note", displayOr(v.scopeBuf.Value(), "none")}, [2]string{"protection", protectWord(v.protectedChoice)})
	for _, s := range advFieldSpecs {
		if val := strings.TrimSpace(v.advBufs[s.bufIdx].Value()); val != "" {
			rows = append(rows, [2]string{strings.ToLower(s.label), val})
		}
	}
	return rows
}

func (v *addIntegrationView) View() string {
	name := strings.TrimSpace(v.nameBuf.Value())
	title := "Add integration"
	if v.existingIntegration {
		title = "Add credential"
	}
	switch v.step {
	case integAddStepRun:
		return v.running(title, "Saving "+vault.NormalizeIntegrationName(name))
	case integAddStepDone:
		rows := v.summaryRows()[:1]
		rows = append(rows, [2]string{"credential", strings.TrimSpace(v.credBuf.Value())})
		if v.probeSummary != "" {
			rows = append(rows, [2]string{"scan", strings.TrimPrefix(firstLine(v.probeSummary), "probe → ")})
		}
		return v.doneScreen(map[bool]string{true: "Credential added", false: "Integration saved"}[v.existingIntegration],
			rows, "Next: add a grant, then issue a bearer.", "")
	case integAddStepSave:
		q := "Save this integration?"
		if v.existingIntegration {
			q = "Add this credential to " + name + "?"
		}
		return v.review(title, q, v.summaryRows(), "save", false, v.err)
	}
	fl := v.flow()
	var prompt, helper string
	switch v.step {
	case integAddStepName:
		prompt, helper = "Service name", "Spaces and symbols become hyphens when saved."
		if norm := vault.NormalizeIntegrationName(name); name != "" && norm != name {
			helper = "Saved as " + norm + "."
		}
	case integAddStepKind:
		prompt = "Kind of " + name
	case integAddStepDesc:
		prompt, helper = "What it's for", "Optional, one line."
	case integAddStepKindSlot:
		prompt, helper = kindSlotLabel(v.kindChoice)
		v.urlBuf.Placeholder = map[string]string{vault.IntegrationKindCLI: "gh", vault.IntegrationKindMCP: "https://mcp.example.com/sse"}[v.kindChoice]
		if v.urlBuf.Placeholder == "" {
			v.urlBuf.Placeholder = "https://api.example.com/v1"
		}
	case integAddStepProbe:
		prompt = "Scan for an endpoints doc"
	case integAddStepCred:
		prompt, helper = "Credential name for "+name, "Prefilled from the service name; change it to add several."
	case integAddStepValue:
		prompt, helper = "Credential value", "The API key or password, masked as you type."
	case integAddStepScope, integAddStepScopeText:
		prompt = "What it can do"
	case integAddStepProtect:
		prompt = "Protection"
	case integAddStepPassphrase:
		prompt, helper = "Your approval passphrase", "Protected integrations need it to save."
	case integAddStepAdvanced:
		prompt = "Advanced fields"
	default: // advanced field
		s := advFieldSpecs[advFieldsForKind(v.kindChoice)[v.step-integAddStepAdv0]]
		prompt, helper = s.label, "Optional. "+s.hint
	}
	var input []string
	if opts, cur := v.picker(); opts != nil {
		input = optRows(opts, *cur)
	} else if in := v.curBuf(); in != nil {
		input = []string{inputRow(in)}
	}
	return v.screen(title, counter(stepPos(fl, v.step), len(fl)), prompt, input, helper, v.err, "", wizKeys("next"))
}

// ---------- Add grant ----------

// Add grant steps: id, integration, credential, env prefix, projects,
// tags, then review / running / done.
const (
	grantAddStepID = iota
	grantAddStepInteg
	grantAddStepCred
	grantAddStepEnv
	grantAddStepProjects
	grantAddStepTags
	grantAddStepReview
	grantAddStepRun
	grantAddStepDone
)

type addGrantView struct {
	wiz
	client *admin.Client
	paths  *config.Paths

	step        int
	idBuf       textinput.Model
	integration string
	token       string
	envBuf      textinput.Model
	projectsBuf textinput.Model // CSV, split by the CLI
	tagsBuf     textinput.Model // CSV

	integrations []string            // integration names
	tokensByInt  map[string][]string // credentials per integration
	cursor       int                 // integration / credential picker cursor

	err   string
	flash string
	done  bool
}

func newAddGrantView(c *admin.Client, p *config.Paths) *addGrantView {
	v := &addGrantView{client: c, paths: p, tokensByInt: map[string][]string{}}
	for _, t := range []*textinput.Model{&v.idBuf, &v.envBuf, &v.projectsBuf, &v.tagsBuf} {
		*t = newFormInput(false)
	}
	v.idBuf.Placeholder = "notion.read"
	v.envBuf.Placeholder = "auto"
	v.projectsBuf.Placeholder = "docs, wiki"
	v.tagsBuf.Placeholder = "ro, ci"
	v.loadIntegrations()
	return v
}

func (v *addGrantView) Init() tea.Cmd { return nil }
func (v *addGrantView) Done() bool    { return v.done }
func (v *addGrantView) Flash() string { return v.flash }

func (v *addGrantView) loadIntegrations() {
	// Read the vault to surface integrations + upstream tokens.
	if v.client == nil {
		return
	}
	vlt, _, err := loadVaultForListing(v.client, v.paths)
	if err != nil {
		return
	}
	for name, integ := range vlt.Integrations {
		v.integrations = append(v.integrations, name)
		for tn := range integ.Tokens {
			v.tokensByInt[name] = append(v.tokensByInt[name], tn)
		}
		sort.Strings(v.tokensByInt[name])
	}
	sort.Strings(v.integrations)
}

type grantAddedMsg struct{ err string }

func (v *addGrantView) curBuf() *textinput.Model {
	return map[int]*textinput.Model{grantAddStepID: &v.idBuf, grantAddStepEnv: &v.envBuf,
		grantAddStepProjects: &v.projectsBuf, grantAddStepTags: &v.tagsBuf}[v.step]
}

// opts is the integration / credential picker of the current step.
func (v *addGrantView) opts() []string {
	switch v.step {
	case grantAddStepInteg:
		return v.integrations
	case grantAddStepCred:
		return v.tokensByInt[v.integration]
	}
	return nil
}

func (v *addGrantView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	in := v.curBuf()
	if ok, cmd := v.wizMsg(msg, in != nil && in.Value() != ""); ok {
		return v, cmd
	}
	switch mm := msg.(type) {
	case grantAddedMsg:
		if mm.err != "" {
			v.err, v.step = firstLine(mm.err), grantAddStepReview
			return v, nil
		}
		v.step = grantAddStepDone
	case tea.KeyMsg:
		switch {
		case v.step == grantAddStepRun:
			return v, nil
		case v.step == grantAddStepDone || mm.String() == "ctrl+c":
			v.done = true
			v.flash = map[bool]string{true: "grant saved · synced with team"}[v.step == grantAddStepDone]
			return v, nil
		}
		if mm.String() != "enter" {
			v.err = ""
		}
		switch mm.String() {
		case "enter":
			return v.advance()
		case "esc", "shift+tab":
			if wizBack(mm, &v.step) < 0 {
				v.done = true
			}
			v.cursor = 0
			return v, nil
		case "up", "down":
			if o := v.opts(); o != nil {
				stepCursor(&v.cursor, len(o), map[string]int{"up": -1, "down": 1}[mm.String()])
				return v, nil
			}
		}
		if in != nil {
			edit(in, mm)
		}
	}
	return v, nil
}

func (v *addGrantView) advance() (tea.Model, tea.Cmd) {
	switch v.step {
	case grantAddStepID:
		if strings.TrimSpace(v.idBuf.Value()) == "" {
			v.err = "Grant name is required"
			return v, nil
		}
	case grantAddStepInteg:
		if len(v.integrations) == 0 {
			v.err = "No integrations yet: add one first"
			return v, nil
		}
		if in := v.integrations[v.cursor]; in != v.integration {
			v.integration = in
			v.envBuf.SetValue(strings.ToUpper(in))
		}
	case grantAddStepCred:
		toks := v.tokensByInt[v.integration]
		if len(toks) == 0 {
			v.err = "This integration has no credentials"
			return v, nil
		}
		v.token = toks[v.cursor]
	case grantAddStepReview:
		v.step, v.err = grantAddStepRun, ""
		return v, tea.Batch(v.spinStart(), v.save())
	}
	v.err, v.cursor = "", 0
	v.step++
	return v, nil
}

func (v *addGrantView) save() tea.Cmd {
	id := strings.TrimSpace(v.idBuf.Value())
	env := strings.TrimSpace(v.envBuf.Value())
	projects := strings.TrimSpace(v.projectsBuf.Value())
	tags := strings.TrimSpace(v.tagsBuf.Value())
	integ := v.integration
	tok := v.token
	return func() tea.Msg {
		self, _ := os.Executable()
		args := []string{"grant", "add",
			"--id", id,
			"--integration", integ,
			"--token", tok}
		// v1.13.0-rc4 — only pass --env-prefix when the user supplied
		// one explicitly. Pre-rc4 the TUI auto-filled with
		// strings.ToUpper(integration) which left spaces intact
		// ("Boiler Pensieve" → "BOILER PENSIEVE" → literal space in
		// the resulting env var name — invalid shell identifier).
		// With empty env_prefix the grant falls through to
		// EffectivePrefix() which runs SanitizeEnvKey on the
		// auto-derived <INTEGRATION>_<TOKEN>.
		if env != "" {
			args = append(args, "--env-prefix", env)
		}
		// v1.13.0-rc5 — parity with CLI/edit: projects + tags as CSV.
		if projects != "" {
			args = append(args, "--projects", projects)
		}
		if tags != "" {
			args = append(args, "--tags", tags)
		}
		cmd := exec.Command(self, args...)
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return grantAddedMsg{err: strings.TrimSpace(stderr.String())}
		}
		return grantAddedMsg{}
	}
}

func (v *addGrantView) summaryRows() [][2]string {
	return [][2]string{{"grant", strings.TrimSpace(v.idBuf.Value())}, {"integration", v.integration}, {"credential", v.token},
		{"env prefix", displayOr(v.envBuf.Value(), "auto")}, {"projects", displayOr(v.projectsBuf.Value(), "none")},
		{"tags", displayOr(v.tagsBuf.Value(), "none")}}
}

func (v *addGrantView) View() string {
	const title = "Add grant"
	id := strings.TrimSpace(v.idBuf.Value())
	switch v.step {
	case grantAddStepRun:
		return v.running(title, "Saving "+id)
	case grantAddStepDone:
		return v.doneScreen("Grant saved", v.summaryRows()[:3], "Next: issue a bearer with this grant.", "")
	case grantAddStepReview:
		return v.review(title, "Save this grant?", v.summaryRows(), "save", false, v.err)
	}
	prompt := map[int]string{grantAddStepID: "Grant name", grantAddStepInteg: "Integration for " + id,
		grantAddStepCred: "Credential of " + v.integration, grantAddStepEnv: "Env prefix",
		grantAddStepProjects: "Projects", grantAddStepTags: "Tags"}[v.step]
	helper := map[int]string{grantAddStepEnv: "Optional. Empty derives it from integration and credential.",
		grantAddStepProjects: "Optional, comma-separated. Projects group grants; they are not permissions.",
		grantAddStepTags:     "Optional, comma-separated."}[v.step]
	var input []string
	if in := v.curBuf(); in != nil {
		input = []string{inputRow(in)}
	} else if o := v.opts(); len(o) > 0 {
		var rows [][2]string
		for _, n := range o {
			rows = append(rows, [2]string{n, ""})
		}
		input = optRows(rows, v.cursor)
	} else {
		input = []string{mutedSt.Render("  none yet")}
	}
	return v.screen(title, counter(v.step, grantAddStepReview), prompt, input, helper, v.err, "", wizKeys("next"))
}

// displayOr returns s unless it's empty, in which case fallback is used
// (for compact labels in the review line of multi-step forms).
func displayOr(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
