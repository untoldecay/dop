// Add-integration and add-grant TUI forms.

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

// ---------- Add integration (v1.10.3 rewrite) ----------
//
// Same look-and-feel as Issue Token: every row visible at once, the
// active row highlighted with a cursor bar, values fill in as you
// go. One credential per Add flow — additional credentials go through
// the integration edit path (a future release will unify these).
//
// The steps map to on-screen rows:
//   0 Service name         (e.g. notion, github, db-primary)
//   1 What it's for        (optional description)
//   2 Base URL             (optional; sets an env var like NOTION_BASE_URL)
//   3 Credential name      (prefilled from service name; user can edit)
//   4 Credential value     (masked as you type)
//   5 What can it do       (optional scope note — e.g. "read-only")
//   6 Save                 (enter to persist)
//   7 Running
//   100 Done

const (
	integAddStepName = 0
	// v1.13.0-rc13 — new Kind preset step. Everything after shifts by 1.
	// The old "Base URL" row becomes a KIND-ADAPTIVE slot: label +
	// placeholder change based on kind picked at step 1.
	integAddStepKind     = 1
	integAddStepDesc     = 2
	integAddStepKindSlot = 3
	// v1.13.0-rc15 — opt-in endpoints probe. Preset picker (yes/no);
	// only rendered when kind=api AND KindSlot has a URL, OR kind=mcp
	// AND KindSlot has an mcp URL. Skipped silently otherwise.
	integAddStepProbe = 4
	integAddStepCred  = 5
	integAddStepValue = 6
	integAddStepScope = 7
	// v1.13.0-rc12 — new protection step mirrors the scope-note preset
	// picker shape (two-item preset list, enter to pick, backspace to
	// return). If "protected" is picked, we insert a passphrase step
	// before Save; otherwise we jump straight to Save.
	integAddStepProtect    = 8
	integAddStepPassphrase = 9
	integAddStepSave       = 10
	integAddStepRun        = 11
	integAddStepDone       = 100
	integAddFieldCount     = 11 // rows shown (0..10)
)

type addIntegrationView struct {
	client *admin.Client
	paths  *config.Paths

	step       int
	nameBuf    strings.Builder
	descBuf    strings.Builder
	urlBuf     strings.Builder
	credBuf    strings.Builder
	valueBuf   strings.Builder
	scopeBuf   strings.Builder
	credEdited bool // true once the operator changed the prefill

	// v1.13.0-rc6 — service picker at step 0. existingServices lists
	// vault integrations in sorted order so operators adding a second
	// credential to an existing service don't accidentally re-type
	// the name (which would create a near-duplicate even with rc4's
	// case-insensitive merge). servicePickCursor: 0 = "+ Create new…",
	// 1..N = existing services. serviceMode true = picker; false =
	// text input (switched on when "+ Create new…" is picked).
	existingServices  []string
	servicePickCursor int
	serviceMode       bool // true until operator switches to text input

	// v1.13.0-rc7 — scope-note preset picker on step 5. Mirrors the
	// expiry preset picker in issueView: a short menu of common
	// values (read-only, read-write, admin) plus "other…" that drops
	// into the free-text input. scopeMode true = picker; false =
	// text input.
	scopePickCursor int
	scopeMode       bool // true until operator picks "other…"

	// v1.13.0-rc12 — Protection preset picker (step 7 post-rc13).
	// Same shape as scopePresets. protectedChoice is set from the
	// picker; passphraseBuf is the masked text input used when
	// protectedChoice is true.
	protectPickCursor int
	protectedChoice   bool
	passphraseBuf     strings.Builder

	// v1.13.0-rc13 — Kind preset picker (step 1). The kind drives the
	// label + behavior of the KindSlot step (step 3). urlBuf is reused
	// across all kinds — its SEMANTIC meaning changes:
	//   api  → _BASE_URL
	//   cli  → _CMD (binary name)
	//   mcp  → _MCP_URL or _MCP_CMD
	//   other → ignored (step is skipped)
	kindPickCursor int
	kindChoice     string // IntegrationKind* value picked by the user

	// v1.13.0-rc15 — Probe preset picker (step 4). Only visited when
	// kind=api AND the KindSlot (base URL) is non-empty, OR kind=mcp
	// AND the KindSlot is a URL. probeChoice becomes --probe-endpoints
	// at save time.
	probePickCursor int
	probeChoice     bool

	err   string
	flash string
	done  bool
}

// scopePresets is the common-case menu offered on the scope-note
// step of addIntegrationView. The last entry drops the operator
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
	{"api", vault.IntegrationKindAPI, "HTTP service — token sent to a base URL (default)"},
	{"cli", vault.IntegrationKindCLI, "command-line tool — token exported to a binary's env"},
	{"mcp", vault.IntegrationKindMCP, "Model Context Protocol server — URL or stdio launcher"},
	{"other", vault.IntegrationKindOther, "unspecified — only the token is exported"},
}

// v1.13.0-rc15 — probePresets drives the opt-in endpoints discovery
// step. "no" default — DOP never auto-fetches without an explicit yes.
var probePresets = []struct {
	label string
	value bool
	hint  string
}{
	{"no", false, "default — only the URL you entered gets stored"},
	{"yes", true, "scan common OpenAPI paths (or MCP tools/list) and stamp the result"},
}

// probeApplicable reports whether the probe step should be visited
// for the current kind + KindSlot buffer. Returns false for cli/other
// and for api/mcp when the KindSlot is empty.
func probeApplicable(kind, urlBuf string) bool {
	url := strings.TrimSpace(urlBuf)
	if url == "" {
		return false
	}
	switch kind {
	case vault.IntegrationKindAPI:
		return strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")
	case vault.IntegrationKindMCP:
		return strings.HasPrefix(url, "http://") || strings.HasPrefix(url, "https://")
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
		return "MCP URL (or stdio cmd)", "either an HTTP URL or a launcher cmd like `npx my-mcp`"
	case vault.IntegrationKindOther:
		return "(no extra config)", "other kind — this row is skipped"
	default: // api, empty
		return "Base URL", "optional — sets an env var like NOTION_BASE_URL"
	}
}

func newAddIntegrationView(c *admin.Client, p *config.Paths) *addIntegrationView {
	v := &addIntegrationView{
		client:      c,
		paths:       p,
		serviceMode: true,
		scopeMode:   true,
		// v1.13.0-rc13 — default kind is api (matches 99% of existing use
		// and keeps the "just enter through the form" flow unchanged).
		kindChoice: vault.IntegrationKindAPI,
	}
	v.loadExistingServices()
	return v
}

// loadExistingServices populates existingServices from the vault so
// the step-0 picker can offer "pick a service you already have"
// alongside the "+ Create new…" entry.
func (v *addIntegrationView) loadExistingServices() {
	if v.client == nil {
		return
	}
	vlt, _, err := loadVaultForListing(v.client, v.paths)
	if err != nil || vlt == nil {
		return
	}
	for name := range vlt.Integrations {
		v.existingServices = append(v.existingServices, name)
	}
	sort.Strings(v.existingServices)
}
func (v *addIntegrationView) Init() tea.Cmd { return nil }
func (v *addIntegrationView) Done() bool    { return v.done }
func (v *addIntegrationView) Flash() string { return v.flash }

type integrationAddedMsg struct{ err string }

func (v *addIntegrationView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch mm := msg.(type) {
	case integrationAddedMsg:
		if mm.err != "" {
			v.err = mm.err
			v.step = integAddStepSave
			return v, nil
		}
		v.step = integAddStepDone
	case tea.KeyMsg:
		switch mm.String() {
		case "esc", "ctrl+c":
			v.done = true
			return v, nil
		}
		if v.step == integAddStepDone {
			v.done = true
			v.flash = "integration saved · synced with team"
			return v, nil
		}
		// v1.13.0-rc13 — step 1 (Kind) is a preset picker. Enter commits
		// the choice and advances to Description. Up/down moves within
		// the preset list.
		if v.step == integAddStepKind {
			switch mm.String() {
			case "up", "k":
				if v.kindPickCursor > 0 {
					v.kindPickCursor--
				}
			case "down", "j":
				if v.kindPickCursor < len(kindPresets)-1 {
					v.kindPickCursor++
				}
			case "enter":
				v.kindChoice = kindPresets[v.kindPickCursor].value
				v.err = ""
				v.step = integAddStepDesc
				return v, nil
			}
			return v, nil
		}
		// v1.13.0-rc7 — step 5 (scope note) is a preset picker unless
		// the operator picked "other…". Mirrors rc5's expiry picker.
		if v.step == integAddStepScope && v.scopeMode {
			switch mm.String() {
			case "up", "k":
				if v.scopePickCursor > 0 {
					v.scopePickCursor--
				}
			case "down", "j":
				if v.scopePickCursor < len(scopePresets)-1 {
					v.scopePickCursor++
				}
			case "enter":
				sel := scopePresets[v.scopePickCursor]
				if sel.value == "" {
					// "other…" — drop into free-text input.
					v.scopeMode = false
					v.scopeBuf.Reset()
					return v, nil
				}
				v.scopeBuf.Reset()
				v.scopeBuf.WriteString(sel.value)
				v.step = integAddStepProtect
				return v, nil
			}
			return v, nil
		}
		// v1.13.0-rc12 — step 6 (Protection) is a two-item preset picker.
		if v.step == integAddStepProtect {
			switch mm.String() {
			case "up", "k":
				if v.protectPickCursor > 0 {
					v.protectPickCursor--
				}
			case "down", "j":
				if v.protectPickCursor < len(protectionPresets)-1 {
					v.protectPickCursor++
				}
			case "enter":
				sel := protectionPresets[v.protectPickCursor]
				v.protectedChoice = sel.value
				if sel.value {
					v.step = integAddStepPassphrase
					v.passphraseBuf.Reset()
				} else {
					v.step = integAddStepSave
				}
				return v, nil
			}
			return v, nil
		}
		// v1.13.0-rc15 — step 4 (Probe) is a two-item preset picker.
		// Only visited when probeApplicable(kind, urlBuf). On enter,
		// commits the choice and advances to Credential name.
		if v.step == integAddStepProbe {
			switch mm.String() {
			case "up", "k":
				if v.probePickCursor > 0 {
					v.probePickCursor--
				}
			case "down", "j":
				if v.probePickCursor < len(probePresets)-1 {
					v.probePickCursor++
				}
			case "enter":
				v.probeChoice = probePresets[v.probePickCursor].value
				v.err = ""
				v.step = integAddStepCred
				v.prefillIfNeeded()
				return v, nil
			}
			return v, nil
		}
		// v1.13.0-rc12 — step 7 (passphrase) is a masked text input,
		// only visited when protection = protected. Enter advances to
		// Save; empty passphrase is refused.
		if v.step == integAddStepPassphrase {
			switch mm.String() {
			case "enter":
				if v.passphraseBuf.Len() == 0 {
					v.err = "passphrase required for protected integrations"
					return v, nil
				}
				v.err = ""
				v.step = integAddStepSave
				return v, nil
			case "backspace":
				s := v.passphraseBuf.String()
				if len(s) > 0 {
					v.passphraseBuf.Reset()
					v.passphraseBuf.WriteString(s[:len(s)-1])
				} else {
					// Empty + backspace → return to protection picker.
					v.step = integAddStepProtect
				}
				return v, nil
			default:
				if len(mm.Runes) > 0 {
					v.passphraseBuf.WriteString(string(mm.Runes))
				}
			}
			return v, nil
		}
		// v1.13.0-rc6 — step 0 is a service picker (unless the user
		// opted into text-input via "+ Create new…").
		if v.step == integAddStepName && v.serviceMode {
			total := len(v.existingServices) + 1 // +1 for "+ Create new…"
			switch mm.String() {
			case "up", "k":
				if v.servicePickCursor > 0 {
					v.servicePickCursor--
				}
			case "down", "j":
				if v.servicePickCursor < total-1 {
					v.servicePickCursor++
				}
			case "enter":
				if v.servicePickCursor == 0 {
					// "+ Create new…" — drop into text input.
					v.serviceMode = false
					v.nameBuf.Reset()
					return v, nil
				}
				// Pick an existing service — advance to credential name.
				// v1.13.0-rc13 — inherit the existing integration's kind
				// so the Kind step isn't re-prompted when just adding a
				// new credential to a service we already know about.
				svc := v.existingServices[v.servicePickCursor-1]
				v.nameBuf.Reset()
				v.nameBuf.WriteString(svc)
				if vlt, _, err := loadVaultForListing(v.client, v.paths); err == nil && vlt != nil {
					if integ, ok := vlt.Integrations[svc]; ok {
						v.kindChoice = vault.IntegrationKindOf(integ)
					}
				}
				v.step = integAddStepCred
				v.prefillIfNeeded()
				return v, nil
			}
			return v, nil
		}
		switch mm.String() {
		case "enter":
			return v.advance()
		case "tab", "down":
			if v.step < integAddStepSave {
				v.step++
				v.prefillIfNeeded()
			}
		case "shift+tab", "up":
			if v.step > integAddStepName {
				v.step--
			}
		case "backspace":
			buf := v.curBuf()
			s := buf.String()
			if len(s) > 0 {
				buf.Reset()
				buf.WriteString(s[:len(s)-1])
			} else if v.step == integAddStepName && !v.serviceMode {
				// Empty name + backspace returns to the service picker.
				v.serviceMode = true
			} else if v.step == integAddStepScope && !v.scopeMode {
				// v1.13.0-rc7 — empty scope + backspace returns to picker.
				v.scopeMode = true
			}
			if v.step == integAddStepCred {
				v.credEdited = true
			}
		default:
			if len(mm.Runes) > 0 && v.step >= integAddStepName && v.step <= integAddStepScope {
				v.curBuf().WriteString(string(mm.Runes))
				if v.step == integAddStepCred {
					v.credEdited = true
				}
			}
		}
	}
	return v, nil
}

func (v *addIntegrationView) curBuf() *strings.Builder {
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
	case integAddStepScope:
		return &v.scopeBuf
	}
	var scratch strings.Builder
	return &scratch
}

// prefillIfNeeded seeds the credential-name buffer with the service
// name the first time we arrive at that step. The operator can still
// edit it — but the default is what most single-credential services
// need, and it makes the redundancy ("why two names?") obvious.
func (v *addIntegrationView) prefillIfNeeded() {
	if v.step == integAddStepCred && v.credBuf.Len() == 0 && !v.credEdited {
		v.credBuf.WriteString(strings.TrimSpace(v.nameBuf.String()))
	}
}

func (v *addIntegrationView) advance() (tea.Model, tea.Cmd) {
	switch v.step {
	case integAddStepName:
		if strings.TrimSpace(v.nameBuf.String()) == "" {
			v.err = "service name is required"
			return v, nil
		}
		v.err = ""
		v.step = integAddStepKind
	case integAddStepKind:
		// Enter outside the picker loop (e.g. after a tab-forward)
		// commits whatever the cursor is on. The picker loop handles the
		// normal case.
		if v.kindChoice == "" {
			v.kindChoice = kindPresets[v.kindPickCursor].value
		}
		v.err = ""
		v.step = integAddStepDesc
	case integAddStepDesc:
		v.err = ""
		// v1.13.0-rc13 — "other" kind has no kind-specific slot;
		// skip straight to the credential name.
		if v.kindChoice == vault.IntegrationKindOther {
			v.step = integAddStepCred
			v.prefillIfNeeded()
		} else {
			v.step = integAddStepKindSlot
		}
	case integAddStepKindSlot:
		v.err = ""
		// v1.13.0-rc15 — route to Probe step only when applicable.
		// Otherwise skip straight to Cred, preserving the pre-rc15 flow.
		if probeApplicable(v.kindChoice, v.urlBuf.String()) {
			v.step = integAddStepProbe
		} else {
			v.step = integAddStepCred
			v.prefillIfNeeded()
		}
	case integAddStepProbe:
		v.err = ""
		v.step = integAddStepCred
		v.prefillIfNeeded()
	case integAddStepCred:
		if strings.TrimSpace(v.credBuf.String()) == "" {
			v.err = "credential name is required"
			return v, nil
		}
		v.err = ""
		v.step = integAddStepValue
	case integAddStepValue:
		if strings.TrimSpace(v.valueBuf.String()) == "" {
			v.err = "credential value is required"
			return v, nil
		}
		v.err = ""
		v.step = integAddStepScope
	case integAddStepScope:
		v.err = ""
		v.step = integAddStepProtect
	case integAddStepProtect:
		// Non-picker path (tab/enter in text mode) — fall through to Save
		// using whatever was last picked (defaults to default/unrestricted).
		v.err = ""
		if v.protectedChoice {
			v.step = integAddStepPassphrase
		} else {
			v.step = integAddStepSave
		}
	case integAddStepPassphrase:
		if v.passphraseBuf.Len() == 0 {
			v.err = "passphrase required for protected integrations"
			return v, nil
		}
		v.err = ""
		v.step = integAddStepSave
	case integAddStepSave:
		v.step = integAddStepRun
		return v, v.save()
	}
	return v, nil
}

func (v *addIntegrationView) save() tea.Cmd {
	name := strings.TrimSpace(v.nameBuf.String())
	desc := strings.TrimSpace(v.descBuf.String())
	url := strings.TrimSpace(v.urlBuf.String())
	cred := strings.TrimSpace(v.credBuf.String())
	value := strings.TrimSpace(v.valueBuf.String())
	scope := strings.TrimSpace(v.scopeBuf.String())
	if scope == "" {
		scope = "-"
	}
	// v1.13.0-rc12 — capture protected state + passphrase for the
	// subprocess invocation. Passphrase travels via stdin (never on
	// the command line) and only when protection is actually on.
	protected := v.protectedChoice
	passphrase := v.passphraseBuf.String()
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
		if protected {
			args = append(args, "--protected", "--passphrase-stdin")
		}
		cmd := exec.Command(self, args...)
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1")
		if protected {
			cmd.Stdin = strings.NewReader(passphrase + "\n")
		}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return integrationAddedMsg{err: strings.TrimSpace(stderr.String())}
		}
		return integrationAddedMsg{}
	}
}

func (v *addIntegrationView) View() string {
	var b strings.Builder
	b.WriteString(titleSt.Render("Add integration") + "\n")
	b.WriteString(mutedSt.Render("Register a service and one credential for it. You can add more credentials later from the integration list.") + "\n\n")

	if v.step == integAddStepDone {
		b.WriteString(okSt.Render("✓ integration saved") + "\n\n")
		b.WriteString(mutedSt.Render("Next: create a grant that binds a name (like `notion.read`) to this credential,") + "\n")
		b.WriteString(mutedSt.Render("then `Issue token` to hand a bearer to your agent.") + "\n\n")
		b.WriteString(helpSt.Render("any key to return"))
		return b.String()
	}

	// v1.13.0-rc6 — step 0 is a service picker when serviceMode is on.
	// Picks either "+ Create new…" (drops into text input) or an
	// existing service (skips to credential name).
	if v.step == integAddStepName && v.serviceMode {
		b.WriteString(cursorSt.Render("Service") + "\n\n")
		entries := append([]string{"+ Create new service…"}, v.existingServices...)
		for i, label := range entries {
			prefix := "    "
			styled := label
			if i == v.servicePickCursor {
				prefix = "  " + cursorSt.Render("➤ ")
				styled = cursorSt.Render(label)
			}
			if i == 0 {
				b.WriteString(prefix + styled + "\n")
				if len(v.existingServices) > 0 {
					b.WriteString("    " + mutedSt.Render("— or pick an existing service below to add another credential —") + "\n\n")
				} else {
					b.WriteString("\n")
				}
				continue
			}
			b.WriteString(prefix + styled + "\n")
		}
		b.WriteString("\n" + helpSt.Render("↑↓ move · enter select · esc cancel"))
		if v.err != "" {
			b.WriteString("\n" + failSt.Render(v.err))
		}
		return b.String()
	}

	// Rows mirror the Issue Token style — all visible at once, active
	// row highlighted, past rows shown as filled-in.
	// v1.13.0-rc6 — the service-name hint also previews the normalized
	// key that will actually be stored (auto-normalize is silent per
	// the design spec; preview surfaces WHAT will be saved before you
	// save it).
	nameHint := "e.g. notion, github, db-primary"
	if trimmed := strings.TrimSpace(v.nameBuf.String()); trimmed != "" {
		norm := vault.NormalizeIntegrationName(trimmed)
		if norm != trimmed {
			nameHint = fmt.Sprintf("will be saved as %q (auto-normalized)", norm)
		}
	}
	// v1.13.0-rc12 — Protection row value: show the picked label.
	protectionLabel := "default"
	if v.protectedChoice {
		protectionLabel = "protected (owner-locked)"
	}
	// v1.13.0-rc13 — kind-adaptive KindSlot row label/hint.
	kindSlotLbl, kindSlotHint := kindSlotLabel(v.kindChoice)
	// v1.13.0-rc15 — Probe row value.
	probeLabel := "no"
	if v.probeChoice {
		probeLabel = "yes"
	}
	rows := []struct {
		label string
		value string
		hint  string
		mask  bool
	}{
		{"Service name", v.nameBuf.String(), nameHint, false},
		{"Kind", v.kindChoice, "api · cli · mcp · other — shapes what the agent sees", false},
		{"What it's for", v.descBuf.String(), "optional — a one-line description", false},
		{kindSlotLbl, v.urlBuf.String(), kindSlotHint, false},
		{"Scan endpoints doc", probeLabel, "only applies when kind=api or kind=mcp with a URL set", false},
		{"Credential name", v.credBuf.String(), "prefilled from the service name — edit if you'll have multiple credentials", false},
		{"Credential value", v.valueBuf.String(), "the actual API key / token / password", true},
		{"What it can do", v.scopeBuf.String(), "optional — e.g. read-only on /docs", false},
		{"Protection", protectionLabel, "default = any admin can modify; protected = only you (requires passphrase)", false},
		{"Passphrase", strings.Repeat("•", v.passphraseBuf.Len()), "your admin approval passphrase", true},
	}
	for i, r := range rows {
		// v1.13.0-rc7 — hide the scope row inline when the preset
		// picker will render below (otherwise the operator sees both
		// an empty "What it can do:" row AND the picker, which is
		// confusing).
		if i == integAddStepScope && v.step == integAddStepScope && v.scopeMode {
			continue
		}
		// v1.13.0-rc12 — hide the Protection row inline when the
		// preset picker renders below. Also hide the Passphrase row
		// entirely until protection = protected (otherwise it clutters
		// the common path).
		if i == integAddStepProtect && v.step == integAddStepProtect {
			continue
		}
		if i == integAddStepPassphrase && !v.protectedChoice {
			continue
		}
		// v1.13.0-rc13 — hide the Kind row inline when the Kind
		// preset picker renders below. Hide the KindSlot row when
		// kind=other (no kind-specific field for that kind).
		if i == integAddStepKind && v.step == integAddStepKind {
			continue
		}
		if i == integAddStepKindSlot && v.kindChoice == vault.IntegrationKindOther {
			continue
		}
		// v1.13.0-rc15 — hide the Probe row inline when its picker
		// renders below, and skip it entirely when the probe isn't
		// applicable to this kind+URL combination.
		if i == integAddStepProbe && v.step == integAddStepProbe {
			continue
		}
		if i == integAddStepProbe && !probeApplicable(v.kindChoice, v.urlBuf.String()) {
			continue
		}
		style := mutedSt
		if i == v.step {
			style = cursorSt
		}
		b.WriteString(style.Render(r.label) + ": ")
		display := r.value
		if r.mask && !(i == v.step) {
			display = strings.Repeat("•", len(r.value))
		} else if r.mask && i == v.step {
			display = strings.Repeat("•", len(r.value))
		}
		b.WriteString(display)
		if i == v.step {
			b.WriteString(cursorSt.Render("▎"))
		}
		b.WriteString("\n")
		if i == v.step && r.hint != "" {
			b.WriteString("    " + mutedSt.Render(r.hint) + "\n")
		}
	}

	// v1.13.0-rc12 — Protection preset picker on step 7.
	if v.step == integAddStepProtect {
		b.WriteString("\n" + cursorSt.Render("Protection") + "\n")
		for i, p := range protectionPresets {
			prefix := "    "
			label := p.label
			if i == v.protectPickCursor {
				prefix = "  " + cursorSt.Render("➤ ")
				label = cursorSt.Render(p.label)
			}
			b.WriteString(prefix + label + "    " + mutedSt.Render(p.hint) + "\n")
		}
	}

	// v1.13.0-rc13 — Kind preset picker on step 1.
	if v.step == integAddStepKind {
		b.WriteString("\n" + cursorSt.Render("Kind") + "\n")
		for i, p := range kindPresets {
			prefix := "    "
			label := p.label
			if i == v.kindPickCursor {
				prefix = "  " + cursorSt.Render("➤ ")
				label = cursorSt.Render(p.label)
			}
			b.WriteString(prefix + label + "    " + mutedSt.Render(p.hint) + "\n")
		}
	}

	// v1.13.0-rc15 — Probe preset picker on step 4.
	if v.step == integAddStepProbe {
		b.WriteString("\n" + cursorSt.Render("Scan endpoints doc") + "\n")
		for i, p := range probePresets {
			prefix := "    "
			label := p.label
			if i == v.probePickCursor {
				prefix = "  " + cursorSt.Render("➤ ")
				label = cursorSt.Render(p.label)
			}
			b.WriteString(prefix + label + "    " + mutedSt.Render(p.hint) + "\n")
		}
	}

	// v1.13.0-rc7 — scope-note preset picker on step 5.
	if v.step == integAddStepScope && v.scopeMode {
		b.WriteString("\n" + cursorSt.Render("What it can do") + "\n")
		for i, p := range scopePresets {
			prefix := "    "
			label := p.label
			if i == v.scopePickCursor {
				prefix = "  " + cursorSt.Render("➤ ")
				label = cursorSt.Render(p.label)
			}
			b.WriteString(prefix + label + "\n")
		}
	}

	// Save row.
	b.WriteString("\n")
	saveStyle := mutedSt
	if v.step == integAddStepSave {
		saveStyle = cursorSt
	}
	b.WriteString("    " + saveStyle.Render("[ Save ]"))
	if v.step == integAddStepSave {
		b.WriteString("   " + mutedSt.Render("← press enter to save"))
	}
	b.WriteString("\n")

	if v.step == integAddStepRun {
		b.WriteString("\n" + mutedSt.Render("saving…") + "\n")
	}
	if v.err != "" {
		b.WriteString("\n" + failSt.Render(v.err) + "\n")
	}

	b.WriteString("\n" + helpSt.Render("enter next · tab/↑↓ jump between rows · esc cancel"))
	return b.String()
}

// ---------- Add grant ----------

type addGrantView struct {
	client *admin.Client
	paths  *config.Paths

	step        int
	idBuf       strings.Builder
	integration string
	token       string
	envBuf      strings.Builder
	// v1.13.0-rc5 — parity with `dop grant add` (and with grant edit
	// in the TUI): new fields for projects + tags, CSV in the TUI
	// (comma-separated), split by splitCSV at save time.
	projectsBuf strings.Builder
	tagsBuf     strings.Builder

	integrations []string           // list of integration names
	tokensByInt  map[string][]string // upstream tokens per integration
	cursor       int

	err   string
	flash string
	done  bool
}

func newAddGrantView(c *admin.Client, p *config.Paths) *addGrantView {
	v := &addGrantView{client: c, paths: p, tokensByInt: map[string][]string{}}
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

func (v *addGrantView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch mm := msg.(type) {
	case grantAddedMsg:
		if mm.err != "" {
			v.err = mm.err
			// Back to tags step so operator can review before retry.
			v.step = 5
			return v, nil
		}
		v.flash = "grant saved · synced with team"
		v.done = true
		return v, nil
	case tea.KeyMsg:
		switch mm.String() {
		case "esc", "ctrl+c":
			v.done = true
			return v, nil
		}
		switch v.step {
		case 0:
			// grant id
			switch mm.String() {
			case "enter":
				if strings.TrimSpace(v.idBuf.String()) == "" {
					v.err = "grant id required"
					return v, nil
				}
				v.err = ""
				v.step = 1
				v.cursor = 0
			case "backspace":
				s := v.idBuf.String()
				if len(s) > 0 {
					v.idBuf.Reset()
					v.idBuf.WriteString(s[:len(s)-1])
				}
			default:
				if len(mm.Runes) > 0 {
					v.idBuf.WriteString(string(mm.Runes))
				}
			}
		case 1:
			// pick integration
			switch mm.String() {
			case "up", "k":
				if v.cursor > 0 {
					v.cursor--
				}
			case "down", "j":
				if v.cursor < len(v.integrations)-1 {
					v.cursor++
				}
			case "enter":
				if len(v.integrations) == 0 {
					v.err = "no integrations exist yet — add one first"
					return v, nil
				}
				v.integration = v.integrations[v.cursor]
				v.cursor = 0
				v.step = 2
			}
		case 2:
			// pick token within integration
			toks := v.tokensByInt[v.integration]
			switch mm.String() {
			case "up", "k":
				if v.cursor > 0 {
					v.cursor--
				}
			case "down", "j":
				if v.cursor < len(toks)-1 {
					v.cursor++
				}
			case "enter":
				if len(toks) == 0 {
					v.err = "integration has no tokens"
					return v, nil
				}
				v.token = toks[v.cursor]
				v.envBuf.Reset()
				v.envBuf.WriteString(strings.ToUpper(v.integration))
				v.step = 3
			}
		case 3:
			// env prefix (optional — empty = auto-derive + sanitize)
			switch mm.String() {
			case "enter":
				v.step = 4
			case "backspace":
				s := v.envBuf.String()
				if len(s) > 0 {
					v.envBuf.Reset()
					v.envBuf.WriteString(s[:len(s)-1])
				}
			default:
				if len(mm.Runes) > 0 {
					v.envBuf.WriteString(string(mm.Runes))
				}
			}
		case 4:
			// v1.13.0-rc5 — projects (CSV, optional)
			switch mm.String() {
			case "enter":
				v.step = 5
			case "backspace":
				s := v.projectsBuf.String()
				if len(s) > 0 {
					v.projectsBuf.Reset()
					v.projectsBuf.WriteString(s[:len(s)-1])
				}
			default:
				if len(mm.Runes) > 0 {
					v.projectsBuf.WriteString(string(mm.Runes))
				}
			}
		case 5:
			// v1.13.0-rc5 — tags (CSV, optional) + submit
			switch mm.String() {
			case "enter":
				v.step = 6
				return v, v.save()
			case "backspace":
				s := v.tagsBuf.String()
				if len(s) > 0 {
					v.tagsBuf.Reset()
					v.tagsBuf.WriteString(s[:len(s)-1])
				}
			default:
				if len(mm.Runes) > 0 {
					v.tagsBuf.WriteString(string(mm.Runes))
				}
			}
		}
	}
	return v, nil
}

func (v *addGrantView) save() tea.Cmd {
	id := strings.TrimSpace(v.idBuf.String())
	env := strings.TrimSpace(v.envBuf.String())
	projects := strings.TrimSpace(v.projectsBuf.String())
	tags := strings.TrimSpace(v.tagsBuf.String())
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
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return grantAddedMsg{err: strings.TrimSpace(stderr.String())}
		}
		return grantAddedMsg{}
	}
}

func (v *addGrantView) View() string {
	var b strings.Builder
	b.WriteString(titleSt.Render("Add grant") + "\n\n")
	switch v.step {
	case 0:
		b.WriteString(cursorSt.Render("Grant id (e.g. notion.read)") + ":\n")
		b.WriteString("  " + v.idBuf.String() + cursorSt.Render("▎") + "\n")
	case 1:
		b.WriteString(cursorSt.Render("Pick integration") + ":\n\n")
		if len(v.integrations) == 0 {
			b.WriteString(mutedSt.Render("  (no integrations — add one first)") + "\n")
		}
		for i, name := range v.integrations {
			prefix := "  "
			if i == v.cursor {
				prefix = cursorSt.Render("➤ ")
			}
			b.WriteString(prefix + name + "\n")
		}
	case 2:
		b.WriteString(cursorSt.Render("Pick token from "+v.integration) + ":\n\n")
		toks := v.tokensByInt[v.integration]
		if len(toks) == 0 {
			b.WriteString(mutedSt.Render("  (this integration has no upstream tokens)") + "\n")
		}
		for i, tn := range toks {
			prefix := "  "
			if i == v.cursor {
				prefix = cursorSt.Render("➤ ")
			}
			b.WriteString(prefix + tn + "\n")
		}
	case 3:
		b.WriteString(mutedSt.Render("Grant id:      "+v.idBuf.String()) + "\n")
		b.WriteString(mutedSt.Render("Integration:   "+v.integration) + "\n")
		b.WriteString(mutedSt.Render("Token:         "+v.token) + "\n\n")
		b.WriteString(cursorSt.Render("Env prefix (optional — leave empty for auto)") + ":\n")
		b.WriteString("  " + v.envBuf.String() + cursorSt.Render("▎") + "\n")
	case 4:
		// v1.13.0-rc5 — projects (CSV, optional)
		b.WriteString(mutedSt.Render("Grant id:      "+v.idBuf.String()) + "\n")
		b.WriteString(mutedSt.Render("Integration:   "+v.integration) + "\n")
		b.WriteString(mutedSt.Render("Token:         "+v.token) + "\n")
		b.WriteString(mutedSt.Render("Env prefix:    "+displayOr(v.envBuf.String(), "(auto)")) + "\n\n")
		b.WriteString(cursorSt.Render("Projects (comma-separated, optional)") + ":\n")
		b.WriteString("  " + v.projectsBuf.String() + cursorSt.Render("▎") + "\n")
	case 5:
		// v1.13.0-rc5 — tags (CSV, optional) + confirm
		b.WriteString(mutedSt.Render("Grant id:      "+v.idBuf.String()) + "\n")
		b.WriteString(mutedSt.Render("Integration:   "+v.integration) + "\n")
		b.WriteString(mutedSt.Render("Token:         "+v.token) + "\n")
		b.WriteString(mutedSt.Render("Env prefix:    "+displayOr(v.envBuf.String(), "(auto)")) + "\n")
		b.WriteString(mutedSt.Render("Projects:      "+displayOr(v.projectsBuf.String(), "(none)")) + "\n\n")
		b.WriteString(cursorSt.Render("Tags (comma-separated, optional) · enter saves") + ":\n")
		b.WriteString("  " + v.tagsBuf.String() + cursorSt.Render("▎") + "\n")
	case 6:
		b.WriteString("saving…\n")
	}
	b.WriteString("\n" + helpSt.Render("↑↓ move · enter next · esc cancel"))
	if v.err != "" {
		b.WriteString("\n" + failSt.Render(v.err))
	}
	return b.String()
}

// displayOr returns s unless it's empty, in which case fallback is used
// (for compact labels in the review line of multi-step forms).
func displayOr(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}
