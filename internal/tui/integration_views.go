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
	integAddStepName   = 0
	integAddStepDesc   = 1
	integAddStepURL    = 2
	integAddStepCred   = 3
	integAddStepValue  = 4
	integAddStepScope  = 5
	integAddStepSave   = 6
	integAddStepRun    = 7
	integAddStepDone   = 100
	integAddFieldCount = 7 // rows shown (0..6)
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

	err   string
	flash string
	done  bool
}

func newAddIntegrationView(c *admin.Client, p *config.Paths) *addIntegrationView {
	return &addIntegrationView{client: c, paths: p}
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
	case integAddStepURL:
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
		v.step = integAddStepDesc
	case integAddStepDesc:
		v.err = ""
		v.step = integAddStepURL
	case integAddStepURL:
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
	return func() tea.Msg {
		self, _ := os.Executable()
		args := []string{"integration", "add", "--name", name}
		if desc != "" {
			args = append(args, "--description", desc)
		}
		if url != "" {
			args = append(args, "--base-url", url)
		}
		args = append(args, "--token", fmt.Sprintf("%s=%s:%s", cred, value, scope))
		cmd := exec.Command(self, args...)
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1")
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

	// Rows mirror the Issue Token style — all visible at once, active
	// row highlighted, past rows shown as filled-in.
	rows := []struct {
		label string
		value string
		hint  string
		mask  bool
	}{
		{"Service name", v.nameBuf.String(), "e.g. notion, github, db-primary", false},
		{"What it's for", v.descBuf.String(), "optional — a one-line description", false},
		{"Base URL", v.urlBuf.String(), "optional — sets an env var like NOTION_BASE_URL", false},
		{"Credential name", v.credBuf.String(), "prefilled from the service name — edit if you'll have multiple credentials", false},
		{"Credential value", v.valueBuf.String(), "the actual API key / token / password", true},
		{"What it can do", v.scopeBuf.String(), "optional — e.g. read-only on /docs", false},
	}
	for i, r := range rows {
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
			v.step = 3 // back to confirm
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
			// env prefix
			switch mm.String() {
			case "enter":
				v.step = 4
				return v, v.save()
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
		}
	}
	return v, nil
}

func (v *addGrantView) save() tea.Cmd {
	id := strings.TrimSpace(v.idBuf.String())
	env := strings.TrimSpace(v.envBuf.String())
	if env == "" {
		env = strings.ToUpper(v.integration)
	}
	integ := v.integration
	tok := v.token
	return func() tea.Msg {
		self, _ := os.Executable()
		cmd := exec.Command(self, "grant", "add",
			"--id", id,
			"--integration", integ,
			"--token", tok,
			"--env-prefix", env)
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
		b.WriteString(cursorSt.Render("Env prefix") + ":\n")
		b.WriteString("  " + v.envBuf.String() + cursorSt.Render("▎") + "\n")
	case 4:
		b.WriteString("saving…\n")
	}
	if v.err != "" {
		b.WriteString("\n" + failSt.Render(v.err) + "\n")
	}
	b.WriteString("\n" + helpSt.Render("↑↓ move · enter select · esc cancel"))
	return b.String()
}
