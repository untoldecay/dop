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

// ---------- Add integration ----------

type integrationTokenDraft struct {
	name, value, scope string
}

type addIntegrationView struct {
	client *admin.Client
	paths  *config.Paths

	step    int
	nameBuf strings.Builder
	descBuf strings.Builder
	urlBuf  strings.Builder
	// The currently-active token's field buffers. Reset when a token is
	// finalized and we start collecting the next one.
	tokenNameBuf  strings.Builder
	tokenValueBuf strings.Builder
	tokenScopeBuf strings.Builder
	tokens        []integrationTokenDraft
	err           string
	flash         string
	done          bool

	// step 4 = "add another token?" y/n
	// step 5 = confirm
	// step 6 = running
	// step 100 = success
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
			v.step = 5 // back to confirm
			return v, nil
		}
		v.step = 100
	case tea.KeyMsg:
		switch mm.String() {
		case "esc", "ctrl+c":
			v.done = true
			return v, nil
		}
		if v.step == 100 {
			v.done = true
			v.flash = "integration saved"
			return v, nil
		}
		if v.step == 4 {
			switch mm.String() {
			case "y", "Y":
				// buffers already reset in advance(); go back to token name.
				v.step = 1
			case "n", "N", "enter":
				v.step = 5 // confirm
			}
			return v, nil
		}
		if v.step == 5 {
			switch mm.String() {
			case "y", "Y", "enter":
				v.step = 6
				return v, v.save()
			case "n", "N":
				v.done = true
			}
			return v, nil
		}
		switch mm.String() {
		case "enter":
			return v.advance()
		case "backspace":
			buf := v.curBuf()
			s := buf.String()
			if len(s) > 0 {
				buf.Reset()
				buf.WriteString(s[:len(s)-1])
			}
		default:
			if len(mm.Runes) > 0 {
				v.curBuf().WriteString(string(mm.Runes))
			}
		}
	}
	return v, nil
}

// curBuf returns the buffer for the currently-active text-input step.
// Never returns a copy — each buffer lives on the struct and outlives
// the caller.
func (v *addIntegrationView) curBuf() *strings.Builder {
	switch v.step {
	case 0:
		return &v.nameBuf
	case 10:
		return &v.descBuf
	case 11:
		return &v.urlBuf
	case 1:
		return &v.tokenNameBuf
	case 2:
		return &v.tokenValueBuf
	case 3:
		return &v.tokenScopeBuf
	}
	// Steps 4/5/6/100 aren't text-input; the input handler ignores
	// them. Return a throwaway.
	var scratch strings.Builder
	return &scratch
}

func (v *addIntegrationView) advance() (tea.Model, tea.Cmd) {
	switch v.step {
	case 0:
		if strings.TrimSpace(v.nameBuf.String()) == "" {
			v.err = "name required"
			return v, nil
		}
		v.err = ""
		v.step = 10
	case 10:
		v.step = 11
	case 11:
		v.step = 1 // start collecting the first token
	case 1:
		if strings.TrimSpace(v.tokenNameBuf.String()) == "" {
			v.err = "token name required"
			return v, nil
		}
		v.err = ""
		v.step = 2
	case 2:
		if strings.TrimSpace(v.tokenValueBuf.String()) == "" {
			v.err = "token value required"
			return v, nil
		}
		v.err = ""
		v.step = 3
	case 3:
		scope := strings.TrimSpace(v.tokenScopeBuf.String())
		if scope == "" {
			scope = "read-only"
		}
		v.tokens = append(v.tokens, integrationTokenDraft{
			name:  strings.TrimSpace(v.tokenNameBuf.String()),
			value: strings.TrimSpace(v.tokenValueBuf.String()),
			scope: scope,
		})
		v.tokenNameBuf.Reset()
		v.tokenValueBuf.Reset()
		v.tokenScopeBuf.Reset()
		v.step = 4
	}
	return v, nil
}

func (v *addIntegrationView) save() tea.Cmd {
	name := strings.TrimSpace(v.nameBuf.String())
	desc := strings.TrimSpace(v.descBuf.String())
	url := strings.TrimSpace(v.urlBuf.String())
	tokens := v.tokens
	return func() tea.Msg {
		self, _ := os.Executable()
		args := []string{"integration", "add", "--name", name}
		if desc != "" {
			args = append(args, "--description", desc)
		}
		if url != "" {
			args = append(args, "--base-url", url)
		}
		for _, t := range tokens {
			args = append(args, "--token", fmt.Sprintf("%s=%s:%s", t.name, t.value, t.scope))
		}
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
	b.WriteString(titleSt.Render("Add integration") + "\n\n")
	if v.step == 100 {
		b.WriteString(okSt.Render("✓ integration saved") + "\n\n")
		b.WriteString(mutedSt.Render("You'll typically add a grant next (`dop grant add`).") + "\n\n")
		b.WriteString(helpSt.Render("any key to return"))
		return b.String()
	}
	// Summary above the prompt.
	if v.nameBuf.Len() > 0 {
		b.WriteString(mutedSt.Render("Integration: "+v.nameBuf.String()) + "\n")
	}
	if v.descBuf.Len() > 0 {
		b.WriteString(mutedSt.Render("Description: "+v.descBuf.String()) + "\n")
	}
	if v.urlBuf.Len() > 0 {
		b.WriteString(mutedSt.Render("Base URL:    "+v.urlBuf.String()) + "\n")
	}
	for i, t := range v.tokens {
		b.WriteString(mutedSt.Render(fmt.Sprintf("Token %d:     %s (scope=%s)", i+1, t.name, t.scope)) + "\n")
	}
	if v.nameBuf.Len() > 0 || len(v.tokens) > 0 {
		b.WriteString("\n")
	}

	prompt := ""
	value := ""
	switch v.step {
	case 0:
		prompt = "Integration name (e.g. notion, boiler)"
		value = v.nameBuf.String()
	case 10:
		prompt = "Description (optional — press enter to skip)"
		value = v.descBuf.String()
	case 11:
		prompt = "Base URL (optional, e.g. https://api.notion.com/v1)"
		value = v.urlBuf.String()
	case 1:
		prompt = "Token name (e.g. read, write, admin)"
		value = v.tokenNameBuf.String()
	case 2:
		prompt = "Token VALUE (the real bearer from the upstream service)"
		value = v.tokenValueBuf.String()
	case 3:
		prompt = "Scope note (default: read-only)"
		value = v.tokenScopeBuf.String()
	case 4:
		b.WriteString("Add another token? (y/n)\n")
		if v.err != "" {
			b.WriteString("\n" + failSt.Render(v.err) + "\n")
		}
		b.WriteString("\n" + helpSt.Render("y add another · n / enter done · esc cancel"))
		return b.String()
	case 5:
		b.WriteString("Ready to save? (y/n)\n")
		if v.err != "" {
			b.WriteString("\n" + failSt.Render(v.err) + "\n")
		}
		b.WriteString("\n" + helpSt.Render("y save · n cancel · esc back"))
		return b.String()
	case 6:
		b.WriteString("saving…")
		return b.String()
	}
	b.WriteString(cursorSt.Render(prompt) + "\n")
	b.WriteString("  " + value + cursorSt.Render("▎") + "\n")
	if v.err != "" {
		b.WriteString("\n" + failSt.Render(v.err) + "\n")
	}
	b.WriteString("\n" + helpSt.Render("enter next · esc cancel"))
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
		v.flash = "grant saved"
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
