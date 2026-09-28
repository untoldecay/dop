package views

import (
	"fmt"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/fray/dop/internal/tokenio"
	"github.com/fray/dop/internal/tui/styles"
)

// AddIntegrationModel walks the user through a guided form to add an
// integration + its tokens + auto-generated grants. On save it decrypts
// the vault, mutates the tree, and re-encrypts via tokenio.SavePlain.
//
// Form fields (advance with Enter, back with esc):
//   0. integration name          (e.g. notion)
//   1. description
//   2. base_url
//   3. env prefix                (default: uppercased name)
//   4. token name #1             (e.g. read)
//   5. token value #1
//   6. token scope_note #1       (drives sensitive-grant gate later)
//   7. (offer: "add another token?" y/n; loop back to 4 if yes)
//   8. confirmation screen with a summary → save / cancel
type AddIntegrationModel struct {
	vaultPath string

	step   int
	fields addIntFields
	tokens []tokenDraft
	cur    tokenDraft
	addMoreTokens bool

	// UI state
	input      strings.Builder
	message    string
	done       bool
	saved      bool
}

type addIntFields struct {
	name        string
	description string
	baseURL     string
	envPrefix   string
}

type tokenDraft struct {
	name      string
	value     string
	scopeNote string
}

func NewAddIntegration(vaultPath string) *AddIntegrationModel {
	return &AddIntegrationModel{vaultPath: vaultPath}
}

func (m *AddIntegrationModel) Init() tea.Cmd { return nil }
func (m *AddIntegrationModel) Done() bool    { return m.done }

func (m *AddIntegrationModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	km, ok := msg.(tea.KeyMsg)
	if !ok {
		return m, nil
	}
	switch km.String() {
	case "ctrl+c":
		m.done = true
		return m, nil
	case "esc":
		m.done = true
		return m, nil
	}
	// Confirmation screen (post-form).
	if m.step == 100 {
		switch km.String() {
		case "y", "Y", "enter":
			if err := m.save(); err != nil {
				m.message = "save failed: " + err.Error()
				return m, nil
			}
			m.saved = true
			m.step = 101 // success screen
			return m, nil
		case "n", "N", "q":
			m.done = true
		}
		return m, nil
	}
	// Success screen.
	if m.step == 101 {
		m.done = true
		return m, nil
	}
	// "Add another token?" prompt.
	if m.step == 7 {
		switch km.String() {
		case "y", "Y":
			m.tokens = append(m.tokens, m.cur)
			m.cur = tokenDraft{}
			m.step = 4
			m.input.Reset()
			return m, nil
		case "n", "N", "enter":
			m.tokens = append(m.tokens, m.cur)
			m.step = 100
			return m, nil
		}
		return m, nil
	}
	// Text-input steps.
	switch km.String() {
	case "enter":
		m.commitCurrent()
	case "backspace":
		s := m.input.String()
		if len(s) > 0 {
			m.input.Reset()
			m.input.WriteString(s[:len(s)-1])
		}
	default:
		// runes only
		if len(km.Runes) > 0 {
			m.input.WriteString(string(km.Runes))
		}
	}
	return m, nil
}

func (m *AddIntegrationModel) commitCurrent() {
	val := strings.TrimSpace(m.input.String())
	switch m.step {
	case 0:
		if val == "" {
			m.message = "name is required"
			return
		}
		m.fields.name = val
	case 1:
		m.fields.description = val
	case 2:
		if val == "" {
			m.message = "base URL is required (empty is OK if the service doesn't need one, type '-' to skip)"
			return
		}
		if val == "-" {
			val = ""
		}
		m.fields.baseURL = val
	case 3:
		if val == "" {
			val = strings.ToUpper(m.fields.name)
		}
		m.fields.envPrefix = val
	case 4:
		if val == "" {
			m.message = "token name is required"
			return
		}
		m.cur.name = val
	case 5:
		if val == "" {
			m.message = "token value is required"
			return
		}
		m.cur.value = val
	case 6:
		if val == "" {
			val = "read-only"
		}
		m.cur.scopeNote = val
	}
	m.input.Reset()
	m.message = ""
	m.step++
}

func (m *AddIntegrationModel) View() string {
	var b strings.Builder
	b.WriteString(styles.Title.Render("Add integration") + "\n\n")

	if m.step == 101 {
		b.WriteString(styles.Status["ok"].Render("✓ integration saved and vault re-encrypted") + "\n\n")
		b.WriteString(styles.Help.Render("any key to return to the menu"))
		return b.String()
	}

	// Summary preview (always visible below the form for context).
	summary := m.summary()

	if m.step == 100 {
		b.WriteString(summary)
		b.WriteString("\n" + styles.Muted.Render("Ready to save. This decrypts the vault, adds the integration, and re-encrypts.") + "\n\n")
		if m.message != "" {
			b.WriteString(styles.Status["fail"].Render(m.message) + "\n\n")
		}
		b.WriteString(styles.Help.Render("y save · n cancel · esc back"))
		return b.String()
	}

	if m.step == 7 {
		b.WriteString(summary + "\n")
		b.WriteString(styles.FormLabel.Render("Add another token to this integration?") + "\n")
		b.WriteString(styles.Help.Render("y add another · n / enter done · esc cancel"))
		return b.String()
	}

	label := m.stepLabel()
	b.WriteString(styles.FormLabel.Render(label) + "\n")
	b.WriteString(styles.FormInput.Render("› "+m.input.String()) + "\n")
	if m.message != "" {
		b.WriteString("\n" + styles.Status["warn"].Render(m.message) + "\n")
	}
	b.WriteString("\n" + summary)
	b.WriteString("\n" + styles.Help.Render("enter next · backspace edit · esc cancel"))
	return b.String()
}

func (m *AddIntegrationModel) stepLabel() string {
	switch m.step {
	case 0:
		return "Integration name (lowercase, e.g. `notion`, `boiler`, `github`)"
	case 1:
		return "Description (one line, freeform — press enter to skip)"
	case 2:
		return "Base URL (e.g. https://api.notion.com/v1 — enter `-` to skip)"
	case 3:
		return fmt.Sprintf("Env var prefix (default: %s)", strings.ToUpper(m.fields.name))
	case 4:
		return "Token name (e.g. `read`, `write`, `admin`)"
	case 5:
		return "Token VALUE (the actual bearer from the upstream service — kept encrypted at rest)"
	case 6:
		return "Scope note (default: `read-only`; use `read+write` / `admin — DANGEROUS` to mark sensitive)"
	}
	return "…"
}

func (m *AddIntegrationModel) summary() string {
	if m.fields.name == "" {
		return ""
	}
	var b strings.Builder
	b.WriteString(styles.FormLabel.Render("So far:") + "\n")
	b.WriteString(fmt.Sprintf("  integration: %s\n", styles.FormInput.Render(m.fields.name)))
	if m.fields.description != "" {
		b.WriteString(fmt.Sprintf("  description: %s\n", m.fields.description))
	}
	if m.fields.baseURL != "" {
		b.WriteString(fmt.Sprintf("  base_url: %s\n", m.fields.baseURL))
	}
	if m.fields.envPrefix != "" {
		b.WriteString(fmt.Sprintf("  env prefix: %s\n", m.fields.envPrefix))
	}
	all := append([]tokenDraft(nil), m.tokens...)
	if m.cur.name != "" {
		all = append(all, m.cur)
	}
	for _, t := range all {
		note := t.scopeNote
		if note == "" {
			note = "read-only"
		}
		masked := "•••"
		if t.value != "" {
			masked = fmt.Sprintf("%s%s", string(t.value[0]), strings.Repeat("•", 4))
		}
		b.WriteString(fmt.Sprintf("  token %s: value=%s scope=%s\n", t.name, masked, note))
	}
	return b.String()
}

// save decrypts the vault, injects the new integration + auto-grants,
// re-encrypts.
func (m *AddIntegrationModel) save() error {
	if m.vaultPath == "" {
		return fmt.Errorf("no vault attached — run `dop init --vault ...` first")
	}
	plain, err := tokenio.LoadPlain(m.vaultPath)
	if err != nil {
		return err
	}
	root, err := tokenio.ParseTree(plain)
	if err != nil {
		return err
	}
	injectIntegration(root, m.fields, m.tokens)
	out, err := tokenio.EmitTree(root)
	if err != nil {
		return err
	}
	return tokenio.SavePlain(m.vaultPath, out)
}
