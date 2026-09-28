package views

import (
	"fmt"
	"sort"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/fray/dop/internal/tokenio"
	"github.com/fray/dop/internal/tui/styles"
)

// IssueTokenModel walks the user through: pick grants from the vault,
// name the token, confirm (extra prompt if any grant is sensitive),
// save, display the bearer once.
type IssueTokenModel struct {
	vaultPath string

	grantIDs   []string          // all grants in the vault (sorted)
	selected   map[string]bool   // grant IDs the user has toggled on
	sensitive  map[string]bool   // subset that require confirmation
	cursor     int
	step       int // 0=pick grants, 1=name+note, 2=confirm(if sensitive), 3=display bearer
	nameInput  strings.Builder
	noteInput  strings.Builder
	fieldIdx   int // 0=name, 1=note
	loaded     bool
	loadErr    string
	bearer     string
	saveErr    string
	done       bool
}

func NewIssueToken(vaultPath string) *IssueTokenModel {
	return &IssueTokenModel{
		vaultPath: vaultPath,
		selected:  map[string]bool{},
	}
}

func (m *IssueTokenModel) Init() tea.Cmd { return m.loadCmd() }
func (m *IssueTokenModel) Done() bool    { return m.done }

func (m *IssueTokenModel) loadCmd() tea.Cmd {
	return func() tea.Msg {
		if m.vaultPath == "" {
			return issueLoadedMsg{err: "no vault attached — run `dop init --vault ...` first"}
		}
		plain, err := tokenio.LoadPlain(m.vaultPath)
		if err != nil {
			return issueLoadedMsg{err: err.Error()}
		}
		root, err := tokenio.ParseTree(plain)
		if err != nil {
			return issueLoadedMsg{err: err.Error()}
		}
		known := tokenio.KnownGrants(root)
		ids := make([]string, 0, len(known))
		for k := range known {
			ids = append(ids, k)
		}
		sort.Strings(ids)
		return issueLoadedMsg{grantIDs: ids}
	}
}

type issueLoadedMsg struct {
	grantIDs []string
	err      string
}

func (m *IssueTokenModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch mm := msg.(type) {
	case issueLoadedMsg:
		m.loaded = true
		m.grantIDs = mm.grantIDs
		m.loadErr = mm.err
		return m, nil
	case tea.KeyMsg:
		switch mm.String() {
		case "ctrl+c", "esc":
			m.done = true
			return m, nil
		}
		switch m.step {
		case 0:
			m.updatePickGrants(mm)
		case 1:
			m.updateForm(mm)
		case 2:
			m.updateConfirm(mm)
		case 3:
			m.done = true
		}
	}
	return m, nil
}

func (m *IssueTokenModel) updatePickGrants(km tea.KeyMsg) {
	switch km.String() {
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(m.grantIDs)-1 {
			m.cursor++
		}
	case " ", "space":
		if len(m.grantIDs) > 0 {
			id := m.grantIDs[m.cursor]
			m.selected[id] = !m.selected[id]
		}
	case "enter":
		if m.anySelected() {
			m.step = 1
			m.fieldIdx = 0
		}
	}
}

func (m *IssueTokenModel) updateForm(km tea.KeyMsg) {
	switch km.String() {
	case "tab":
		if m.fieldIdx == 0 {
			m.fieldIdx = 1
		} else {
			m.fieldIdx = 0
		}
	case "enter":
		if strings.TrimSpace(m.nameInput.String()) == "" {
			return
		}
		m.computeSensitive()
		if len(m.sensitive) > 0 {
			m.step = 2
		} else {
			if err := m.save(); err != nil {
				m.saveErr = err.Error()
				return
			}
			m.step = 3
		}
	case "backspace":
		buf := m.currentBuf()
		s := buf.String()
		if len(s) > 0 {
			buf.Reset()
			buf.WriteString(s[:len(s)-1])
		}
	default:
		if len(km.Runes) > 0 {
			m.currentBuf().WriteString(string(km.Runes))
		}
	}
}

func (m *IssueTokenModel) updateConfirm(km tea.KeyMsg) {
	switch km.String() {
	case "y", "Y", "enter":
		if err := m.save(); err != nil {
			m.saveErr = err.Error()
			return
		}
		m.step = 3
	case "n", "N", "q":
		m.done = true
	}
}

func (m *IssueTokenModel) currentBuf() *strings.Builder {
	if m.fieldIdx == 0 {
		return &m.nameInput
	}
	return &m.noteInput
}

func (m *IssueTokenModel) anySelected() bool {
	for _, v := range m.selected {
		if v {
			return true
		}
	}
	return false
}

func (m *IssueTokenModel) selectedList() []string {
	var out []string
	for _, id := range m.grantIDs {
		if m.selected[id] {
			out = append(out, id)
		}
	}
	return out
}

func (m *IssueTokenModel) computeSensitive() {
	m.sensitive = map[string]bool{}
	plain, err := tokenio.LoadPlain(m.vaultPath)
	if err != nil {
		return
	}
	root, err := tokenio.ParseTree(plain)
	if err != nil {
		return
	}
	sensitive := tokenio.SensitiveGrants(root, m.selectedList())
	for _, s := range sensitive {
		m.sensitive[s] = true
	}
}

func (m *IssueTokenModel) save() error {
	plain, err := tokenio.LoadPlain(m.vaultPath)
	if err != nil {
		return err
	}
	root, err := tokenio.ParseTree(plain)
	if err != nil {
		return err
	}
	bearer, err := tokenio.TokenBearer()
	if err != nil {
		return err
	}
	name := strings.TrimSpace(m.nameInput.String())
	if name == "" {
		name = "token-" + bearer[4:12]
	}
	rec := tokenio.TokenRecord{
		Name:   name,
		Grants: m.selectedList(),
		Note:   strings.TrimSpace(m.noteInput.String()),
	}
	if err := tokenio.AddAuthToken(root, bearer, rec, ""); err != nil {
		return err
	}
	out, err := tokenio.EmitTree(root)
	if err != nil {
		return err
	}
	if err := tokenio.SavePlain(m.vaultPath, out); err != nil {
		return err
	}
	m.bearer = bearer
	return nil
}

func (m *IssueTokenModel) View() string {
	var b strings.Builder
	b.WriteString(styles.Title.Render("Issue token") + "\n\n")

	if !m.loaded {
		b.WriteString(styles.Muted.Render("loading grants…") + "\n")
		return b.String()
	}
	if m.loadErr != "" {
		b.WriteString(styles.Status["fail"].Render(m.loadErr) + "\n\n")
		b.WriteString(styles.Help.Render("esc back"))
		return b.String()
	}

	switch m.step {
	case 0:
		b.WriteString(styles.FormLabel.Render("Pick the grants this token unlocks (space to toggle, enter to continue):") + "\n\n")
		if len(m.grantIDs) == 0 {
			b.WriteString(styles.Muted.Render("(no grants defined yet — add an integration first)") + "\n")
		}
		for i, id := range m.grantIDs {
			prefix := "  [ ] "
			if m.selected[id] {
				prefix = "  [x] "
			}
			if i == m.cursor {
				prefix = styles.Cursor.String() + prefix[2:]
			}
			b.WriteString(prefix + id + "\n")
		}
		b.WriteString("\n" + styles.Help.Render("↑↓ move · space toggle · enter continue · esc cancel"))
	case 1:
		b.WriteString(styles.FormLabel.Render("Token name (human label, optional — tab to switch fields):") + "\n")
		activeName := "  " + m.nameInput.String()
		activeNote := "  " + m.noteInput.String()
		if m.fieldIdx == 0 {
			activeName = "› " + m.nameInput.String()
		} else {
			activeNote = "› " + m.noteInput.String()
		}
		b.WriteString(styles.FormInput.Render(activeName) + "\n\n")
		b.WriteString(styles.FormLabel.Render("Note (optional):") + "\n")
		b.WriteString(styles.FormInput.Render(activeNote) + "\n\n")
		b.WriteString(styles.Muted.Render("Grants: "+strings.Join(m.selectedList(), ", ")) + "\n")
		if m.saveErr != "" {
			b.WriteString("\n" + styles.Status["fail"].Render(m.saveErr) + "\n")
		}
		b.WriteString("\n" + styles.Help.Render("tab switch · enter save · esc cancel"))
	case 2:
		b.WriteString(styles.Status["warn"].Render("⚠ Sensitive grants selected:") + "\n")
		for id := range m.sensitive {
			b.WriteString("  - " + id + "\n")
		}
		b.WriteString("\nThis token will let its holder write or admin at the upstream service.\n")
		if m.saveErr != "" {
			b.WriteString("\n" + styles.Status["fail"].Render(m.saveErr) + "\n")
		}
		b.WriteString("\n" + styles.Help.Render("y proceed · n cancel"))
	case 3:
		b.WriteString(styles.Status["ok"].Render("✓ token issued") + "\n\n")
		b.WriteString(styles.FormLabel.Render("Bearer (shown ONCE — copy it now):") + "\n")
		b.WriteString(styles.FormInput.Render("  "+m.bearer) + "\n\n")
		b.WriteString(styles.Muted.Render(fmt.Sprintf("Then: export DOP_TOKEN=%s", m.bearer)) + "\n")
		b.WriteString("\n" + styles.Help.Render("any key to return to the menu"))
	}
	return b.String()
}
