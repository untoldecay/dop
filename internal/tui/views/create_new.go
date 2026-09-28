package views

import (
	"os"
	"os/user"
	"strings"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/tui/styles"
	"github.com/fray/dop/internal/vaultgit"
)

// CreateMethod is the three-way choice for creating a new vault.
type CreateMethod int

const (
	CreateMethodNone CreateMethod = iota
	CreateMethodGH               // gh repo create (private)
	CreateMethodURL              // clone an already-empty remote
	CreateMethodLocal            // git init --bare locally
)

// CreateNewModel walks: pick method → collect the bits it needs → run.
// End state: vault attached at paths.Vault, initial .sops.yaml + .gitattributes
// committed and pushed.
type CreateNewModel struct {
	paths  *config.Paths
	pubkey string

	step   int
	method CreateMethod

	// Method-specific inputs.
	ghName    strings.Builder
	otherURL  strings.Builder
	localPath strings.Builder

	// Cursor for the method-selection menu.
	cursor int

	// Runtime state.
	runOut     strings.Builder
	runErr     string
	done       bool
	success    bool
	resolvedURL string
}

func NewCreateNew(paths *config.Paths, pubkey string) *CreateNewModel {
	m := &CreateNewModel{paths: paths, pubkey: pubkey}
	// Sensible default for gh name.
	if u, err := user.Current(); err == nil {
		m.ghName.WriteString("dop-vault-" + u.Username)
	}
	// Sensible default for local path.
	if h, err := os.UserHomeDir(); err == nil {
		m.localPath.WriteString(h + "/dop-vault-bare.git")
	}
	return m
}

func (m *CreateNewModel) Init() tea.Cmd { return nil }
func (m *CreateNewModel) Done() bool    { return m.done }

type createResultMsg struct{ err string; url string }

func (m *CreateNewModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch mm := msg.(type) {
	case createResultMsg:
		if mm.err != "" {
			m.runErr = mm.err
			m.step = 99
		} else {
			m.resolvedURL = mm.url
			m.success = true
			m.step = 100
		}
		return m, nil
	case tea.KeyMsg:
		switch mm.String() {
		case "ctrl+c":
			m.done = true
			return m, nil
		}
		switch m.step {
		case 0:
			return m.updateMethodChoice(mm)
		case 1:
			return m.updateMethodInput(mm)
		case 2:
			// Running — ignore keys except ctrl+c.
		case 99, 100:
			m.done = true
		}
	}
	return m, nil
}

func (m *CreateNewModel) updateMethodChoice(km tea.KeyMsg) (tea.Model, tea.Cmd) {
	items := []CreateMethod{CreateMethodGH, CreateMethodURL, CreateMethodLocal}
	switch km.String() {
	case "esc":
		m.done = true
	case "up", "k":
		if m.cursor > 0 {
			m.cursor--
		}
	case "down", "j":
		if m.cursor < len(items)-1 {
			m.cursor++
		}
	case "enter":
		m.method = items[m.cursor]
		m.step = 1
	}
	return m, nil
}

func (m *CreateNewModel) updateMethodInput(km tea.KeyMsg) (tea.Model, tea.Cmd) {
	buf := m.currentInputBuf()
	switch km.String() {
	case "esc":
		m.step = 0
	case "enter":
		if strings.TrimSpace(buf.String()) == "" {
			return m, nil
		}
		m.step = 2
		return m, m.runCmd()
	case "backspace":
		s := buf.String()
		if len(s) > 0 {
			buf.Reset()
			buf.WriteString(s[:len(s)-1])
		}
	default:
		if len(km.Runes) > 0 {
			buf.WriteString(string(km.Runes))
		}
	}
	return m, nil
}

func (m *CreateNewModel) currentInputBuf() *strings.Builder {
	switch m.method {
	case CreateMethodGH:
		return &m.ghName
	case CreateMethodURL:
		return &m.otherURL
	case CreateMethodLocal:
		return &m.localPath
	}
	return &strings.Builder{}
}

func (m *CreateNewModel) runCmd() tea.Cmd {
	return func() tea.Msg {
		var url string
		switch m.method {
		case CreateMethodGH:
			name := strings.TrimSpace(m.ghName.String())
			created, err := vaultgit.CreateGithubRepo(name, true, "DOP vault (private)", &m.runOut)
			if err != nil {
				return createResultMsg{err: err.Error() + "\n" + m.runOut.String()}
			}
			url = created
		case CreateMethodURL:
			url = strings.TrimSpace(m.otherURL.String())
		case CreateMethodLocal:
			url = strings.TrimSpace(m.localPath.String())
		}
		if err := vaultgit.Attach(url, m.paths.Vault, m.pubkey, &m.runOut); err != nil {
			return createResultMsg{err: err.Error() + "\n" + m.runOut.String()}
		}
		// Push initial state (works for gh, URL, and local — the InitialCommitAndPush
		// is a no-op if there's nothing new).
		if err := vaultgit.InitialCommitAndPush(m.paths.Vault, &m.runOut); err != nil {
			return createResultMsg{err: err.Error() + "\n" + m.runOut.String()}
		}
		return createResultMsg{url: url}
	}
}

func (m *CreateNewModel) View() string {
	var b strings.Builder
	b.WriteString(styles.Title.Render("Create a new vault") + "\n\n")

	switch m.step {
	case 0:
		items := []struct {
			method CreateMethod
			label  string
			hint   string
		}{
			{CreateMethodGH, "On GitHub via gh CLI", "creates a private repo owned by your current gh account"},
			{CreateMethodURL, "Point at an existing empty repo URL", "you've already made a GitHub/Gitea/etc repo"},
			{CreateMethodLocal, "Local bare repo (no remote)", "for testing; you can push to a remote later"},
		}
		for i, it := range items {
			prefix := styles.Bullet.String()
			label := it.label
			if i == m.cursor {
				prefix = styles.Cursor.String()
				label = styles.Selected.Render(it.label)
			}
			b.WriteString(prefix + label + "  " + styles.Muted.Render(it.hint) + "\n")
		}
		b.WriteString("\n" + styles.Help.Render("↑↓ move · enter select · esc back"))
	case 1:
		b.WriteString(styles.FormLabel.Render(m.inputLabel()) + "\n")
		b.WriteString(styles.FormInput.Render("› "+m.currentInputBuf().String()) + "\n\n")
		b.WriteString(styles.Help.Render("enter go · esc back"))
	case 2:
		b.WriteString("working…\n\n")
		b.WriteString(styles.Muted.Render(tail(m.runOut.String(), 8)) + "\n")
	case 99:
		b.WriteString(styles.Status["fail"].Render("✗ create failed") + "\n\n")
		b.WriteString(styles.Muted.Render(tail(m.runErr, 12)) + "\n\n")
		b.WriteString(styles.Help.Render("any key to go back"))
	case 100:
		b.WriteString(styles.Status["ok"].Render("✓ vault created and attached") + "\n\n")
		b.WriteString(styles.FormLabel.Render("URL: ") + styles.FormInput.Render(m.resolvedURL) + "\n\n")
		b.WriteString(styles.Muted.Render("On other machines: `dop init --vault "+m.resolvedURL+"`") + "\n\n")
		b.WriteString(styles.Help.Render("any key to continue"))
	}
	return b.String()
}

func (m *CreateNewModel) inputLabel() string {
	switch m.method {
	case CreateMethodGH:
		return "Repo name for gh repo create (private, owned by your gh account):"
	case CreateMethodURL:
		return "URL of your empty repo (https or ssh):"
	case CreateMethodLocal:
		return "Path for the bare repo (will `git init --bare` here):"
	}
	return ""
}
