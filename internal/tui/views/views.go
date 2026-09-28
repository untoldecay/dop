// Package views holds the individual TUI screens. Each screen is a Bubble
// Tea sub-model that reports Done() when the user has hit escape/back so
// the root model can pop it off the stack.
package views

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/doctor"
	"github.com/fray/dop/internal/tui/styles"
	"github.com/fray/dop/internal/vault"
)

// Closer is implemented by every sub-model so the root can detect
// "user pressed esc / back / done" without hardcoding message plumbing.
type Closer interface {
	Done() bool
}

// StatusModel is a read-only summary screen.
type StatusModel struct {
	vaultPath string
	paths     *config.Paths
	loaded    *vault.Vault
	err       string
	done      bool
}

func NewStatus(vaultPath string, paths *config.Paths) *StatusModel {
	return &StatusModel{vaultPath: vaultPath, paths: paths}
}

func (m *StatusModel) Init() tea.Cmd {
	if m.vaultPath == "" {
		return nil
	}
	if v, err := vault.Load(m.vaultPath); err == nil {
		m.loaded = v
	} else {
		m.err = err.Error()
	}
	return nil
}

func (m *StatusModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "q", "esc", "enter":
			m.done = true
		}
	}
	return m, nil
}

func (m *StatusModel) Done() bool { return m.done }

func (m *StatusModel) View() string {
	var b strings.Builder
	b.WriteString(styles.Title.Render("Status") + "\n\n")

	line := func(k, v string) {
		b.WriteString(styles.FormLabel.Render(fmt.Sprintf("%-20s", k)))
		b.WriteString(styles.FormInput.Render(v) + "\n")
	}
	if m.paths != nil {
		line("age key", m.paths.KeyFile)
		line("vault clone", m.paths.Vault)
	}
	line("vault.yaml", ifEmpty(m.vaultPath, "(not attached — run `dop init --vault ...`)"))
	if m.err != "" {
		b.WriteString("\n" + styles.Status["fail"].Render("load error: "+m.err) + "\n")
	} else if m.loaded != nil {
		b.WriteString("\n")
		line("integrations", fmt.Sprintf("%d", len(m.loaded.Integrations)))
		line("grants", fmt.Sprintf("%d", len(m.loaded.Grants)))
		line("auth tokens", fmt.Sprintf("%d", len(m.loaded.AuthTokens)))
		line("agent pubkeys", fmt.Sprintf("%d", len(m.loaded.AgentPubkeys)))
		line("team members", fmt.Sprintf("%d", len(m.loaded.TeamMembers)))
	}
	b.WriteString("\n" + styles.Help.Render("enter/esc/q to go back"))
	return b.String()
}

// DoctorModel wraps doctor.Run with a pretty renderer.
type DoctorModel struct {
	vaultPath string
	paths     *config.Paths
	results   []doctor.Result
	ran       bool
	done      bool
}

func NewDoctor(vaultPath string, paths *config.Paths) *DoctorModel {
	return &DoctorModel{vaultPath: vaultPath, paths: paths}
}

func (m *DoctorModel) Init() tea.Cmd { return doctorRunCmd(m) }

// doctorRunCmd runs doctor.Run() synchronously (fast enough to not need
// backgrounding; the slowest check is the 5s HTTP timeout on clock skew,
// and the whole battery is bounded by that).
func doctorRunCmd(m *DoctorModel) tea.Cmd {
	return func() tea.Msg {
		var v *vault.Vault
		if m.vaultPath != "" {
			if loaded, err := vault.Load(m.vaultPath); err == nil {
				v = loaded
			}
		}
		client := &http.Client{Timeout: 5 * time.Second}
		results, _ := doctor.Run(v, m.paths, m.vaultPath, discard{}, client)
		return doctorDoneMsg{results: results}
	}
}

type doctorDoneMsg struct{ results []doctor.Result }

func (m *DoctorModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch mm := msg.(type) {
	case doctorDoneMsg:
		m.results = mm.results
		m.ran = true
	case tea.KeyMsg:
		switch mm.String() {
		case "q", "esc", "enter":
			m.done = true
		}
	}
	return m, nil
}

func (m *DoctorModel) Done() bool { return m.done }

func (m *DoctorModel) View() string {
	var b strings.Builder
	b.WriteString(styles.Title.Render("Doctor") + "\n\n")
	if !m.ran {
		b.WriteString(styles.Muted.Render("running…") + "\n")
	}
	for _, r := range m.results {
		glyph, style := statusGlyphStyle(r.Status)
		b.WriteString(style.Render(glyph) + " ")
		b.WriteString(lipgloss.NewStyle().Bold(true).Render(r.Name))
		b.WriteString("  " + styles.Muted.Render(r.Detail) + "\n")
	}
	b.WriteString("\n" + styles.Help.Render("enter/esc/q to go back"))
	return b.String()
}

func statusGlyphStyle(s doctor.Status) (string, lipgloss.Style) {
	switch s {
	case doctor.Pass:
		return "✓", styles.Status["ok"]
	case doctor.Warn:
		return "!", styles.Status["warn"]
	case doctor.Fail:
		return "✗", styles.Status["fail"]
	}
	return "?", styles.Muted
}

func ifEmpty(s, alt string) string {
	if s == "" {
		return alt
	}
	return s
}

// discard is a tiny io.Writer stub for doctor.Run — we render our own way.
type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }
