// v1.7 — inline pending-claim approve panel. Surfaced from the root
// menu whenever a non-expired pending claim exists (banner + 'a' key).
//
// The view keeps the security model: approval still requires the
// admin passphrase. The TUI only saves the click-then-type dance.

package tui

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	tea "github.com/charmbracelet/bubbletea"

	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/pendingclaim"
)

type pendingView struct {
	paths *config.Paths

	claims  []*pendingclaim.Record
	cursor  int
	passBuf strings.Builder
	step    int // 0 = pick, 1 = passphrase for selected
	err     string
	done    bool
	flash   string
}

func (m *rootModel) openPendingApprove() (tea.Model, tea.Cmd) {
	v := &pendingView{paths: m.paths}
	all, err := pendingclaim.List(m.paths)
	if err != nil {
		v.err = err.Error()
	}
	now := time.Now()
	for _, r := range all {
		if !r.Expired(now) {
			v.claims = append(v.claims, r)
		}
	}
	m.child = v
	m.screen = screenPending
	return m, v.Init()
}

func (v *pendingView) Init() tea.Cmd { return nil }
func (v *pendingView) Done() bool    { return v.done }
func (v *pendingView) Flash() string { return v.flash }

func (v *pendingView) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	km, ok := msg.(tea.KeyMsg)
	if !ok {
		return v, nil
	}
	switch km.String() {
	case "esc", "ctrl+c":
		v.done = true
		return v, nil
	}
	if v.step == 0 {
		switch km.String() {
		case "up", "k":
			if v.cursor > 0 {
				v.cursor--
			}
		case "down", "j":
			if v.cursor < len(v.claims)-1 {
				v.cursor++
			}
		case "r":
			// Reject (no passphrase required — reject is safe).
			if len(v.claims) == 0 {
				return v, nil
			}
			sas := pendingclaim.NormalizeSAS(v.claims[v.cursor].SAS)
			if err := runDopReject(sas); err != nil {
				v.err = err.Error()
				return v, nil
			}
			v.flash = "rejected " + v.claims[v.cursor].Subject
			v.done = true
			return v, nil
		case "enter", "a":
			if len(v.claims) == 0 {
				return v, nil
			}
			v.step = 1
			v.passBuf.Reset()
			v.err = ""
		}
		return v, nil
	}
	// step 1 — passphrase entry
	switch km.String() {
	case "enter":
		sas := pendingclaim.NormalizeSAS(v.claims[v.cursor].SAS)
		if err := runDopApprove(sas, v.passBuf.String()); err != nil {
			v.err = err.Error()
			v.passBuf.Reset()
			return v, nil
		}
		v.flash = "approved " + v.claims[v.cursor].Subject
		v.done = true
	case "backspace":
		s := v.passBuf.String()
		v.passBuf.Reset()
		if len(s) > 0 {
			v.passBuf.WriteString(s[:len(s)-1])
		}
	default:
		if len(km.Runes) > 0 {
			v.passBuf.WriteString(string(km.Runes))
		}
	}
	return v, nil
}

func (v *pendingView) View() string {
	var b strings.Builder
	b.WriteString(titleSt.Render("Pending claims") + "\n")
	b.WriteString(mutedSt.Render(fmt.Sprintf("%d waiting", len(v.claims))) + "\n\n")

	if len(v.claims) == 0 {
		b.WriteString(mutedSt.Render("no pending claims") + "\n")
		b.WriteString("\n" + helpSt.Render("esc back"))
		return b.String()
	}

	if v.step == 0 {
		// Row: cursor + SAS + subject + host + pubkey-fingerprint + TTL
		for i, r := range v.claims {
			cursor := "  "
			label := lipgloss.NewStyle()
			if i == v.cursor {
				cursor = cursorSt.Render("➤ ")
				label = cursorSt
			}
			ttl := r.ExpiresAt.Sub(time.Now()).Round(time.Second).String()
			pub := r.Pubkey
			if len(pub) > 10 {
				pub = pub[:10] + "…"
			}
			row := fmt.Sprintf("%-9s %-16s %s  %s", r.SAS, r.Subject, pub, ttl)
			b.WriteString(cursor + label.Render(row) + "\n")
		}
		if v.err != "" {
			b.WriteString("\n" + failSt.Render(v.err) + "\n")
		}
		b.WriteString("\n" + helpSt.Render("↑↓ move | a/enter approve | r reject | esc back"))
		return b.String()
	}

	// step 1 — passphrase entry
	sel := v.claims[v.cursor]
	b.WriteString(fmt.Sprintf("Approving %s (SAS %s)\n\n", sel.Subject, sel.SAS))
	b.WriteString(cursorSt.Render("Approval passphrase") + ":  ")
	masked := strings.Repeat("•", len(v.passBuf.String()))
	b.WriteString(masked + cursorSt.Render("▎") + "\n")
	if v.err != "" {
		b.WriteString("\n" + failSt.Render(v.err) + "\n")
	}
	b.WriteString("\n" + helpSt.Render("enter confirm | esc cancel"))
	return b.String()
}

// runDopApprove shells to the CLI `dop approve --passphrase-stdin <SAS>`
// so the TUI reuses the same crypto path and the flock-atomic counter.
func runDopApprove(sas, passphrase string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(self, "approve", "--passphrase-stdin", sas)
	cmd.Stdin = strings.NewReader(passphrase)
	cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}

// runDopReject shells to `dop reject <SAS>`.
func runDopReject(sas string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(self, "reject", sas)
	cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}
