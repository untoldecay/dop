// v1.13.0-rc14 — handoff text builder. Isolated from view.go so a
// unit test can grep-assert the contract shape without constructing
// a full tea.Model. See _rules/_requirements/contracts/13_handoff_text_shape.md.

package tui

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/x/ansi"

	"github.com/fray/dop/internal/userprefs"
)

// buildHandoffText produces the string pasted into the receiving
// agent's chat. Shape is intentionally minimal — a one-line preface
// + the bearer + the PIN (if present) + exactly one `dop claim`
// command. Nothing imperative after the command, so sandbox prompt-
// injection detectors on the receiving side don't block it.
//
// bearer: the issued bearer (always non-empty on this path).
// pin: short claim PIN; empty when the token was issued --no-bind.
// allowFileKeys: when true, embed DOP_ALLOW_FILE_KEYS=1 + --key-type p256
// in the single command (never on a separate explanatory line).
func buildHandoffText(bearer, pin string, allowFileKeys bool) string {
	claimCmd := "DOP_TOKEN=" + bearer + " dop claim " + pin
	if allowFileKeys {
		claimCmd = "DOP_TOKEN=" + bearer + " DOP_ALLOW_FILE_KEYS=1 dop claim --key-type p256 " + pin
	}
	return "Scoped credential access via DOP — run:\n\n" +
		"  " + claimCmd
}

// bearerHandoff is the clipboard text for a fresh bearer: the agent
// handoff when it carries a PIN, else the bare bearer.
func bearerHandoff(bearer, pin string, allowFileKeys bool) string {
	if pin == "" {
		return bearer
	}
	return buildHandoffText(bearer, pin, allowFileKeys)
}

// useGuidance is the next-step block under a fresh bearer (plain text,
// callers render it muted). Not portable: the agent handoff line alone.
// Portable: how to use it from the operator's harness, then where else
// dop use works. At most 3 lines, each within 76 cells.
func useGuidance(harness, subject string, portable bool, handoff string) []string {
	if !portable {
		return []string{handoff}
	}
	var g []string
	if harness == userprefs.HarnessClaudeCode {
		if !skillInstalled() {
			g = append(g, "install the DOP skill once: dop skill install", "then in Claude Code: /dop-use "+subject+" <task>")
		} else {
			g = append(g, "in Claude Code: /dop-use "+subject+" <task>")
		}
	} else {
		g = append(g, `in your shell before running the agent: eval "$(dop use `+subject+`)"`)
	}
	g = append(g, "dop use "+subject+" works from any of your shells")
	for i := range g {
		g[i] = ansi.Truncate(g[i], 76, "…")
	}
	return g
}

// skillInstalled reports whether dop skill install has left both the
// skill and the /dop-use command in ~/.claude.
func skillInstalled() bool {
	home, err := os.UserHomeDir()
	if err != nil {
		return false
	}
	for _, p := range []string{".claude/skills/dop/SKILL.md", ".claude/commands/dop-use.md"} {
		if _, err := os.Stat(filepath.Join(home, p)); err != nil {
			return false
		}
	}
	return true
}

// onceKey guards a shown-once bearer screen so a stray key cannot lose
// the bearer: enter leaves, esc needs a second press, c re-copies,
// anything else is ignored (and disarms esc). Reports whether to leave.
func onceKey(k string, armed, copied *bool, handoff string) bool {
	switch k {
	case "enter":
		return true
	case "esc", "ctrl+c":
		if *armed {
			return true
		}
		*armed = true
		return false
	case "c":
		*copied = clipboardCopy(handoff)
	}
	*armed = false
	return false
}

// onceScreen is the done screen of a fresh bearer: subject, bearer and
// PIN rows, then the muted after lines.
func onceScreen(width, height int, title, subject, bearer, pin string, after []string, armed, copied bool) string {
	rows := [][2]string{{"subject", subject}, {"bearer", bearer}}
	if pin != "" {
		rows = append(rows, [2]string{"PIN", pin})
	}
	body := append(strings.Split(strings.TrimRight(kv(rows...), "\n"), "\n"), "")
	for _, l := range after {
		body = append(body, mutedSt.Render("  "+l))
	}
	st := status{}
	switch {
	case armed:
		st.setHint("press esc again to leave, the bearer will not be shown again")
	case copied:
		st.setFlash("copied to clipboard")
	}
	return frame(width, height, title, nil, "shown once, c copies again", body, st.String(),
		footer(width, hint("enter", "done"), hint("c", "copy")))
}
