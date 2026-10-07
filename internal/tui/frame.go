// Screen frame: row 1 title + tabs + muted context, row 2 blank, body,
// blank, status line, footer. Nothing renders below the footer.

package tui

import (
	"os"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"

	"github.com/fray/dop/internal/config"
)

// tab is one title-row tab; a negative count hides the count.
type tab struct {
	label  string
	count  int
	active bool
}

// frameRows is the body height frame leaves on a terminal height tall.
func frameRows(height int) int {
	if height <= 0 {
		height = 24
	}
	return max(height-5, 1)
}

// frame lays out one screen. Body lines may hold newlines; rows past the
// body area are clipped (views scroll themselves). Every line is
// truncated to width. Zero width/height mean 80x24.
func frame(width, height int, title string, tabs []tab, context string, body []string, status, foot string) string {
	if width <= 0 {
		width = 80
	}
	head := titleSt.Render(title)
	for _, t := range tabs[:min(len(tabs), 3)] {
		l := t.label
		if t.count >= 0 {
			l += " " + strconv.Itoa(t.count)
		}
		st := mutedSt
		if t.active {
			st = focusSt.Underline(true)
		}
		head += "   " + st.Render(l)
	}
	ctx := ""
	if context != "" {
		ctx = mutedSt.Render(context)
	}
	if b := homeBadge(); b != "" {
		ctx = dangerSt.Render(b)
		if context != "" {
			ctx += "  " + mutedSt.Render(context)
		}
	}
	if ctx != "" {
		pad := width - lipgloss.Width(head) - lipgloss.Width(ctx)
		head += strings.Repeat(" ", max(pad, 2)) + ctx
	}
	body = strings.Split(strings.Join(body, "\n"), "\n")
	rows := frameRows(height)
	lines := append(make([]string, 0, rows+5), head, "")
	for i := 0; i < rows; i++ {
		l := ""
		if i < len(body) {
			l = body[i]
		}
		lines = append(lines, l)
	}
	lines = append(lines, "", status, foot)
	for i, l := range lines {
		lines[i] = ansi.Truncate(l, width, "…")
	}
	return strings.Join(lines, "\n")
}

// homeBadge marks every screen while DOP_HOME points at a separate
// install, so the operator never mistakes it for their real one
// (contract 26). DOP_RECORDING=1 hides it for VHS recordings.
func homeBadge() string {
	h := config.HomeOverride()
	if h == "" || os.Getenv("DOP_RECORDING") == "1" {
		return ""
	}
	return "DOP_HOME " + h
}

// status is the one-line status row: one source at a time, error >
// flash > hint. Error in danger, flash in ok, hint muted.
type status struct{ err, flash, hint string }

func (s *status) setError(e string) { s.err = e }
func (s *status) setFlash(f string) { s.flash = f }
func (s *status) setHint(h string)  { s.hint = h }

// onKey: a flash clears on the next key; an error only when the input
// it was about changed.
func (s *status) onKey(inputChanged bool) {
	s.flash = ""
	if inputChanged {
		s.err = ""
	}
}

func (s status) String() string {
	switch {
	case s.err != "":
		return dangerSt.Render("! " + s.err)
	case s.flash != "":
		return okSt.Render(s.flash)
	case s.hint != "":
		return mutedSt.Render(s.hint)
	}
	return ""
}
