// Shared pieces of the list / detail / confirm / form screens (bearers,
// integrations, grants): name list rows, the › action list, the confirm
// footer and the edit-form rows.

package tui

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

// nameColW is the name column of the integrations and grants lists.
const nameColW = 30

// padTrunc fits s into exactly w cells: … truncated, space padded.
func padTrunc(s string, w int) string {
	t := ansi.Truncate(s, w, "…")
	return t + strings.Repeat(" ", max(w-lipgloss.Width(t), 0))
}

// plural is "1 grant" / "3 grants".
var (
	vocabPl = regexp.MustCompile(`(^|[^-\w])(?:capabilities|tokens)\b`)
	vocabSg = regexp.MustCompile(`(^|[^-\w])(?:capability|token)\b`)
)

// vocab rewrites CLI wording into the TUI vocabulary (bearer, never token or
// capability) for text that is echoed from the CLI.
func vocab(s string) string {
	return vocabSg.ReplaceAllString(vocabPl.ReplaceAllString(s, "${1}bearers"), "${1}bearer")
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

// stepCursor moves *c by d inside [0, n).
func stepCursor(c *int, n, d int) { *c = max(0, min(n-1, *c+d)) }

// upTo5 lists names as indented body rows, five at most, then "and n more".
func upTo5(names []string) []string {
	var out []string
	for i, n := range names {
		if i == 5 {
			out = append(out, mutedSt.Render(fmt.Sprintf("    and %d more", len(names)-5)))
			break
		}
		out = append(out, "    "+bodySt.Render(n))
	}
	return out
}

// nameItem / nameDelegate — one-line rows for the integrations and
// grants lists: › cursor, name (nameColW, … truncated), muted rest.
type nameItem struct{ name, desc string }

func (i nameItem) FilterValue() string { return i.name }

type nameDelegate struct{}

func (nameDelegate) Height() int                         { return 1 }
func (nameDelegate) Spacing() int                        { return 0 }
func (nameDelegate) Update(tea.Msg, *list.Model) tea.Cmd { return nil }
func (nameDelegate) Render(w io.Writer, m list.Model, index int, li list.Item) {
	it := li.(nameItem)
	name := padTrunc(it.name, nameColW)
	desc := ansi.Truncate(it.desc, max(m.Width()-nameColW-4, 0), "…")
	if index == m.Index() {
		fmt.Fprint(w, focusSt.Render("› "+name+"  "+desc))
		return
	}
	fmt.Fprint(w, "  "+bodySt.Render(name)+"  "+mutedSt.Render(desc))
}

func newNameList() list.Model {
	l := list.New(nil, nameDelegate{}, 0, 0)
	l.SetShowTitle(false)
	l.SetShowStatusBar(false)
	l.SetFilteringEnabled(false)
	l.SetShowHelp(false)
	return l
}

// nameListBody renders l under a muted "name / col2" header in rows body rows.
func nameListBody(l *list.Model, col2 string, cursor, width, rows int) []string {
	// ponytail: one page stays one page (+2 for the pagination slot), dots only past a page.
	l.SetSize(width, max(3, min(rows-1, len(l.Items())+2)))
	l.Select(cursor)
	return []string{"  " + mutedSt.Render(padTrunc("name", nameColW)+"  "+col2), l.View()}
}

// actionRows renders a detail's › action list; the highlighted action's
// desc becomes the status hint.
func actionRows(acts []listAction, cursor int, st *status) []string {
	var out []string
	for i, a := range acts {
		if i == cursor {
			out = append(out, focusSt.Render("› "+a.label))
			st.setHint(a.desc)
		} else {
			out = append(out, "  "+bodySt.Render(a.label))
		}
	}
	return out
}

// confirmFoot is a confirm's footer: "enter <verb> · esc cancel", the
// destructive verb in danger.
func confirmFoot(verb string) string {
	return bodySt.Render("enter") + " " + dangerSt.Render(verb) + mutedSt.Render(" · ") + bodySt.Render("esc") + mutedSt.Render(" cancel")
}

// formRow is one edit-form row: › and the caret on the focused row,
// a muted label otherwise.
func formRow(focused bool, label, before, after string) string {
	if !focused {
		return "  " + mutedSt.Render(padTrunc(label, 19)) + "  " + before + after
	}
	return focusSt.Render("› ") + bodySt.Render(padTrunc(label, 19)) + "  " + before + focusSt.Render("▎") + after
}

// pickRows is a focused single-choice picker: its label, then one row
// per option (label + muted hint), › on the cursor.
func pickRows(label string, opts [][2]string, cur int) []string {
	out := []string{"  " + bodySt.Render(label)}
	for i, o := range opts {
		row := "    " + bodySt.Render(padTrunc(o[0], 10))
		if i == cur {
			row = "  " + focusSt.Render("› "+padTrunc(o[0], 10))
		}
		out = append(out, row+"  "+mutedSt.Render(o[1]))
	}
	return out
}

// protectOpts is protectionPresets as picker options.
func protectOpts() [][2]string {
	var o [][2]string
	for _, p := range protectionPresets {
		o = append(o, [2]string{p.label, p.hint})
	}
	return o
}

func protectWord(p bool) string {
	if p {
		return "protected"
	}
	return "default"
}

// ---- wizards (forms): one question per screen ----

// wiz is a wizard's chrome state: terminal size, the ? help, the
// running spinner.
type wiz struct {
	width, height int
	help          bool
	spin          spinner.Model
}

// wizMsg handles size, spinner ticks and the ? toggle. typing: the
// focused input holds text, so ? is a character there, not help.
// Reports whether msg was consumed.
func (w *wiz) wizMsg(msg tea.Msg, typing bool) (bool, tea.Cmd) {
	switch mm := msg.(type) {
	case tea.WindowSizeMsg:
		w.width, w.height = mm.Width, mm.Height
	case spinner.TickMsg:
		var cmd tea.Cmd
		w.spin, cmd = w.spin.Update(mm)
		return true, cmd
	case tea.KeyMsg:
		if typing && mm.String() == "?" {
			return false, nil
		}
		return toggleHelp(&w.help, mm), nil
	}
	return false, nil
}

// spinStart arms the brand spinner for a running screen.
func (w *wiz) spinStart() tea.Cmd {
	w.spin = spinner.New(spinner.WithSpinner(spinner.MiniDot), spinner.WithStyle(focusSt))
	return w.spin.Tick
}

// wizKeys is a step's keymap: extra short keys first (space toggle),
// then enter <verb>, esc back.
func wizKeys(verb string, extra ...key.Binding) keyMap {
	return keyMap{
		short: []key.Binding{hint("enter", verb), keyBack},
		full: [][]key.Binding{{hint("enter", verb), hint("shift+tab", "prev"), keyBack},
			append([]key.Binding{keyMove, hint("ctrl+u", "clear")}, extra...)},
	}
}

// screen renders one step: muted prompt, the input rows, a muted
// helper line; err (danger) or hint (muted) on the status line.
// counter is "2 of 4" (empty for single-step forms).
func (w wiz) screen(title, counter, prompt string, input []string, helper, err, hint string, km keyMap) string {
	body := append([]string{mutedSt.Render(prompt)}, input...)
	if helper != "" {
		body = append(body, "", mutedSt.Render(helper))
	}
	body = km.overlay(body, w.width, frameRows(w.height), w.help)
	return frame(w.width, w.height, title, nil, counter, body, status{err: err, hint: hint}.String(), km.footerLine(w.width, w.help))
}

// review is a wizard's last step: the question, the answers as kv
// rows, enter <verb> (danger when destructive) · esc back.
func (w wiz) review(title, question string, rows [][2]string, verb string, destructive bool, err string) string {
	body := append([]string{bodySt.Render(question), ""}, strings.Split(strings.TrimRight(kv(rows...), "\n"), "\n")...)
	km := keyMap{full: [][]key.Binding{{hint("enter", verb), hint("shift+tab", "edit"), keyBack}}}
	body = km.overlay(body, w.width, frameRows(w.height), w.help)
	vst, sep := bodySt, mutedSt.Render(" · ")
	if destructive {
		vst = dangerSt
	}
	foot := bodySt.Render("enter") + " " + vst.Render(verb) + sep + bodySt.Render("esc") + mutedSt.Render(" back") + sep + bodySt.Render("?") + mutedSt.Render(" more")
	if w.help {
		foot = footer(w.width, keyClose)
	}
	return frame(w.width, w.height, title, nil, "review", body, status{err: err}.String(), foot)
}

// running is the in-flight screen: spinner + one present-tense line.
func (w wiz) running(title, line string) string {
	return frame(w.width, w.height, title, nil, "", []string{w.spin.View() + " " + mutedSt.Render(line)}, "", "")
}

// doneScreen is the ✓ outcome: kv rows, one muted note, enter done.
func (w wiz) doneScreen(title string, rows [][2]string, note, flash string) string {
	body := strings.Split(strings.TrimRight(kv(rows...), "\n"), "\n")
	if note != "" {
		body = append(body, "", mutedSt.Render("  "+note))
	}
	return frame(w.width, w.height, "✓ "+title, nil, "", body, status{flash: flash}.String(), footer(w.width, hint("enter", "done")))
}

// counter is "n of m" for step i (0-based) of steps.
func counter(i, n int) string {
	if n <= 1 {
		return ""
	}
	return fmt.Sprintf("%d of %d", i+1, n)
}

// optRows is a wizard picker: › on the cursor row (label brand), label
// in fg elsewhere, the description muted on the same row.
func optRows(opts [][2]string, cur int) []string {
	lw := 0
	for _, o := range opts {
		lw = max(lw, lipgloss.Width(o[0]))
	}
	out := make([]string, 0, len(opts))
	for i, o := range opts {
		row := "  " + bodySt.Render(padTrunc(o[0], lw))
		if i == cur {
			row = focusSt.Render("› " + padTrunc(o[0], lw))
		}
		if o[1] != "" {
			row += "  " + mutedSt.Render(o[1])
		}
		out = append(out, row)
	}
	return out
}

// inputRow is the focused text input: › caret in brand, then the field.
func inputRow(t *textinput.Model) string {
	t.Focus()
	return focusSt.Render("› ") + t.View()
}

// wizBack steps *i back on esc / shift+tab: -1 when that leaves step
// 0 (close the wizard), 1 when it moved, 0 for any other key.
func wizBack(km tea.KeyMsg, i *int) int {
	switch km.String() {
	case "esc", "shift+tab":
		if *i == 0 {
			return -1
		}
		*i--
		return 1
	}
	return 0
}

// midTrunc shortens s to w runes by cutting the middle (keys, hex ids).
func midTrunc(s string, w int) string {
	r := []rune(s)
	if len(r) <= w {
		return s
	}
	h := (w - 1) / 2
	return string(r[:h]) + "…" + string(r[len(r)-(w-1-h):])
}

// pick is a remove-flow picker: one › row per option (label + muted
// desc), a muted count on the title row, the cursor row's full value
// on the status line.
func (w wiz) pick(title, ctx string, opts [][2]string, cur int, hintTxt, err string, km keyMap) string {
	body := km.overlay(optRows(opts, cur), w.width, frameRows(w.height), w.help)
	return frame(w.width, w.height, title, nil, ctx, body, status{err: err, hint: hintTxt}.String(), km.footerLine(w.width, w.help))
}

// confirmScreen is a remove-flow confirm: facts as body rows,
// enter <verb> (danger) · esc cancel; ? is not offered.
func (w wiz) confirmScreen(title string, body []string, verb, err string) string {
	return frame(w.width, w.height, title, nil, "", body, status{err: err}.String(), confirmFoot(verb))
}

// pickKeys is the footer of a remove-flow picker.
func pickKeys(verb string) keyMap {
	return keyMap{short: []key.Binding{hint("enter", verb), keyBack},
		full: [][]key.Binding{{hint("enter", verb), keyBack}, {keyMove}}}
}

// notice is a body-only screen (loading, empty, load error).
func (w wiz) notice(title, text string) string {
	return frame(w.width, w.height, title, nil, "", strings.Split(text, "\n"), "", footer(w.width, keyBack))
}
