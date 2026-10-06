// Shared pieces of the list / detail / confirm / form screens (bearers,
// integrations, grants): name list rows, the › action list, the confirm
// footer and the edit-form rows.

package tui

import (
	"fmt"
	"io"
	"regexp"
	"sort"
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
	sessionGuard
}

// wizMsg handles size, spinner ticks and the ? toggle. typing: the
// focused input holds text, so ? is a character there, not help.
// Reports whether msg was consumed.
func (w *wiz) wizMsg(msg tea.Msg, typing bool) (bool, tea.Cmd) {
	if ok, cmd := w.unlocked(msg); ok {
		return true, cmd
	}
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

// ---- dense form: a label column, a value column, one row per field ----

// formField is one dense-form row: a text input, or a picker (opts)
// whose last option may open the text input for a custom value (other).
type formField struct {
	label string
	in    textinput.Model
	opts  [][2]string // picker options: label (the value), muted desc; nil = text row
	pick  int
	other bool // the last option opens the text input
	fixed bool // muted, not editable; the cursor skips it
	req   bool
	mask  bool
}

func textRow(label, placeholder string, req, mask bool) *formField {
	f := &formField{label: label, in: newFormInput(mask), req: req, mask: mask}
	f.in.Placeholder = placeholder
	return f
}

func pickRow(label string, opts [][2]string) *formField {
	return &formField{label: label, in: newFormInput(false), opts: opts}
}

func fixedRow(label, val string) *formField {
	f := &formField{label: label, in: newFormInput(false), fixed: true}
	f.in.SetValue(val)
	return f
}

// custom: the picker's custom option is selected.
func (f *formField) custom() bool { return f.other && f.pick == len(f.opts)-1 }

// val is the row's value: the picked label, or the trimmed text.
func (f *formField) val() string {
	if f.opts != nil && !f.custom() {
		return f.opts[f.pick][0]
	}
	return strings.TrimSpace(f.in.Value())
}

// denseForm is the cursor / inline-edit state over a []*formField the
// view rebuilds per step (rows may come and go with earlier answers).
// cur == len(rows) is the trailing action row (enter next).
type denseForm struct {
	cur, open, pcur int // open: 0 closed, 1 picker open, 2 text open
	was             string
	wasPick         int
}

const (
	formStay = iota
	formNext // enter on the action row
	formBack // esc on a closed row
)

// move steps the cursor by d to the next editable row (or the action row).
func (d *denseForm) move(rows []*formField, dir int) {
	for i := d.cur + dir; i >= 0 && i <= len(rows); i += dir {
		if i == len(rows) || !rows[i].fixed {
			d.cur = i
			return
		}
	}
}

// settle keeps the cursor in range and off fixed rows.
func (d *denseForm) settle(rows []*formField) {
	d.cur = min(max(d.cur, 0), len(rows))
	if d.cur < len(rows) && rows[d.cur].fixed {
		d.move(rows, 1)
	}
}

// key routes one key: ↑↓ move, enter opens the row (or, on the action
// row, reports formNext), esc cancels an open row or reports formBack.
func (d *denseForm) key(rows []*formField, km tea.KeyMsg) int {
	d.settle(rows)
	k := km.String()
	if d.open != 0 {
		f := rows[d.cur]
		switch {
		case k == "esc":
			f.in.SetValue(d.was)
			f.pick, d.open = d.wasPick, 0
		case d.open == 1 && (k == "up" || k == "down"):
			stepCursor(&d.pcur, len(f.opts), map[string]int{"up": -1, "down": 1}[k])
		case d.open == 1 && k == "enter":
			f.pick, d.open = d.pcur, 0
			if f.custom() {
				d.open = 2
				return formStay
			}
			d.move(rows, 1)
		case d.open == 2 && k == "enter":
			d.open = 0
			d.move(rows, 1)
		case d.open == 2:
			edit(&f.in, km)
		}
		return formStay
	}
	switch k {
	case "up", "down":
		d.move(rows, map[string]int{"up": -1, "down": 1}[k])
	case "esc":
		return formBack
	case "enter":
		if d.cur == len(rows) {
			return formNext
		}
		f := rows[d.cur]
		d.was, d.wasPick = f.in.Value(), f.pick
		d.open, d.pcur = 2, f.pick
		if f.opts != nil {
			d.open = 1
		}
	}
	return formStay
}

// typing: an open text row holds text, so ? is a character there.
func (d *denseForm) typing() bool { return d.open == 2 }

// missing points the cursor at the first required empty row and
// returns its error, or "".
func (d *denseForm) missing(rows []*formField) string {
	for i, f := range rows {
		if f.req && f.val() == "" {
			d.cur = i
			return f.label + " is required"
		}
	}
	return ""
}

// view renders the rows (› on the cursor row, the open picker in place
// under its row), then the action row. Every row fits width.
func (d *denseForm) view(rows []*formField, width int, action string) []string {
	d.settle(rows)
	lw := 0
	for _, f := range rows {
		lw = max(lw, lipgloss.Width(f.label))
	}
	vw := max(width-lw-6, 8)
	var out []string
	for i, f := range rows {
		lab := padTrunc(f.label, lw)
		shown := ansi.Truncate(f.val(), vw, "…")
		if f.mask && shown != "" {
			shown = strings.Repeat("•", min(len([]rune(f.val())), vw))
		}
		switch {
		case f.fixed:
			out = append(out, "  "+mutedSt.Render(lab+"  "+shown))
		case i == d.cur && d.open == 2:
			f.in.Width = vw
			out = append(out, inputRowLabel(&f.in, lab))
		case i == d.cur && d.open == 1:
			out = append(out, "  "+bodySt.Render(lab)+"  "+bodySt.Render(shown))
			for _, o := range optRows(f.opts, d.pcur) {
				out = append(out, strings.Repeat(" ", lw+2)+o)
			}
		case i == d.cur:
			if shown == "" && f.req {
				shown = mutedSt.Render("required")
			}
			out = append(out, focusSt.Render("› "+lab)+"  "+bodySt.Render(shown))
		default:
			if shown == "" && f.req {
				shown = mutedSt.Render("required")
			}
			out = append(out, "  "+mutedSt.Render(lab)+"  "+bodySt.Render(shown))
		}
	}
	out = append(out, "")
	if d.cur == len(rows) {
		return append(out, focusSt.Render("› "+action))
	}
	return append(out, "  "+bodySt.Render(action))
}

// inputRowLabel is an open text row: › and the label in brand, the field.
func inputRowLabel(t *textinput.Model, lab string) string {
	t.Focus()
	return focusSt.Render("› "+lab) + "  " + t.View()
}

// formKeys is a dense form's footer for its current state.
func (d *denseForm) formKeys(rows []*formField, action string, extra ...key.Binding) keyMap {
	var short []key.Binding
	switch {
	case d.open == 1:
		short = []key.Binding{hint("enter", "select"), keyCancel}
	case d.open == 2:
		short = []key.Binding{hint("enter", "done"), keyCancel}
	case d.cur >= len(rows):
		short = append([]key.Binding{hint("enter", strings.ToLower(action))}, extra...)
		short = append(short, keyBack)
	default:
		short = append([]key.Binding{hint("enter", "edit")}, extra...)
		short = append(short, keyBack)
	}
	return keyMap{short: short, full: [][]key.Binding{
		{keyMove, hint("enter", "edit a row / "+strings.ToLower(action)), keyBack},
		append([]key.Binding{hint("esc", "cancel an edit"), hint("ctrl+u", "clear")}, extra...)}}
}

// snap records each row's value, for changes.
func snap(rows []*formField) map[*formField]string {
	was := map[*formField]string{}
	for _, f := range rows {
		was[f] = f.val()
	}
	return was
}

// changes are the rows whose value differs from was, as review kv rows.
func changes(rows []*formField, was map[*formField]string) [][2]string {
	var out [][2]string
	for _, f := range rows {
		if f.val() != was[f] {
			out = append(out, [2]string{f.label, displayOr(f.val(), "none")})
		}
	}
	return out
}

// ---- multi-select picker (issue grants, bearer add grant) ----

// pickItem is one multi-select row: its group header, the name column,
// a muted second column and a muted note.
type pickItem struct{ group, id, col, note string }

type multiPick struct {
	items []pickItem
	sel   map[string]bool
	cur   int
}

// key: ↑↓ move, space toggles, ctrl+a all, n none. Reports whether
// the key was used.
func (p *multiPick) key(k string) bool {
	if p.sel == nil {
		p.sel = map[string]bool{}
	}
	switch k {
	case "up", "down":
		stepCursor(&p.cur, len(p.items), map[string]int{"up": -1, "down": 1}[k])
	case " ":
		if p.cur < len(p.items) {
			id := p.items[p.cur].id
			p.sel[id] = !p.sel[id]
		}
	case "ctrl+a":
		for _, it := range p.items {
			p.sel[it.id] = true
		}
	case "n":
		p.sel = map[string]bool{}
	default:
		return false
	}
	return true
}

// picked is the selection in row order.
func (p *multiPick) picked() []string {
	var out []string
	for _, it := range p.items {
		if p.sel[it.id] {
			out = append(out, it.id)
		}
	}
	return out
}

// rows renders the picker in at most n lines: muted group headers with
// a blank line between groups, ●/○, › on the cursor row, the name and
// second columns aligned; bad rows get a danger !. Scrolls to keep the
// cursor in view.
func (p *multiPick) rows(width, n int, bad map[string]bool) []string {
	nw := 0
	for _, it := range p.items {
		nw = max(nw, lipgloss.Width(it.id))
	}
	nw = min(nw, max(width/2-4, 12))
	cw := max(width-nw-10, 6)
	var out []string
	at, group := 0, "\x00"
	for i, it := range p.items {
		if it.group != group {
			if group != "\x00" {
				out = append(out, "")
			}
			group = it.group
			out = append(out, "  "+mutedSt.Render(it.group))
		}
		mark := mutedSt.Render("○")
		if p.sel[it.id] {
			mark = bodySt.Render("●")
		}
		col := ansi.Truncate(strings.TrimSpace(it.col+"  "+it.note), cw, "…")
		row := "  " + mark + " " + bodySt.Render(padTrunc(it.id, nw)) + "  " + mutedSt.Render(col)
		if i == p.cur {
			at = len(out)
			row = focusSt.Render("› ") + mark + " " + focusSt.Render(padTrunc(it.id, nw)) + "  " + mutedSt.Render(col)
		}
		if bad[it.id] {
			row += " " + dangerSt.Render("!")
		}
		out = append(out, row)
	}
	if n > 0 && len(out) > n {
		top := min(max(at-n/2, 0), len(out)-n)
		out = out[top : top+n]
	}
	return out
}

// grantPickItems lists grant ids for the picker: grouped by their first
// project (ungrouped last), the env prefix as the second column.
func grantPickItems(ids []string, info map[string]tuiGrantInfo) []pickItem {
	var items []pickItem
	for _, id := range ids {
		g := info[id]
		grp := "ungrouped"
		if len(g.Projects) > 0 {
			grp = g.Projects[0]
		}
		note := ""
		if g.Protected {
			note = "protected"
		}
		items = append(items, pickItem{grp, id, g.Prefix, note})
	}
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i].group, items[j].group
		if (a == "ungrouped") != (b == "ungrouped") {
			return b == "ungrouped"
		}
		return a < b
	})
	return items
}
