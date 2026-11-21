// List grouping for the Grants and Integrations lists: `g` cycles
// name → project → tag, `m` moves the row under the cursor to another
// group without the edit form. Rendering follows the grant picker
// (multiPick.rows): muted group headers, a blank line between groups,
// the "none" group last. A row with several projects shows under each.

package tui

import (
	"slices"
	"sort"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/x/ansi"

	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/userprefs"
)

type groupBy int

const (
	groupByName groupBy = iota
	groupByProject
	groupByTag
)

func (g groupBy) label() string { return [...]string{"name", "project", "tag"}[g] }
func (g groupBy) next() groupBy { return (g + 1) % 3 }

// noneLabel heads the rows that have no value for this grouping.
func (g groupBy) noneLabel() string {
	if g == groupByTag {
		return "no tag"
	}
	return "no project"
}

func groupByOf(s string) groupBy {
	switch s {
	case "project":
		return groupByProject
	case "tag":
		return groupByTag
	}
	return groupByName
}

// loadGroupBy / saveGroupBy remember the grouping per list (tui-prefs).
func loadGroupBy(paths *config.Paths, list string) groupBy {
	if paths == nil {
		return groupByName
	}
	return groupByOf(userprefs.Load(paths).ListGroupBy[list])
}

func saveGroupBy(paths *config.Paths, list string, g groupBy) {
	if paths == nil {
		return
	}
	p := userprefs.Load(paths)
	if p.ListGroupBy == nil {
		p.ListGroupBy = map[string]string{}
	}
	if g == groupByName {
		delete(p.ListGroupBy, list)
	} else {
		p.ListGroupBy[list] = g.label()
	}
	_ = userprefs.Save(paths, p)
}

// groupRow is one visible row: an id under one group ("" = none).
type groupRow struct{ id, group string }

// buildGroupRows lists ids (sorted) for a grouping. By name: one row
// per id, no headers. Otherwise one row per (id, value), groups sorted,
// the none group last.
func buildGroupRows(ids []string, by groupBy, valuesOf func(id string) []string) []groupRow {
	rows := make([]groupRow, 0, len(ids))
	for _, id := range ids {
		vs := []string(nil)
		if by != groupByName {
			vs = valuesOf(id)
		}
		if len(vs) == 0 {
			rows = append(rows, groupRow{id, ""})
			continue
		}
		for _, v := range vs {
			rows = append(rows, groupRow{id, v})
		}
	}
	if by == groupByName {
		return rows
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i].group, rows[j].group
		if (a == "") != (b == "") {
			return b == ""
		}
		if a != b {
			return a < b
		}
		return rows[i].id < rows[j].id
	})
	return rows
}

// groupRowIndex finds (id, group), else the first row of id, else -1.
func groupRowIndex(rows []groupRow, id, group string) int {
	first := -1
	for i, r := range rows {
		if r.id == id {
			if r.group == group {
				return i
			}
			if first < 0 {
				first = i
			}
		}
	}
	return first
}

// groupedBody renders grouped rows in at most n body lines under the
// same "name / col2" header as nameListBody, scrolled to the cursor.
func groupedBody(rows []groupRow, by groupBy, cursor int, col2 string, col2Of func(id string) string, width, n int) []string {
	out := []string{"  " + mutedSt.Render(padTrunc("name", nameColW)+"  "+col2)}
	var body []string
	at, group := 0, "\x00"
	for i, r := range rows {
		if r.group != group {
			if group != "\x00" {
				body = append(body, "")
			}
			group = r.group
			h := r.group
			if h == "" {
				h = by.noneLabel()
			}
			body = append(body, "  "+mutedSt.Render(h))
		}
		name := padTrunc(r.id, nameColW)
		desc := ansi.Truncate(col2Of(r.id), max(width-nameColW-4, 0), "…")
		if i == cursor {
			at = len(body)
			body = append(body, focusSt.Render("› "+name+"  "+desc))
			continue
		}
		body = append(body, "  "+bodySt.Render(name)+"  "+mutedSt.Render(desc))
	}
	if n -= 1; n > 0 && len(body) > n {
		top := min(max(at-n/2, 0), len(body)-n)
		body = body[top : top+n]
	}
	return append(out, body...)
}

// moveOpt values that are not group names.
const (
	moveNew  = "\x00new"
	moveNone = "\x00none"
)

// movePicker is the `m` step: the other groups, "new…", and "none"
// (take the row out of the group it sits under).
type movePicker struct {
	id, from string // the row being moved, and the group it sits under
	opts     []string
	cur      int
	typing   bool // "new…" picked: the input has the caret
	in       textinput.Model
}

func newMovePicker(id, from string, all []string) movePicker {
	var opts []string
	for _, g := range all {
		if g != from {
			opts = append(opts, g)
		}
	}
	opts = append(opts, moveNew)
	if from != "" {
		opts = append(opts, moveNone)
	}
	in := newFormInput(false)
	in.Width = 40
	return movePicker{id: id, from: from, opts: opts, in: in}
}

// allGroupValues is every value used across ids, sorted.
func allGroupValues(ids []string, valuesOf func(string) []string) []string {
	var all []string
	for _, id := range ids {
		for _, v := range valuesOf(id) {
			if !slices.Contains(all, v) {
				all = append(all, v)
			}
		}
	}
	sort.Strings(all)
	return all
}

// movedValues is cur with from replaced by to ("" removes from; from ""
// adds to). Order is kept, no duplicates.
func movedValues(cur []string, from, to string) []string {
	var out []string
	for _, v := range cur {
		if v == from {
			continue
		}
		out = append(out, v)
	}
	if to != "" && !slices.Contains(out, to) {
		if i := slices.Index(cur, from); from != "" && i >= 0 && i <= len(out) {
			out = slices.Insert(out, i, to)
		} else {
			out = append(out, to)
		}
	}
	return out
}

// key handles one key in the picker. done: the step is over; when ok,
// to is the target ("" = none).
func (p *movePicker) key(mm tea.KeyMsg) (done, ok bool, to string) {
	k := mm.String()
	if p.typing {
		switch k {
		case "esc":
			p.typing = false
		case "enter":
			if v := strings.TrimSpace(p.in.Value()); v != "" && !strings.Contains(v, ",") {
				return true, true, v
			}
		default:
			p.in, _ = p.in.Update(mm)
		}
		return false, false, ""
	}
	switch k {
	case "esc", "q":
		return true, false, ""
	case "up", "k":
		stepCursor(&p.cur, len(p.opts), -1)
	case "down", "j":
		stepCursor(&p.cur, len(p.opts), 1)
	case "enter":
		switch o := p.opts[p.cur]; o {
		case moveNew:
			p.typing = true
			p.in.SetValue("")
			p.in.Focus()
		case moveNone:
			return true, true, ""
		default:
			return true, true, o
		}
	}
	return false, false, ""
}

// rows renders the picker body.
func (p *movePicker) rows(by groupBy) []string {
	from := p.from
	if from == "" {
		from = by.noneLabel()
	}
	out := []string{"  " + bodySt.Render(ansi.Truncate(p.id, 76, "…")), mutedSt.Render("  now under " + from + ". Move it to:"), ""}
	for i, o := range p.opts {
		label := o
		switch o {
		case moveNew:
			label = "new " + by.label() + "…"
		case moveNone:
			label = by.noneLabel() + " (take it out of " + p.from + ")"
		}
		if i == p.cur {
			out = append(out, focusSt.Render("› "+label))
		} else {
			out = append(out, "  "+bodySt.Render(label))
		}
	}
	if p.typing {
		out = append(out, "", "  "+bodySt.Render(by.label()+" name: ")+p.in.View())
	}
	return out
}
