package tui

import (
	"slices"
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/fray/dop/internal/vault"
)

func TestBuildGroupRows(t *testing.T) {
	vals := map[string][]string{"a": {"docs", "wiki"}, "b": nil, "c": {"docs"}}
	of := func(id string) []string { return vals[id] }
	ids := []string{"a", "b", "c"}

	if got := buildGroupRows(ids, groupByName, of); len(got) != 3 || got[1] != (groupRow{"b", ""}) {
		t.Fatalf("by name: %v", got)
	}
	got := buildGroupRows(ids, groupByProject, of)
	want := []groupRow{{"a", "docs"}, {"c", "docs"}, {"a", "wiki"}, {"b", ""}}
	if !slices.Equal(got, want) {
		t.Fatalf("by project: got %v want %v", got, want)
	}
	if i := groupRowIndex(got, "a", "wiki"); i != 2 {
		t.Fatalf("index of a/wiki = %d", i)
	}
	if i := groupRowIndex(got, "a", "gone"); i != 0 {
		t.Fatalf("missing group falls back to the first row of the id, got %d", i)
	}
}

func TestMovedValues(t *testing.T) {
	cases := []struct {
		cur      []string
		from, to string
		want     []string
	}{
		{[]string{"docs", "wiki"}, "docs", "ops", []string{"ops", "wiki"}}, // replaced in place
		{[]string{"docs", "wiki"}, "docs", "wiki", []string{"wiki"}},       // already there: no duplicate
		{[]string{"docs", "wiki"}, "wiki", "", []string{"docs"}},           // none: taken out
		{nil, "", "docs", []string{"docs"}},                                // from none: added
	}
	for _, c := range cases {
		if got := movedValues(c.cur, c.from, c.to); !slices.Equal(got, c.want) {
			t.Errorf("movedValues(%v, %q, %q) = %v, want %v", c.cur, c.from, c.to, got, c.want)
		}
	}
}

func TestMoveArgsKeepTheOtherFields(t *testing.T) {
	g := vault.Grant{Integration: "notion", Token: "read", EnvPrefix: "NOTION_RO", Projects: []string{"docs"}, Tags: []string{"ro"}}
	got := strings.Join(grantMoveArgs("notion-read", g, groupByProject, "docs", "wiki"), " ")
	want := "grant add --id notion-read --integration notion --token read --projects wiki --tags ro --env-prefix NOTION_RO"
	if got != want {
		t.Fatalf("grant move:\n got %s\nwant %s", got, want)
	}
	if got := strings.Join(grantMoveArgs("x", vault.Grant{Integration: "i", Token: "t", Tags: []string{"ro", "ci"}}, groupByTag, "ci", ""), " "); got != "grant add --id x --integration i --token t --projects  --tags ro" {
		t.Fatalf("tag move without a custom prefix: %s", got)
	}
	it := vault.Integration{Projects: []string{"docs"}, Tags: []string{"ro"}}
	if got := strings.Join(integMoveArgs("notion", it, groupByTag, "ro", "rw"), " "); got != "integration add --name notion --tags rw" {
		t.Fatalf("integration move sends only the moved dimension: %s", got)
	}
}

func keyMsg(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	case "down":
		return tea.KeyMsg{Type: tea.KeyDown}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

// g cycles the grouping and keeps the cursor on the same grant; m opens
// the picker only once the list is grouped; the picker offers the other
// groups, new… and none.
func TestGrantListGroupAndMovePicker(t *testing.T) {
	v := &grantListView{list: newNameList()}
	v.Update(grantListLoadedMsg{items: map[string]vault.Grant{
		"a": {Integration: "notion", Projects: []string{"docs"}},
		"b": {Integration: "github"},
		"c": {Integration: "linear", Projects: []string{"ops"}},
	}})
	v.Update(keyMsg("down")) // b
	v.Update(keyMsg("m"))
	if v.mode != grantModeList || !strings.Contains(v.flash, "Group the list first") {
		t.Fatalf("m by name should only hint: mode=%d flash=%q", v.mode, v.flash)
	}
	v.Update(keyMsg("g"))
	if v.groupBy != groupByProject || v.selectedID() != "b" {
		t.Fatalf("g: by=%v selected=%q", v.groupBy, v.selectedID())
	}
	out := v.View()
	if !strings.Contains(out, "by project") || !strings.Contains(out, "no project") || strings.Index(out, "docs") > strings.Index(out, "no project") {
		t.Fatalf("grouped view: headers or order wrong:\n%s", out)
	}
	v.Update(keyMsg("m"))
	if v.mode != grantModeMove || v.move.id != "b" || v.move.from != "" {
		t.Fatalf("m grouped: mode=%d move=%+v", v.mode, v.move)
	}
	if !slices.Equal(v.move.opts, []string{"docs", "ops", moveNew}) {
		t.Fatalf("picker options for an ungrouped row: %q", v.move.opts)
	}
	v.Update(keyMsg("esc"))
	if v.mode != grantModeList {
		t.Fatalf("esc leaves the picker")
	}
	v.Update(keyMsg("g"))
	v.Update(keyMsg("g"))
	if v.groupBy != groupByName {
		t.Fatalf("g cycles back to name, got %v", v.groupBy)
	}
}
