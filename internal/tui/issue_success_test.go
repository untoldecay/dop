// dop-9ms — the one-time bearer screen must not be dismissed by a
// stray keypress. Only enter, or esc twice, leaves; c re-copies.

package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/x/ansi"
)

func newIssueSuccess(t *testing.T) (*issueView, *[]string) {
	t.Helper()
	var copies []string
	orig := clipboardCopy
	clipboardCopy = func(s string) bool { copies = append(copies, s); return true }
	t.Cleanup(func() { clipboardCopy = orig })
	v := &issueView{}
	v.Update(issueResultMsg{bearer: "dop_bearer_xyz"})
	return v, &copies
}

func press(s string) tea.KeyMsg {
	switch s {
	case "enter":
		return tea.KeyMsg{Type: tea.KeyEnter}
	case "esc":
		return tea.KeyMsg{Type: tea.KeyEsc}
	}
	return tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune(s)}
}

func TestIssueSuccessCopiesOnceOnResult(t *testing.T) {
	v, copies := newIssueSuccess(t)
	for i := 0; i < 3; i++ {
		_ = v.View()
	}
	if len(*copies) != 1 || (*copies)[0] != "dop_bearer_xyz" {
		t.Fatalf("want one copy of the bearer, got %q", *copies)
	}
}

func TestIssueSuccessStrayKeyKeepsScreen(t *testing.T) {
	v, _ := newIssueSuccess(t)
	for _, k := range []string{"x", " ", "q", "j"} {
		v.Update(press(k))
		if v.Done() {
			t.Fatalf("key %q dismissed the bearer screen", k)
		}
	}
	if !strings.Contains(v.View(), "dop_bearer_xyz") {
		t.Fatal("bearer no longer rendered")
	}
}

func TestIssueSuccessEnterLeaves(t *testing.T) {
	v, _ := newIssueSuccess(t)
	v.Update(press("enter"))
	if !v.Done() {
		t.Fatal("enter should leave the success screen")
	}
}

func TestIssueSuccessEscNeedsSecondPress(t *testing.T) {
	v, _ := newIssueSuccess(t)
	v.Update(press("esc"))
	if v.Done() {
		t.Fatal("first esc must only arm the leave confirm")
	}
	if !strings.Contains(v.View(), "press esc again to leave") {
		t.Fatal("armed state should warn before leaving")
	}
	v.Update(press("esc"))
	if !v.Done() {
		t.Fatal("second esc should leave")
	}
}

func TestIssueSuccessStrayKeyDisarmsEsc(t *testing.T) {
	v, _ := newIssueSuccess(t)
	v.Update(press("esc"))
	v.Update(press("x"))
	v.Update(press("esc"))
	if v.Done() {
		t.Fatal("esc after a disarming key should re-arm, not leave")
	}
}

func TestIssueSuccessCRecopies(t *testing.T) {
	v, copies := newIssueSuccess(t)
	v.Update(press("c"))
	if len(*copies) != 2 {
		t.Fatalf("c should copy again, got %d copies", len(*copies))
	}
	if !strings.Contains(v.View(), "copied to clipboard") {
		t.Fatal("re-copy confirmation missing")
	}
}

func TestIssueSuccessPinCopiesHandoff(t *testing.T) {
	var copies []string
	orig := clipboardCopy
	clipboardCopy = func(s string) bool { copies = append(copies, s); return true }
	t.Cleanup(func() { clipboardCopy = orig })
	v := &issueView{}
	v.Update(issueResultMsg{bearer: "dop_bearer_xyz", pin: "123456"})
	if len(copies) != 1 || copies[0] != buildHandoffText("dop_bearer_xyz", "123456", false) {
		t.Fatalf("PIN-bound result should copy the handoff, got %q", copies)
	}
}

// The issue grant picker and the bearer add-grant picker share
// multiPick.rows: at 70 columns nothing wraps and the env prefix column
// starts at the same cell on every grant row.
func TestGrantPickerFits70(t *testing.T) {
	info := map[string]tuiGrantInfo{
		"notion-read": {Prefix: "NOTION_NOTION", Projects: []string{"docs"}},
		"acme-billing-reconciliation-readonly-reporting-grant-for-finance-agents": {
			Prefix: "ACME_INTERNAL_BILLING_RECONCILIATION_SERVICE_PRODUCTION_EU_WEST_1_SERVICE_ACCOUNT", Protected: true},
		"github": {Prefix: "GITHUB_GITHUB"},
	}
	ids := []string{"acme-billing-reconciliation-readonly-reporting-grant-for-finance-agents", "github", "notion-read"}
	v := &issueView{grantList: ids, grantByID: info, step: issueStepGrants}
	v.subject, v.grantsCSV, v.custom, v.passphrase = newFormInput(false), newFormInput(false), newFormInput(false), newFormInput(true)
	v.pick.items = grantPickItems(ids, info)
	v.Update(tea.WindowSizeMsg{Width: 70, Height: 24})
	v.Update(press(" "))
	col := -1
	for _, l := range strings.Split(v.View(), "\n") {
		plain := ansi.Strip(l)
		if w := lipgloss.Width(plain); w > 70 {
			t.Fatalf("row wider than 70 (%d): %q", w, plain)
		}
		for _, p := range []string{"NOTION_", "ACME_", "GITHUB_"} {
			if i := strings.Index(plain, p); i >= 0 && strings.ContainsAny(plain, "●○") {
				if col >= 0 && lipgloss.Width(plain[:i]) != col {
					t.Fatalf("env prefix column misaligned in %q", plain)
				}
				col = lipgloss.Width(plain[:i])
			}
		}
	}
	if col < 0 {
		t.Fatal("no grant rows rendered")
	}
}
