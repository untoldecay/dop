// dop-9ms — the one-time bearer screen must not be dismissed by a
// stray keypress. Only enter, or esc twice, leaves; c re-copies.

package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"
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

func key(s string) tea.KeyMsg {
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
		v.Update(key(k))
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
	v.Update(key("enter"))
	if !v.Done() {
		t.Fatal("enter should leave the success screen")
	}
}

func TestIssueSuccessEscNeedsSecondPress(t *testing.T) {
	v, _ := newIssueSuccess(t)
	v.Update(key("esc"))
	if v.Done() {
		t.Fatal("first esc must only arm the leave confirm")
	}
	if !strings.Contains(v.View(), "esc again to leave") {
		t.Fatal("armed state should warn before leaving")
	}
	v.Update(key("esc"))
	if !v.Done() {
		t.Fatal("second esc should leave")
	}
}

func TestIssueSuccessStrayKeyDisarmsEsc(t *testing.T) {
	v, _ := newIssueSuccess(t)
	v.Update(key("esc"))
	v.Update(key("x"))
	v.Update(key("esc"))
	if v.Done() {
		t.Fatal("esc after a disarming key should re-arm, not leave")
	}
}

func TestIssueSuccessCRecopies(t *testing.T) {
	v, copies := newIssueSuccess(t)
	v.Update(key("c"))
	if len(*copies) != 2 {
		t.Fatalf("c should copy again, got %d copies", len(*copies))
	}
	if !strings.Contains(v.View(), "copied again") {
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
