package tui

import (
	"strings"
	"testing"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/fray/dop/internal/config"
)

const refusal = "dop init: couldn't clone https://github.com/o/vault.\n" +
	"  Details from git: git clone https://github.com/o/vault /x: authentication required: Repository not found. — github.com refused every login dop tried. Save a repo token: dop vault login github.com"

func TestRepoTokenHost(t *testing.T) {
	if h := repoTokenHost(refusal); h != "github.com" {
		t.Fatalf("host = %q", h)
	}
	if h := repoTokenHost("dop init: network is unreachable"); h != "" {
		t.Fatalf("unrelated error matched: %q", h)
	}
}

func TestServerAttachAsksForTokenOnRefusal(t *testing.T) {
	v := newAttachVaultView(&config.Paths{Root: t.TempDir()}, false)
	v.width, v.height = 100, 30
	v.url.SetValue("https://github.com/o/vault")
	v.Update(attachResultMsg{err: refusal})
	if v.tok == nil {
		t.Fatalf("no token step after a login refusal; err=%q", v.err)
	}
	out := v.View()
	for _, want := range []string{"Repo token for github.com", "Fine-grained tokens"} {
		if !strings.Contains(out, want) {
			t.Fatalf("token screen lacks %q:\n%s", want, out)
		}
	}
	v.Update(press("ghp_secret_value_123"))
	if strings.Contains(v.View(), "ghp_secret_value_123") {
		t.Fatal("token shown in clear")
	}
	// A second refusal (bad token) keeps the question, says so, clears the field.
	v.Update(attachResultMsg{err: refusal})
	if v.tok == nil || v.tok.tries != 1 || v.tok.value() != "" || !strings.Contains(v.View(), "refused that token") {
		t.Fatalf("second refusal not handled: %+v", v.tok)
	}
	v.Update(press("esc"))
	if v.tok != nil || v.done {
		t.Fatal("esc should go back to the URL, not close")
	}
	// Any other failure is a plain error, no token question.
	v.Update(attachResultMsg{err: "dop init: network is unreachable"})
	if v.tok != nil || !strings.Contains(v.err, "Attach failed") {
		t.Fatalf("plain failure: tok=%v err=%q", v.tok, v.err)
	}
}

func TestJoinAsksForTokenOnRefusal(t *testing.T) {
	v := newJoinView(&config.Paths{Root: t.TempDir()})
	v.width, v.height = 100, 30
	v.urlBuf.SetValue("https://github.com/o/vault")
	v.lines = strings.Split(refusal, "\n")
	v.Update(inviteDone{rc: 1, err: "exit status 1"})
	if v.step != joinStepToken || v.tok == nil {
		t.Fatalf("step = %d, want the token step", v.step)
	}
	if !strings.Contains(v.View(), "Repo token for github.com") {
		t.Fatalf("join token screen:\n%s", v.View())
	}
	v.Update(press("enter"))
	if !strings.Contains(v.err, "Paste the token") {
		t.Fatalf("empty token accepted: %q", v.err)
	}
	v.Update(press("esc"))
	if v.step != joinStepReview {
		t.Fatalf("esc → step %d, want review", v.step)
	}
	var _ tea.Model = v
}
