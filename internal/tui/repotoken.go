package tui

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
)

// The built-in git (internal/vaultgit) ends a login refusal with
// "<host> refused every login dop tried. Save a repo token: …". The
// Server and Join screens catch it and ask for the token here (dop-ob2):
// a fresh VPS has no git and no saved login, so a private https vault
// is unreachable until a token is saved.
var refusedRe = regexp.MustCompile(`(\S+) refused every login dop tried`)

// repoTokenHost returns the refusing host found in a command's output,
// or "".
func repoTokenHost(out string) string {
	if m := refusedRe.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

// repoTokenStep is the "paste your repo token" question.
type repoTokenStep struct {
	host  string
	in    textinput.Model
	tries int // tokens already saved and refused
}

func newRepoTokenStep(host string) *repoTokenStep {
	in := newFormInput(true)
	in.Placeholder = "github_pat_…"
	return &repoTokenStep{host: host, in: in}
}

func (r *repoTokenStep) value() string { return strings.TrimSpace(r.in.Value()) }

func (r *repoTokenStep) prompt() string { return "Repo token for " + r.host }

func (r *repoTokenStep) helper() string {
	how := "A token with read and write access to the vault repo."
	if r.host == "github.com" {
		how = "GitHub › Settings › Developer settings › Fine-grained tokens · this repo · Contents: Read and write."
	}
	if r.tries > 0 {
		return r.host + " refused that token too. " + how
	}
	return how
}

func (r *repoTokenStep) notes() []string {
	return []string{
		r.host + " refused every login this machine has (no git login here), so dop needs a token to reach the vault repo.",
		"Saved for " + r.host + " on this machine only, readable only by you. dop vault logout " + r.host + " forgets it.",
	}
}

// saveRepoToken runs `dop vault login <host>` with the token on stdin,
// so the token never appears in a process list or the shell history.
func saveRepoToken(host, token string) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(self, "vault", "login", host)
	cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
	cmd.Stdin = strings.NewReader(token + "\n")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if s := strings.TrimSpace(stderr.String()); s != "" {
			return errors.New(s)
		}
		return err
	}
	return nil
}
