// Package gitprobe inspects a git URL and the local environment to
// surface likely-blockers before we try to `git clone`.
//
// The TUI uses this to show hints to the user (missing ssh-agent, gh not
// installed for https auth, etc.) instead of just running clone and
// letting them read git's stderr.
package gitprobe

import (
	"os/exec"
	"strings"
)

// Protocol is the transport we detected on the URL.
type Protocol string

const (
	HTTPS   Protocol = "https"
	SSH     Protocol = "ssh"
	FileURL Protocol = "file"
	Local   Protocol = "local" // bare filesystem path, not a URL
	Unknown Protocol = "unknown"
)

// Report is what the caller renders. Hints are user-facing; Blockers are
// things that will almost certainly cause the clone to fail.
type Report struct {
	URL      string
	Protocol Protocol
	Hints    []string
	Blockers []string
}

// Probe classifies the URL and looks for obvious problems given the
// current environment. Never touches the network.
func Probe(rawURL string) Report {
	rep := Report{URL: rawURL, Protocol: classify(rawURL)}
	switch rep.Protocol {
	case HTTPS:
		probeHTTPS(&rep)
	case SSH:
		probeSSH(&rep)
	case FileURL, Local:
		// Nothing to check.
	case Unknown:
		rep.Blockers = append(rep.Blockers, "could not classify URL as https, ssh, file://, or local path")
	}
	return rep
}

// classify inspects the URL prefix; case-insensitive on scheme.
func classify(u string) Protocol {
	if u == "" {
		return Unknown
	}
	if strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://") {
		return HTTPS
	}
	if strings.HasPrefix(u, "ssh://") || strings.HasPrefix(u, "git@") {
		return SSH
	}
	if strings.HasPrefix(u, "file://") {
		return FileURL
	}
	// Local path heuristic: starts with `/`, `~`, or `.`
	if strings.HasPrefix(u, "/") || strings.HasPrefix(u, "~") || strings.HasPrefix(u, "./") || strings.HasPrefix(u, "../") {
		return Local
	}
	return Unknown
}

func probeHTTPS(rep *Report) {
	// If gh is installed and authed, git-credential-osxkeychain (or the
	// equivalent) is almost certainly set up. Suggest `gh auth setup-git`
	// when gh exists but no credential helper is configured.
	if !onPath("git") {
		rep.Blockers = append(rep.Blockers, "`git` binary not on $PATH — install git first")
		return
	}
	helper := getCredentialHelper()
	if helper != "" {
		return // git credential helper is set — we're likely fine
	}
	if onPath("gh") {
		rep.Hints = append(rep.Hints, "no git credential helper configured; if you use GitHub, run `gh auth setup-git` first for silent https auth")
		return
	}
	rep.Hints = append(rep.Hints, "no git credential helper configured; if git prompts for a password, paste a Personal Access Token (not your account password)")
}

func probeSSH(rep *Report) {
	if !onPath("git") {
		rep.Blockers = append(rep.Blockers, "`git` binary not on $PATH — install git first")
		return
	}
	if !onPath("ssh") {
		rep.Blockers = append(rep.Blockers, "`ssh` client not found — install openssh")
		return
	}
	if !sshAgentHasKeys() {
		rep.Hints = append(rep.Hints, "no ssh keys in your ssh-agent — clone will likely fail. Add one first (e.g. `ssh-add ~/.ssh/id_ed25519`) or switch to an https URL")
	}
}

// --- side-effecting helpers, kept thin so tests can hoist them out via
// package-level variables. ---

// commandRunner runs `cmd args...` and returns exit code + combined output.
// A package-level var so tests can stub it.
var commandRunner = func(cmd string, args ...string) (int, string) {
	c := exec.Command(cmd, args...)
	out, err := c.CombinedOutput()
	code := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			return -1, err.Error()
		}
	}
	return code, string(out)
}

// lookPath tells us if a binary is on $PATH. Var-ed so tests can replace.
var lookPath = func(bin string) (string, error) { return exec.LookPath(bin) }

func onPath(bin string) bool {
	_, err := lookPath(bin)
	return err == nil
}

func getCredentialHelper() string {
	code, out := commandRunner("git", "config", "--global", "credential.helper")
	if code != 0 {
		return ""
	}
	return strings.TrimSpace(out)
}

func sshAgentHasKeys() bool {
	// `ssh-add -l`: exit 0 + list, exit 1 + "The agent has no identities.",
	// exit 2 + "Could not open a connection to your authentication agent."
	code, _ := commandRunner("ssh-add", "-l")
	return code == 0
}
