package gitprobe

import (
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		in   string
		want Protocol
	}{
		{"https://github.com/foo/bar.git", HTTPS},
		{"http://internal/repo", HTTPS},
		{"ssh://git@github.com/foo/bar.git", SSH},
		{"git@github.com:foo/bar.git", SSH},
		{"file:///tmp/bare.git", FileURL},
		{"/tmp/bare.git", Local},
		{"~/vault-bare.git", Local},
		{"./relative", Local},
		{"../parent", Local},
		{"", Unknown},
		{"github.com/foo/bar", Unknown}, // missing scheme
	}
	for _, c := range cases {
		got := classify(c.in)
		if got != c.want {
			t.Errorf("classify(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// stubRunner rewrites commandRunner + lookPath for the duration of a test.
type stubRunner struct {
	prevRunner  func(string, ...string) (int, string)
	prevLookup  func(string) (string, error)
	commands    map[string]struct {
		code int
		out  string
	}
	pathBinaries map[string]bool
}

func newStub(t *testing.T) *stubRunner {
	t.Helper()
	s := &stubRunner{
		prevRunner:   commandRunner,
		prevLookup:   lookPath,
		commands:     map[string]struct{ code int; out string }{},
		pathBinaries: map[string]bool{},
	}
	commandRunner = func(cmd string, args ...string) (int, string) {
		key := cmd + " " + strings.Join(args, " ")
		if r, ok := s.commands[key]; ok {
			return r.code, r.out
		}
		return 127, "" // not-found by default
	}
	lookPath = func(bin string) (string, error) {
		if s.pathBinaries[bin] {
			return "/usr/bin/" + bin, nil
		}
		return "", &notFoundErr{bin: bin}
	}
	t.Cleanup(func() {
		commandRunner = s.prevRunner
		lookPath = s.prevLookup
	})
	return s
}

func (s *stubRunner) onPath(bins ...string) {
	for _, b := range bins {
		s.pathBinaries[b] = true
	}
}
func (s *stubRunner) cmd(key string, code int, out string) {
	s.commands[key] = struct{ code int; out string }{code, out}
}

type notFoundErr struct{ bin string }

func (e *notFoundErr) Error() string { return e.bin + " not found" }

func TestProbe_HTTPS_CredentialHelperConfigured(t *testing.T) {
	s := newStub(t)
	s.onPath("git")
	s.cmd("git config --global credential.helper", 0, "osxkeychain\n")
	r := Probe("https://github.com/foo/bar.git")
	if r.Protocol != HTTPS {
		t.Fatalf("protocol: %s", r.Protocol)
	}
	if len(r.Hints) != 0 || len(r.Blockers) != 0 {
		t.Fatalf("unexpected hints/blockers: %+v", r)
	}
}

func TestProbe_HTTPS_NoHelper_GhAvailable(t *testing.T) {
	s := newStub(t)
	s.onPath("git", "gh")
	s.cmd("git config --global credential.helper", 1, "") // helper missing
	r := Probe("https://github.com/foo/bar.git")
	if len(r.Hints) == 0 {
		t.Fatal("expected a hint about gh auth setup-git")
	}
	found := false
	for _, h := range r.Hints {
		if strings.Contains(h, "gh auth setup-git") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected 'gh auth setup-git' hint, got: %v", r.Hints)
	}
}

func TestProbe_HTTPS_NoHelper_NoGh(t *testing.T) {
	s := newStub(t)
	s.onPath("git")
	s.cmd("git config --global credential.helper", 1, "")
	r := Probe("https://github.com/foo/bar.git")
	if len(r.Hints) == 0 {
		t.Fatal("expected a PAT hint")
	}
	found := false
	for _, h := range r.Hints {
		if strings.Contains(h, "Personal Access Token") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected PAT hint, got: %v", r.Hints)
	}
}

func TestProbe_HTTPS_NoGit(t *testing.T) {
	newStub(t) // git NOT onPath
	r := Probe("https://github.com/foo/bar.git")
	if len(r.Blockers) == 0 {
		t.Fatal("expected blocker for missing git")
	}
}

func TestProbe_SSH_AgentEmpty(t *testing.T) {
	s := newStub(t)
	s.onPath("git", "ssh")
	s.cmd("ssh-add -l", 1, "The agent has no identities.")
	r := Probe("git@github.com:foo/bar.git")
	if r.Protocol != SSH {
		t.Fatalf("wrong protocol: %s", r.Protocol)
	}
	if len(r.Hints) == 0 {
		t.Fatal("expected empty-agent hint")
	}
	found := false
	for _, h := range r.Hints {
		if strings.Contains(h, "ssh-agent") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected ssh-agent hint, got %v", r.Hints)
	}
}

func TestProbe_SSH_AgentHasKeys(t *testing.T) {
	s := newStub(t)
	s.onPath("git", "ssh")
	s.cmd("ssh-add -l", 0, "256 SHA256:abc user@host (ED25519)")
	r := Probe("ssh://git@github.com/foo/bar.git")
	if len(r.Hints) != 0 || len(r.Blockers) != 0 {
		t.Fatalf("unexpected hints/blockers: %+v", r)
	}
}

func TestProbe_LocalPath(t *testing.T) {
	s := newStub(t)
	s.onPath("git")
	r := Probe("/tmp/vault-bare.git")
	if r.Protocol != Local {
		t.Fatalf("expected Local, got %s", r.Protocol)
	}
	if len(r.Hints) != 0 || len(r.Blockers) != 0 {
		t.Fatalf("local should not need auth: %+v", r)
	}
}

func TestProbe_Unknown(t *testing.T) {
	newStub(t)
	r := Probe("github.com/foo/bar") // missing scheme
	if r.Protocol != Unknown {
		t.Fatalf("expected Unknown, got %s", r.Protocol)
	}
	if len(r.Blockers) == 0 {
		t.Fatal("unknown URL should be a blocker")
	}
}
