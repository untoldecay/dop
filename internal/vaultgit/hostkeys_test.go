package vaultgit

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var addr = &net.TCPAddr{IP: net.IPv4(140, 82, 121, 4), Port: 22}

func parsed(t *testing.T, line string) ssh.PublicKey {
	t.Helper()
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

func randomKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	pk, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

func TestBuiltinHostKeysParse(t *testing.T) {
	for host, lines := range builtinHostKeys {
		for _, l := range lines {
			if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(l)); err != nil {
				t.Errorf("%s: %v", host, err)
			}
		}
	}
	// Pin GitHub's published fingerprints (api.github.com/meta).
	want := map[string]bool{
		"SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU": true,
		"SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM": true,
		"SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s": true,
	}
	for _, l := range builtinHostKeys["github.com"] {
		if fp := ssh.FingerprintSHA256(parsed(t, l)); !want[fp] {
			t.Errorf("github.com key %s isn't a published fingerprint", fp)
		}
	}
}

func TestHostKeysFreshBox(t *testing.T) {
	t.Setenv("HOME", t.TempDir()) // no ~/.ssh/known_hosts
	t.Setenv("SSH_KNOWN_HOSTS", "")
	cb, err := hostKeyCallback()
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range builtinHostKeys["github.com"] {
		if err := cb("github.com:22", addr, parsed(t, l)); err != nil {
			t.Fatalf("GitHub's published key refused on a fresh box: %v", err)
		}
	}
	if err := cb("github.com:22", addr, randomKey(t)); err == nil || !strings.Contains(err.Error(), "impersonation") {
		t.Fatalf("a fake github.com key: want refused, got %v", err)
	}
	if err := cb("git.example.org:22", addr, randomKey(t)); err == nil || !strings.Contains(err.Error(), "ssh -T git@git.example.org") {
		t.Fatalf("unknown host: want the trust-once hint, got %v", err)
	}
}

func TestHostKeysKnownHostsWins(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("SSH_KNOWN_HOSTS", "")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	other := randomKey(t)
	line := knownhosts.Line([]string{"github.com"}, other) + "\n" +
		knownhosts.Line([]string{"git.example.org"}, other) + "\n"
	if err := os.WriteFile(filepath.Join(home, ".ssh", "known_hosts"), []byte(line), 0o600); err != nil {
		t.Fatal(err)
	}
	cb, err := hostKeyCallback()
	if err != nil {
		t.Fatal(err)
	}
	// The user's file says github.com has another key: refuse even
	// GitHub's published one — the mismatch is the warning.
	gh := parsed(t, builtinHostKeys["github.com"][0])
	if err := cb("github.com:22", addr, gh); err == nil || !strings.Contains(err.Error(), "known_hosts") {
		t.Fatalf("known_hosts mismatch: want refused, got %v", err)
	}
	if err := cb("git.example.org:22", addr, other); err != nil {
		t.Fatalf("host trusted in known_hosts: %v", err)
	}
	// A host the file doesn't list falls back to the built-in keys.
	gl := parsed(t, builtinHostKeys["gitlab.com"][0])
	if err := cb("gitlab.com:22", addr, gl); err != nil {
		t.Fatalf("gitlab.com via the built-in keys: %v", err)
	}
}
