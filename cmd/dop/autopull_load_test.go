// Pull-before-load: an admin load fast-forwards to the team's latest
// vault, and the freshness window stops a second fetch.

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/fray/dop/internal/config"
)

func gitT(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

// twoAdmins returns a bare origin with one plain vault commit and two
// clones (a, b) of it, each with its own DOP root.
func twoAdmins(t *testing.T) (a, b *config.Paths) {
	t.Helper()
	tmp := t.TempDir()
	origin := filepath.Join(tmp, "origin.git")
	gitT(t, tmp, "init", "-q", "--bare", "-b", "main", origin)
	seed := filepath.Join(tmp, "seed")
	gitT(t, tmp, "clone", "-q", origin, seed)
	writeVault(t, seed, "grants:\n  notion.read: {}\n")
	gitT(t, seed, "add", "-A")
	gitT(t, seed, "commit", "-q", "-m", "seed")
	gitT(t, seed, "push", "-q", "origin", "HEAD:main")
	mk := func(name string) *config.Paths {
		root := filepath.Join(tmp, name)
		gitT(t, tmp, "clone", "-q", origin, filepath.Join(root, "vault"))
		return &config.Paths{Root: root, Vault: filepath.Join(root, "vault")}
	}
	return mk("a"), mk("b")
}

func writeVault(t *testing.T, dir, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "vault.yaml"), []byte("schema_version: v1\n"+body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func pushChange(t *testing.T, p *config.Paths, body string) {
	t.Helper()
	writeVault(t, p.Vault, body)
	gitT(t, p.Vault, "add", "-A")
	gitT(t, p.Vault, "commit", "-q", "-m", "change")
	gitT(t, p.Vault, "push", "-q")
}

func TestLoadVaultPullsTeamChanges(t *testing.T) {
	a, b := twoAdmins(t)
	pushChange(t, a, "grants:\n  notion.read: {}\n  github.write: {}\n")

	v, _, err := loadVaultViaDaemon(nil, b)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := v.Grants["github.write"]; !ok {
		t.Fatalf("admin b loaded a stale vault: grants=%v", v.Grants)
	}
	if !vaultPullFresh(b) {
		t.Fatal("pull should stamp last-pull.ts")
	}
}

func TestLoadVaultRespectsFreshnessWindow(t *testing.T) {
	a, b := twoAdmins(t)
	touchPullMarker(b) // just pulled
	pushChange(t, a, "grants:\n  linear.read: {}\n")

	v, _, _ := loadVaultViaDaemon(nil, b)
	if _, ok := v.Grants["linear.read"]; ok {
		t.Fatal("a fresh marker must skip the fetch")
	}

	old := time.Now().Add(-time.Minute)
	_ = os.Chtimes(filepath.Join(b.Root, "last-pull.ts"), old, old)
	v, _, _ = loadVaultViaDaemon(nil, b)
	if _, ok := v.Grants["linear.read"]; !ok {
		t.Fatal("a stale marker must pull")
	}
}

func TestLoadVaultNoAutoPullOptOut(t *testing.T) {
	t.Setenv("DOP_NO_AUTO_PULL", "1")
	a, b := twoAdmins(t)
	pushChange(t, a, "grants:\n  linear.read: {}\n")
	v, _, _ := loadVaultViaDaemon(nil, b)
	if _, ok := v.Grants["linear.read"]; ok {
		t.Fatal("DOP_NO_AUTO_PULL=1 must skip the pull")
	}
}
