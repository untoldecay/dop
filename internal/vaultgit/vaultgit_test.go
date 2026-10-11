package vaultgit

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Tests drive go-git and check the result with the real git binary —
// teammates on older dop builds (and humans) still use git on the
// same repos. Skipped when git isn't installed.

func sysgit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not installed")
	}
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@t", "GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@t")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return strings.TrimSpace(string(out))
}

func write(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func open(t *testing.T, dir string) *Repo {
	t.Helper()
	g, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func commitFile(t *testing.T, g *Repo, name, body, msg string) {
	t.Helper()
	write(t, g.dir, name, body)
	if err := g.Add(); err != nil {
		t.Fatal(err)
	}
	if err := g.Commit(msg, false); err != nil {
		t.Fatal(err)
	}
}

// setup: an empty bare repo made by InitBare, cloned twice.
func setup(t *testing.T) (bare string, a, b *Repo) {
	t.Helper()
	root := t.TempDir()
	bare = filepath.Join(root, "bare.git")
	if err := InitBare(bare); err != nil {
		t.Fatal(err)
	}
	url := "file://" + bare
	for _, n := range []string{"a", "b"} {
		if err := Clone(url, filepath.Join(root, n)); err != nil {
			t.Fatalf("clone %s: %v", n, err)
		}
	}
	a, b = open(t, filepath.Join(root, "a")), open(t, filepath.Join(root, "b"))
	if up := a.Upstream(); up != "origin/main" {
		t.Fatalf("upstream of an empty clone = %q, want origin/main", up)
	}
	commitFile(t, a, "vault.yaml", "v: 1\n", "first")
	if err := a.Push(false); err != nil {
		t.Fatalf("first push: %v", err)
	}
	if err := b.PullFFOnly(); err != nil {
		t.Fatalf("pull into empty clone: %v", err)
	}
	return bare, a, b
}

func TestEmptyCloneCommitPushPull(t *testing.T) {
	bare, a, b := setup(t)
	if got := sysgit(t, bare, "log", "--format=%s", "main"); got != "first" {
		t.Fatalf("bare log = %q", got)
	}
	if body, _ := os.ReadFile(filepath.Join(b.dir, "vault.yaml")); string(body) != "v: 1\n" {
		t.Fatalf("b worktree = %q", body)
	}
	if got := sysgit(t, b.dir, "status", "--porcelain"); got != "" {
		t.Fatalf("b not clean after pull: %q", got)
	}
	sysgit(t, bare, "fsck", "--strict")
	_ = a
}

func TestAheadBehindDivergedMergeOurs(t *testing.T) {
	bare, a, b := setup(t)
	commitFile(t, a, "vault.yaml", "v: 2\n", "a change")
	if err := a.Push(false); err != nil {
		t.Fatal(err)
	}
	commitFile(t, b, "other.txt", "b\n", "b change")

	// Ahead-only pull is fine (git pull --ff-only says "up to date").
	if err := a.PullFFOnly(); err != nil {
		t.Fatalf("a ahead/equal pull: %v", err)
	}
	if err := b.PullFFOnly(); !errors.Is(err, ErrNotFastForward) {
		t.Fatalf("diverged pull: want ErrNotFastForward, got %v", err)
	}
	team := b.Upstream()
	ours, _ := b.Count(team, "HEAD")
	theirs, _ := b.Count("HEAD", team)
	if ours != 1 || theirs != 1 {
		t.Fatalf("ahead/behind = %d/%d, want 1/1", ours, theirs)
	}
	if want := sysgit(t, b.dir, "merge-base", "HEAD", team); true {
		got, err := b.MergeBase("HEAD", team)
		if err != nil || got != want {
			t.Fatalf("merge-base = %q (%v), want %q", got, err, want)
		}
	}
	if got, err := b.Show(team, "vault.yaml"); err != nil || string(got) != "v: 2\n" {
		t.Fatalf("show team:vault.yaml = %q (%v)", got, err)
	}

	// dop writes the merged vault itself, then records the merge.
	write(t, b.dir, "vault.yaml", "v: merged\n")
	if err := b.Add(); err != nil {
		t.Fatal(err)
	}
	if err := b.Commit("dop: sync", false); err != nil {
		t.Fatal(err)
	}
	if err := b.MergeOurs(team, "dop: merged your changes with the team's"); err != nil {
		t.Fatal(err)
	}
	if err := b.Push(false); err != nil {
		t.Fatalf("push after merge: %v", err)
	}
	parents := strings.Fields(sysgit(t, bare, "log", "-1", "--format=%P", "main"))
	if len(parents) != 2 {
		t.Fatalf("merge commit parents = %v", parents)
	}
	if got := sysgit(t, bare, "show", "main:vault.yaml"); got != "v: merged" {
		t.Fatalf("bare vault.yaml = %q", got)
	}
	sysgit(t, bare, "fsck", "--strict")

	// a catches up by fast-forward.
	if err := a.PullFFOnly(); err != nil {
		t.Fatalf("a pull merge: %v", err)
	}
	if n, _ := a.Count("HEAD", a.Upstream()); n != 0 {
		t.Fatalf("a still behind by %d", n)
	}
}

func TestFastForwardKeepsUnrelatedLocalEdits(t *testing.T) {
	_, a, b := setup(t)
	commitFile(t, a, "vault.yaml", "v: 2\n", "a change")
	if err := a.Push(false); err != nil {
		t.Fatal(err)
	}
	write(t, b.dir, "scratch.txt", "local, untracked\n")
	if err := b.PullFFOnly(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(b.dir, "scratch.txt")); err != nil {
		t.Fatal("fast-forward removed an untracked file")
	}
	if body, _ := os.ReadFile(filepath.Join(b.dir, "vault.yaml")); string(body) != "v: 2\n" {
		t.Fatalf("vault.yaml = %q", body)
	}
}

func TestResetHardAddDeletionsCommit(t *testing.T) {
	_, a, _ := setup(t)
	if err := a.Commit("nothing", false); !errors.Is(err, ErrNothingToCommit) {
		t.Fatalf("clean commit: want ErrNothingToCommit, got %v", err)
	}
	if err := a.Commit("empty ok", true); err != nil {
		t.Fatalf("allow-empty: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(a.dir, "pending"), 0o755); err != nil {
		t.Fatal(err)
	}
	write(t, a.dir, "pending/x.json", "{}")
	write(t, a.dir, "pending/y.json", "{}")
	if err := a.Add("pending"); err != nil {
		t.Fatal(err)
	}
	if err := a.Commit("add pending", false); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(a.dir, "pending/x.json")); err != nil {
		t.Fatal(err)
	}
	if err := a.Add("pending"); err != nil {
		t.Fatalf("add -A with a deletion: %v", err)
	}
	if err := a.Commit("drop x", false); err != nil {
		t.Fatal(err)
	}
	if got := sysgit(t, a.dir, "ls-files", "pending"); got != "pending/y.json" {
		t.Fatalf("tracked after deletion = %q", got)
	}
	write(t, a.dir, "vault.yaml", "dirty\n")
	if err := a.ResetHard(a.Upstream()); err != nil {
		t.Fatal(err)
	}
	if got := sysgit(t, a.dir, "status", "--porcelain"); got != "" {
		t.Fatalf("not clean after reset --hard: %q", got)
	}
	if body, _ := os.ReadFile(filepath.Join(a.dir, "vault.yaml")); string(body) != "v: 1\n" {
		t.Fatalf("vault.yaml after reset = %q", body)
	}
}

func TestForceWithLease(t *testing.T) {
	bare, a, b := setup(t)
	commitFile(t, a, "vault.yaml", "v: a\n", "a")
	if err := a.Push(false); err != nil {
		t.Fatal(err)
	}
	commitFile(t, b, "vault.yaml", "v: b\n", "b")
	if err := b.Push(false); err == nil {
		t.Fatal("non-force push of a diverged branch succeeded")
	}
	// b's lease is its stale origin/main → refused until it fetches.
	if err := b.Push(true); err == nil {
		t.Fatal("force-with-lease with a stale lease succeeded")
	}
	if err := b.Fetch(); err != nil {
		t.Fatal(err)
	}
	if err := b.Push(true); err != nil {
		t.Fatalf("force-with-lease after fetch: %v", err)
	}
	if got := sysgit(t, bare, "show", "main:vault.yaml"); got != "v: b" {
		t.Fatalf("bare after force = %q", got)
	}
}

// A vault repo created by git with its default branch (often master).
func TestSystemGitRepoMaster(t *testing.T) {
	root := t.TempDir()
	bare := filepath.Join(root, "bare.git")
	sysgit(t, root, "init", "--bare", "-b", "master", bare)
	seed := filepath.Join(root, "seed")
	sysgit(t, root, "clone", bare, seed)
	write(t, seed, "vault.yaml", "v: 1\n")
	sysgit(t, seed, "add", "-A")
	sysgit(t, seed, "commit", "-m", "seed")
	sysgit(t, seed, "push", "origin", "HEAD:master")

	dest := filepath.Join(root, "c")
	if err := Clone(bare, dest); err != nil {
		t.Fatal(err)
	}
	g := open(t, dest)
	if up := g.Upstream(); up != "origin/master" {
		t.Fatalf("upstream = %q, want origin/master", up)
	}
	if got := g.RemoteURL(); got != bare {
		t.Fatalf("remote url = %q", got)
	}
	commitFile(t, g, "vault.yaml", "v: 2\n", "from go-git")
	if err := g.Push(false); err != nil {
		t.Fatal(err)
	}
	if got := sysgit(t, bare, "log", "-1", "--format=%s", "master"); got != "from go-git" {
		t.Fatalf("bare master = %q", got)
	}
}

func TestCandidatesOrder(t *testing.T) {
	CredentialsPath = filepath.Join(t.TempDir(), "repo-credentials.json")
	t.Setenv("DOP_NO_GIT_CREDENTIAL", "1")
	t.Setenv("DOP_REPO_TOKEN", "")
	if err := SaveToken("github.com", "", "stored"); err != nil {
		t.Fatal(err)
	}
	cs, err := candidates("https://github.com/o/r.git")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range cs {
		names = append(names, c.name)
	}
	if strings.Join(names, ",") != "stored token,anonymous" {
		t.Fatalf("candidates = %v", names)
	}
	t.Setenv("DOP_REPO_TOKEN", "env")
	cs, _ = candidates("https://github.com/o/r.git")
	if cs[0].name != "DOP_REPO_TOKEN" {
		t.Fatalf("env token not first: %v", cs[0].name)
	}
	if st, _ := os.Stat(CredentialsPath); st.Mode().Perm() != 0o600 {
		t.Fatalf("credentials mode = %v", st.Mode().Perm())
	}
	if cs, _ := candidates("file:///tmp/x"); len(cs) != 1 || cs[0].auth != nil {
		t.Fatal("file:// should need no auth")
	}
}
