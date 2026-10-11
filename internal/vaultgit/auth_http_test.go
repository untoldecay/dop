package vaultgit

import (
	"net/http"
	"net/http/cgi"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// A real smart-HTTP git server (git http-backend) that only accepts one
// token: no login is refused with dop's "refused every login" message,
// a wrong token too, and the saved token clones and pushes.
func TestHTTPTokenLogin(t *testing.T) {
	out, err := exec.Command("git", "--exec-path").Output()
	if err != nil {
		t.Skip("git not installed")
	}
	backend := filepath.Join(strings.TrimSpace(string(out)), "git-http-backend")
	root := t.TempDir()
	if err := InitBare(filepath.Join(root, "vault.git")); err != nil {
		t.Fatal(err)
	}
	const token = "ghp_right_token"
	cgiH := &cgi.Handler{Path: backend, Env: []string{
		"GIT_PROJECT_ROOT=" + root, "GIT_HTTP_EXPORT_ALL=1", "REMOTE_USER=dop-test",
	}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, pass, ok := r.BasicAuth(); !ok || pass != token {
			w.Header().Set("WWW-Authenticate", `Basic realm="git"`)
			http.Error(w, "auth", http.StatusUnauthorized)
			return
		}
		cgiH.ServeHTTP(w, r)
	}))
	defer srv.Close()

	t.Setenv("DOP_NO_GIT_CREDENTIAL", "1")
	t.Setenv("DOP_REPO_TOKEN", "")
	CredentialsPath = filepath.Join(t.TempDir(), "repo-credentials.json")
	url := srv.URL + "/vault.git"
	host := Host(url)

	err = Clone(url, filepath.Join(root, "c0"))
	if err == nil || !strings.Contains(err.Error(), host+" refused every login dop tried") {
		t.Fatalf("no login: want the refusal message, got %v", err)
	}
	if err := SaveToken(host, "", "wrong"); err != nil {
		t.Fatal(err)
	}
	if err := Clone(url, filepath.Join(root, "c1")); err == nil {
		t.Fatal("wrong token accepted")
	}
	if err := SaveToken(host, "", token); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(root, "c2")
	if err := Clone(url, dest); err != nil {
		t.Fatalf("clone with the saved token: %v", err)
	}
	g := open(t, dest)
	commitFile(t, g, "vault.yaml", "v: 1\n", "over http")
	if err := g.Push(false); err != nil {
		t.Fatalf("push with the saved token: %v", err)
	}
	if got := sysgit(t, filepath.Join(root, "vault.git"), "log", "-1", "--format=%s", "main"); got != "over http" {
		t.Fatalf("server log = %q", got)
	}
	// A fresh clone now has history; pull works too.
	if err := Clone(url, filepath.Join(root, "c3")); err != nil {
		t.Fatalf("second clone: %v", err)
	}
	if err := open(t, filepath.Join(root, "c3")).PullFFOnly(); err != nil {
		t.Fatalf("pull: %v", err)
	}
}
