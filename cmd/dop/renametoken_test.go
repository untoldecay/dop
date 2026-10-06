package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fray/dop/internal/vault"
)

// TestRenameToken: the key moves, grants using it follow, other grants
// stay, an existing target is refused, one token_rename event.
func TestRenameToken(t *testing.T) {
	paths, client, _ := tokenFixture(t)
	v, vp, err := loadVaultViaDaemon(client, paths)
	must(t, err)
	integ := v.Integrations["gh"]
	integ.Tokens["gh-ro"] = vault.Token{Value: "ghp_ro"}
	v.Integrations["gh"] = integ
	v.Grants["github-ro"] = vault.Grant{Integration: "gh", Token: "gh-ro"}
	must(t, saveVaultViaDaemon(client, paths, vp, v))

	if rc := runIntegrationRenameToken([]string{"--integration", "gh", "--from", "gh", "--to", "gh-ro"}); rc == 0 {
		t.Fatal("rename onto an existing credential succeeded")
	}
	if rc := runIntegrationRenameToken([]string{"--integration", "gh", "--from", "gh", "--to", "gh-admin"}); rc != 0 {
		t.Fatalf("rename: rc=%d", rc)
	}
	v, _, err = loadVaultViaDaemon(client, paths)
	must(t, err)
	toks := v.Integrations["gh"].Tokens
	if _, ok := toks["gh"]; ok || toks["gh-admin"].Value != "ghp_fixture" {
		t.Fatalf("tokens not renamed: %v", toks)
	}
	if g := v.Grants["github"].Token; g != "gh-admin" {
		t.Fatalf("referencing grant: %q", g)
	}
	if g := v.Grants["github-ro"].Token; g != "gh-ro" {
		t.Fatalf("other grant touched: %q", g)
	}
	b, _ := os.ReadFile(filepath.Join(paths.Logs, "audit.jsonl"))
	if !strings.Contains(string(b), `"event":"token_rename"`) || !strings.Contains(string(b), `"grants":"1"`) {
		t.Fatalf("no token_rename event: %s", b)
	}
}
