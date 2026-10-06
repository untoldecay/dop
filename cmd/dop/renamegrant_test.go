package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/fray/dop/internal/vault"
)

// TestRenameGrant: the key moves, active bearers carrying it get the new
// id with a valid signature, other bearers keep their grants, a missing
// source or an existing target is refused, one grant_rename event.
func TestRenameGrant(t *testing.T) {
	paths, client, _ := tokenFixture(t)
	v, vp, err := loadVaultViaDaemon(client, paths)
	must(t, err)
	v.Grants["github-ro"] = vault.Grant{Integration: "gh", Token: "gh"}
	other := v.Capabilities["claimed"]
	other.Subject, other.Grants, other.LookupID = "other", []string{"github-ro"}, "dddddddddddddddddddddddd"
	v.Capabilities["other"] = other
	must(t, saveVaultViaDaemon(client, paths, vp, v))

	if rc := runGrantRename([]string{"--from", "nope", "--to", "x"}); rc == 0 {
		t.Fatal("rename of a missing grant succeeded")
	}
	if rc := runGrantRename([]string{"--from", "github", "--to", "github-ro"}); rc == 0 {
		t.Fatal("rename onto an existing grant succeeded")
	}
	if rc := runGrantRename([]string{"--from", "github", "--to", "gh-all"}); rc != 0 {
		t.Fatalf("rename: rc=%d", rc)
	}
	v, _, err = loadVaultViaDaemon(client, paths)
	must(t, err)
	if _, ok := v.Grants["github"]; ok || v.Grants["gh-all"].Token != "gh" {
		t.Fatalf("grant not moved: %v", v.Grants)
	}
	for _, id := range []string{"claimed", "unclaimed"} {
		c := v.Capabilities[id]
		if !slices.Equal(c.Grants, []string{"gh-all"}) {
			t.Fatalf("%s grants: %v", id, c.Grants)
		}
		rec := vaultCapability2Record(c, id)
		if err := rec.Verify(); err != nil {
			t.Fatalf("%s signature: %v", id, err)
		}
	}
	if g := v.Capabilities["gone"].Grants; !slices.Equal(g, []string{"github"}) {
		t.Fatalf("revoked bearer touched: %v", g)
	}
	if c := v.Capabilities["other"]; !slices.Equal(c.Grants, []string{"github-ro"}) || c.Generation != other.Generation {
		t.Fatalf("unrelated bearer touched: %v gen %d", c.Grants, c.Generation)
	}
	b, _ := os.ReadFile(filepath.Join(paths.Logs, "audit.jsonl"))
	if !strings.Contains(string(b), `"event":"grant_rename"`) || !strings.Contains(string(b), `"bearers":"2"`) {
		t.Fatalf("no grant_rename event: %s", b)
	}
}
