package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveDefaultRoot(t *testing.T) {
	t.Setenv("DOP_HOME", "")
	base, err := os.UserConfigDir()
	if err != nil {
		t.Skip(err)
	}
	p, err := Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(base, "dop"); p.Root != want {
		t.Fatalf("root = %q, want %q", p.Root, want)
	}
}

func TestResolveDOPHome(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("DOP_HOME", dir)
	p, err := Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if p.Root != dir || p.Vault != filepath.Join(dir, "vault") || p.KeyFile != filepath.Join(dir, "keys", "age.txt") {
		t.Fatalf("DOP_HOME not applied to every path: %+v", p)
	}
}

func TestResolveDOPHomeRelative(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("DOP_HOME", "demo")
	p, err := Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(p.Root) || filepath.Base(p.Root) != "demo" {
		t.Fatalf("relative DOP_HOME should resolve absolute, got %q", p.Root)
	}
}
