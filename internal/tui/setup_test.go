package tui

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/fray/dop/internal/config"
)

func makePaths(t *testing.T) *config.Paths {
	t.Helper()
	root := t.TempDir()
	return &config.Paths{
		Root:    root,
		KeysDir: filepath.Join(root, "keys"),
		KeyFile: filepath.Join(root, "keys", "age.txt"),
		Vault:   filepath.Join(root, "vault"),
		Logs:    filepath.Join(root, "logs"),
		Config:  filepath.Join(root, "config.yaml"),
	}
}

func TestDetectSetup_NoKey(t *testing.T) {
	p := makePaths(t)
	got, _ := DetectSetup(p)
	if got != SetupNoKey {
		t.Fatalf("expected SetupNoKey, got %v", got)
	}
}

func TestDetectSetup_NoVault(t *testing.T) {
	p := makePaths(t)
	// Key present, vault dir absent.
	if err := os.MkdirAll(p.KeysDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.KeyFile, []byte("# key\nAGE-SECRET-KEY-1XXX\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, _ := DetectSetup(p)
	if got != SetupNoVault {
		t.Fatalf("expected SetupNoVault, got %v", got)
	}
}

func TestDetectSetup_VaultEmpty(t *testing.T) {
	p := makePaths(t)
	os.MkdirAll(p.KeysDir, 0o700)
	os.WriteFile(p.KeyFile, []byte("key"), 0o600)
	os.MkdirAll(p.Vault, 0o700)
	os.WriteFile(filepath.Join(p.Vault, ".sops.yaml"), []byte("creation_rules: []\n"), 0o644)
	got, vp := DetectSetup(p)
	if got != SetupVaultEmpty {
		t.Fatalf("expected SetupVaultEmpty, got %v", got)
	}
	if vp != filepath.Join(p.Vault, "vault.yaml") {
		t.Fatalf("unexpected vault path: %s", vp)
	}
}

func TestDetectSetup_NilPaths(t *testing.T) {
	got, _ := DetectSetup(nil)
	if got != SetupUnknownError {
		t.Fatalf("expected SetupUnknownError, got %v", got)
	}
}
