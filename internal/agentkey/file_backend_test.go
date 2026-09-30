package agentkey

import (
	"os"
	"testing"

	"github.com/fray/dop/internal/vault"
)

func tmpBackend(t *testing.T) *FileBackend {
	t.Helper()
	dir, err := os.MkdirTemp("", "agentkey-*")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return NewFileBackend(dir)
}

func TestFileBackend_Ed25519_Roundtrip(t *testing.T) {
	b := tmpBackend(t)
	s, err := b.Generate("lookup-a", vault.KeyTypeEd25519)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if s.KeyType() != vault.KeyTypeEd25519 {
		t.Fatalf("wrong key type: %s", s.KeyType())
	}
	if !s.Extractable() {
		t.Fatal("file-backed key must report Extractable=true")
	}
	challenge := []byte("dop-v1-exec:lookup-a:cap-foo")
	sig, err := s.Sign(challenge)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Verify(vault.KeyTypeEd25519, s.PublicKey(), challenge, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Load back and verify the pubkey is stable.
	loaded, err := b.Load("lookup-a")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !PubkeyEqual(loaded.PublicKey(), s.PublicKey()) {
		t.Fatal("loaded pubkey doesn't match generated")
	}
}

func TestFileBackend_P256_RequiresOptIn(t *testing.T) {
	b := tmpBackend(t)
	// Without the env var — refuse.
	os.Unsetenv("DOP_ALLOW_FILE_KEYS")
	_, err := b.Generate("lookup-b", vault.KeyTypeP256)
	if err == nil {
		t.Fatal("expected error without DOP_ALLOW_FILE_KEYS")
	}
	// With the env var — allow.
	t.Setenv("DOP_ALLOW_FILE_KEYS", "1")
	s, err := b.Generate("lookup-b", vault.KeyTypeP256)
	if err != nil {
		t.Fatalf("generate p256: %v", err)
	}
	if s.KeyType() != vault.KeyTypeP256 {
		t.Fatalf("wrong key type: %s", s.KeyType())
	}
	challenge := []byte("dop-v1-exec:lookup-b:cap-baz")
	sig, err := s.Sign(challenge)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Verify(vault.KeyTypeP256, s.PublicKey(), challenge, sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
	// Wrong challenge — verify must fail.
	if err := Verify(vault.KeyTypeP256, s.PublicKey(), []byte("wrong"), sig); err == nil {
		t.Fatal("verify should have failed for wrong challenge")
	}
}

func TestFileBackend_LoadTriesBothTypes(t *testing.T) {
	b := tmpBackend(t)
	t.Setenv("DOP_ALLOW_FILE_KEYS", "1")

	// Only ed25519 exists: Load should return the ed25519 store.
	if _, err := b.Generate("lookup-c", vault.KeyTypeEd25519); err != nil {
		t.Fatal(err)
	}
	s, err := b.Load("lookup-c")
	if err != nil || s.KeyType() != vault.KeyTypeEd25519 {
		t.Fatalf("expected ed25519, got %v/%s", err, s.KeyType())
	}

	// Only p256 exists.
	if _, err := b.Generate("lookup-d", vault.KeyTypeP256); err != nil {
		t.Fatal(err)
	}
	s, err = b.Load("lookup-d")
	if err != nil || s.KeyType() != vault.KeyTypeP256 {
		t.Fatalf("expected p256, got %v/%s", err, s.KeyType())
	}

	// Delete removes both files.
	if err := b.Delete("lookup-c"); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Load("lookup-c"); err != ErrNotFound {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}

func TestFileBackend_RefusesLoosePerms(t *testing.T) {
	b := tmpBackend(t)
	s, err := b.Generate("lookup-e", vault.KeyTypeEd25519)
	if err != nil {
		t.Fatal(err)
	}
	// Chmod to 0644 → load must refuse.
	path := b.edPath(s.LookupID())
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Load("lookup-e"); err == nil {
		t.Fatal("expected refusal on loose perms")
	}
}
