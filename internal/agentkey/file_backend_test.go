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

// v1.12: MigrateLookupID renames the file and keeps the key valid.
func TestFileBackend_MigrateLookupID(t *testing.T) {
	t.Setenv("DOP_ALLOW_FILE_KEYS", "1")
	b := tmpBackend(t)
	s, err := b.Generate("lookup-old", vault.KeyTypeP256)
	if err != nil {
		t.Fatalf("gen: %v", err)
	}
	oldPub := s.PublicKey()
	migrator, ok := s.(LookupMigrator)
	if !ok {
		t.Fatal("fileP256Store should implement LookupMigrator")
	}
	if err := migrator.MigrateLookupID("lookup-new"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if s.LookupID() != "lookup-new" {
		t.Fatalf("LookupID after migrate: %s", s.LookupID())
	}
	// Same key: pubkey unchanged, sign still verifies.
	if !PubkeyEqual(s.PublicKey(), oldPub) {
		t.Fatal("pubkey changed after migrate")
	}
	sig, err := s.Sign([]byte("chal"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Verify(vault.KeyTypeP256, oldPub, []byte("chal"), sig); err != nil {
		t.Fatalf("post-migrate verify: %v", err)
	}
	// Old file gone, new file present.
	loaded, err := b.Load("lookup-new")
	if err != nil {
		t.Fatalf("load new: %v", err)
	}
	if !PubkeyEqual(loaded.PublicKey(), oldPub) {
		t.Fatal("loaded pubkey mismatch")
	}
	if _, err := b.Load("lookup-old"); err == nil {
		t.Fatal("old lookup should be gone after migrate")
	}
}

// v1.12: SharedSecret returns ErrECDHUnsupported for ed25519.
func TestFileBackend_Ed25519_SharedSecret_Unsupported(t *testing.T) {
	b := tmpBackend(t)
	s, err := b.Generate("lookup-ed", vault.KeyTypeEd25519)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	_, err = s.SharedSecret(make([]byte, 65))
	if err == nil {
		t.Fatal("ed25519 SharedSecret should return ErrECDHUnsupported")
	}
	if err != ErrECDHUnsupported {
		t.Fatalf("wrong error: %v", err)
	}
}

// v1.12: P-256 file-backed key's SharedSecret is a symmetric-key
// candidate — proves the store contract for the pure-Go path.
// The SE-backed store is exercised through Sign in field tests; this
// test protects the Go-side plumbing.
func TestFileBackend_P256_SharedSecret_Symmetric(t *testing.T) {
	t.Setenv("DOP_ALLOW_FILE_KEYS", "1")
	// Two independent P-256 keys — simulate admin ephemeral + agent.
	b := tmpBackend(t)
	agentStore, err := b.Generate("lookup-ecdh", vault.KeyTypeP256)
	if err != nil {
		t.Fatalf("agent gen: %v", err)
	}
	peerStore, err := b.Generate("lookup-ecdh-peer", vault.KeyTypeP256)
	if err != nil {
		t.Fatalf("peer gen: %v", err)
	}
	// Alice's shared(peer_pub) must equal Bob's shared(alice_pub).
	sharedA, err := agentStore.SharedSecret(peerStore.PublicKey())
	if err != nil {
		t.Fatalf("agent side: %v", err)
	}
	sharedB, err := peerStore.SharedSecret(agentStore.PublicKey())
	if err != nil {
		t.Fatalf("peer side: %v", err)
	}
	if string(sharedA) != string(sharedB) {
		t.Fatalf("ECDH not symmetric: A=%x B=%x", sharedA, sharedB)
	}
	if len(sharedA) != 32 {
		t.Fatalf("P-256 shared secret should be 32B, got %d", len(sharedA))
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
