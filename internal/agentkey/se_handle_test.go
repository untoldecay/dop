//go:build darwin && cgo

// dop-ofn: Secure Enclave keys persisted as SE handles (no keychain
// item, no entitlement). Skipped where there is no Secure Enclave
// (VMs, CI runners).

package agentkey

import (
	"crypto/ecdh"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

func seRoot(t *testing.T) *config.Paths {
	t.Helper()
	if err := ProbeSecureEnclave(); err != nil {
		t.Skipf("no Secure Enclave here: %v", err)
	}
	t.Setenv("DOP_NO_KEYCHAIN", "")
	return &config.Paths{Root: t.TempDir()}
}

func TestSEHandleCreateSignReload(t *testing.T) {
	p := seRoot(t)
	s, err := Create(p, "lookup-a", vault.KeyTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	if s.Extractable() || s.KeyType() != vault.KeyTypeP256 || !strings.Contains(s.StorageDescription(), "Secure Enclave") {
		t.Fatalf("want a non-extractable SE p256 key, got %s", s.StorageDescription())
	}
	raw, err := os.ReadFile(filepath.Join(p.Root, "agent-keys", "lookup-a.se"))
	if err != nil || !strings.HasPrefix(string(raw), seHandleMagic) {
		t.Fatalf("handle file missing or malformed: %v", err)
	}
	msg := []byte("dop-v1-exec:lookup-a:cap")
	sig, err := s.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if err := Verify(vault.KeyTypeP256, s.PublicKey(), msg, sig); err != nil {
		t.Fatalf("signature from the SE key doesn't verify: %v", err)
	}
	r, err := OpenByType(p, "lookup-a", vault.KeyTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	if !PubkeyEqual(r.PublicKey(), s.PublicKey()) {
		t.Fatal("reloaded handle gives a different key")
	}
}

func TestSEHandleECDH(t *testing.T) {
	p := seRoot(t)
	s, err := Create(p, "lookup-b", vault.KeyTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	peer, _ := ecdh.P256().GenerateKey(rand.Reader)
	got, err := s.SharedSecret(peer.PublicKey().Bytes())
	if err != nil {
		t.Fatal(err)
	}
	sePub, err := ecdh.P256().NewPublicKey(s.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	want, _ := peer.ECDH(sePub)
	if string(got) != string(want) {
		t.Fatal("SE ECDH secret differs from the peer's")
	}
}

func TestSEHandleMigrateAndDelete(t *testing.T) {
	p := seRoot(t)
	s, err := Create(p, "old", vault.KeyTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.(LookupMigrator).MigrateLookupID("new"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(p.Root, "agent-keys", "old.se")); !os.IsNotExist(err) {
		t.Fatal("old handle should be gone after migration")
	}
	if _, err := OpenByType(p, "new", vault.KeyTypeP256); err != nil {
		t.Fatalf("migrated handle should load: %v", err)
	}
	if err := Delete(p, "new"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(p.Root, "agent-keys", "new.se")); !os.IsNotExist(err) {
		t.Fatal("handle should be deleted")
	}
}

func TestSEHandleCorruptedIsAnError(t *testing.T) {
	p := seRoot(t)
	if _, err := Create(p, "bad", vault.KeyTypeP256); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(p.Root, "agent-keys", "bad.se")
	if err := os.WriteFile(path, []byte(seHandleMagic+"garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenByType(p, "bad", vault.KeyTypeP256); err == nil || !strings.Contains(err.Error(), "not usable on this Mac") {
		t.Fatalf("want a clear 'not usable' error, got %v", err)
	}
}
