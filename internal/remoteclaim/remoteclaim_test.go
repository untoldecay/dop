package remoteclaim

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/fray/dop/internal/agentkey"
	"github.com/fray/dop/internal/vault"
)

// Sign/Verify must round-trip for both agent key types and reject a
// request whose signed fields were edited after signing.
func TestSignVerifyBothKeyTypes(t *testing.T) {
	t.Setenv("DOP_ALLOW_FILE_KEYS", "1")
	for _, kt := range []string{vault.KeyTypeEd25519, vault.KeyTypeP256} {
		store, err := agentkey.NewFileBackend(t.TempDir()).Generate("lk-"+kt, kt)
		if err != nil {
			t.Fatalf("%s: generate: %v", kt, err)
		}
		r := Request{LookupID: "lk-" + kt, Subject: "bot", Host: "ci", NewGeneration: 2,
			RequestedAt: time.Now(), ExpiresAt: time.Now().Add(TTL)}
		if err := r.Sign(store); err != nil {
			t.Fatalf("%s: sign: %v", kt, err)
		}
		if r.KeyType != kt {
			t.Fatalf("%s: key_type not stamped: %q", kt, r.KeyType)
		}
		if err := r.Verify(); err != nil {
			t.Fatalf("%s: verify: %v", kt, err)
		}
		r.NewGeneration++
		if err := r.Verify(); err == nil {
			t.Fatalf("%s: tampered request verified", kt)
		}
	}
}

// A request staged by a pre-parity binary has no key_type; it must
// still verify as ed25519.
func TestLegacyRequestDefaultsToEd25519(t *testing.T) {
	store, err := agentkey.NewFileBackend(t.TempDir()).Generate("lk", vault.KeyTypeEd25519)
	if err != nil {
		t.Fatal(err)
	}
	// Legacy binaries signed a payload without key_type and never set it.
	r := Request{LookupID: "lk", Subject: "bot", Pubkey: hex.EncodeToString(store.PublicKey())}
	payload, err := signingPayload(r)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := store.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	r.Signature = hex.EncodeToString(sig)
	if r.EffectiveKeyType() != vault.KeyTypeEd25519 {
		t.Fatalf("effective key type %q", r.EffectiveKeyType())
	}
	if err := r.Verify(); err != nil {
		t.Fatalf("legacy verify: %v", err)
	}
}
