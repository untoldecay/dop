package envseal

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"strings"
	"testing"
)

// mustAgentKey generates a P-256 keypair for the tests. In real life
// the agent's private half lives in the Secure Enclave and only the
// public half is on disk; the tests use crypto/ecdh directly to
// exercise the primitive without dragging in the SE bridge.
func mustAgentKey(t *testing.T) (*ecdh.PrivateKey, []byte) {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("agent keygen: %v", err)
	}
	return priv, priv.PublicKey().Bytes()
}

func TestSealOpen_Roundtrip(t *testing.T) {
	agentPriv, agentPub := mustAgentKey(t)
	plaintext := []byte(`{"NOTION_TOKEN":"ntn_xxx","BOILER_TOKEN":"bl_yyy"}`)
	aad := []byte("lookup=abc123 gen=7")

	sealed, err := Seal(agentPub, plaintext, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if len(sealed.AdminEphemPub) != 65 || sealed.AdminEphemPub[0] != 0x04 {
		t.Fatalf("ephem pub not uncompressed X9.62: len=%d, tag=%02x", len(sealed.AdminEphemPub), sealed.AdminEphemPub[0])
	}
	if len(sealed.Salt) != 32 {
		t.Fatalf("salt len=%d, want 32", len(sealed.Salt))
	}
	if len(sealed.Nonce) != 24 {
		t.Fatalf("nonce len=%d, want 24 (XChaCha20)", len(sealed.Nonce))
	}
	if len(sealed.Ciphertext) < len(plaintext)+16 {
		t.Fatalf("ciphertext suspiciously short: %d < %d+16", len(sealed.Ciphertext), len(plaintext))
	}

	got, err := OpenWithPriv(agentPriv, sealed, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("roundtrip mismatch: got %q, want %q", got, plaintext)
	}
}

func TestOpen_AADMismatch_Fails(t *testing.T) {
	agentPriv, agentPub := mustAgentKey(t)
	sealed, err := Seal(agentPub, []byte("secret"), []byte("aad-a"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := OpenWithPriv(agentPriv, sealed, []byte("aad-b")); err == nil {
		t.Fatal("expected AAD-mismatch to fail Open, got nil")
	}
}

func TestOpen_TamperedCiphertext_Fails(t *testing.T) {
	agentPriv, agentPub := mustAgentKey(t)
	sealed, err := Seal(agentPub, []byte("secret payload"), []byte("aad"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	// Flip a bit in the ciphertext body (before the tag).
	sealed.Ciphertext[0] ^= 0x01
	if _, err := OpenWithPriv(agentPriv, sealed, []byte("aad")); err == nil {
		t.Fatal("expected tampered ciphertext to fail Open, got nil")
	}
}

func TestOpen_TamperedNonce_Fails(t *testing.T) {
	agentPriv, agentPub := mustAgentKey(t)
	sealed, _ := Seal(agentPub, []byte("secret"), nil)
	sealed.Nonce[0] ^= 0x01
	if _, err := OpenWithPriv(agentPriv, sealed, nil); err == nil {
		t.Fatal("expected tampered nonce to fail Open, got nil")
	}
}

func TestOpen_TamperedEphemPub_Fails(t *testing.T) {
	agentPriv, agentPub := mustAgentKey(t)
	sealed, _ := Seal(agentPub, []byte("secret"), nil)
	// Swap the ephem pubkey for a different valid point → different
	// shared secret → key doesn't match → AEAD auth fails.
	other, _ := ecdh.P256().GenerateKey(rand.Reader)
	sealed.AdminEphemPub = other.PublicKey().Bytes()
	if _, err := OpenWithPriv(agentPriv, sealed, nil); err == nil {
		t.Fatal("expected swapped ephem pub to fail Open, got nil")
	}
}

func TestOpen_WrongAgentKey_Fails(t *testing.T) {
	// Seal to agent A, try to open with agent B's key.
	_, agentAPub := mustAgentKey(t)
	agentBPriv, _ := mustAgentKey(t)
	sealed, err := Seal(agentAPub, []byte("secret"), nil)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if _, err := OpenWithPriv(agentBPriv, sealed, nil); err == nil {
		t.Fatal("expected wrong-key open to fail, got nil")
	}
}

func TestHexRoundtrip(t *testing.T) {
	agentPriv, agentPub := mustAgentKey(t)
	sealed, err := Seal(agentPub, []byte("hex-roundtrip"), []byte("aad"))
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	m := sealed.ToHex()
	for k := range m {
		// Every hex string must be valid hex.
		if _, err := hex.DecodeString(m[k]); err != nil {
			t.Fatalf("hex field %q invalid: %v", k, err)
		}
	}
	restored, err := FromHex(m)
	if err != nil {
		t.Fatalf("FromHex: %v", err)
	}
	pt, err := OpenWithPriv(agentPriv, restored, []byte("aad"))
	if err != nil {
		t.Fatalf("Open after hex roundtrip: %v", err)
	}
	if string(pt) != "hex-roundtrip" {
		t.Fatalf("got %q", pt)
	}
}

func TestFromHex_MalformedField_Fails(t *testing.T) {
	m := map[string]string{
		"admin_ephem_pub": "not-hex-xxx",
		"salt":            "abcd",
		"nonce":           "abcd",
		"ciphertext":      "abcd",
	}
	if _, err := FromHex(m); err == nil {
		t.Fatal("expected FromHex to reject malformed hex, got nil")
	} else if !strings.Contains(err.Error(), "admin_ephem_pub") {
		t.Fatalf("error should name the bad field, got: %v", err)
	}
}

func TestSeal_InvalidAgentPub_Fails(t *testing.T) {
	// Not a valid P-256 point encoding.
	if _, err := Seal([]byte("hello"), []byte("secret"), nil); err == nil {
		t.Fatal("expected Seal to reject garbage agent pubkey, got nil")
	}
}

func TestOpenWithShared_EmptySecret_Fails(t *testing.T) {
	if _, err := OpenWithShared(nil, Sealed{}, nil); err == nil {
		t.Fatal("expected empty shared secret to error")
	}
}
