// v1.14.0-rc1 — admin-use wrap/unwrap primitives. Round-trips a
// bearer-looking string through WrapToRecipient → UnwrapWithIdentity
// and verifies that a mismatched identity fails to decrypt.

package admin

import (
	"strings"
	"testing"

	"filippo.io/age"
)

func TestWrapUnwrap_Roundtrip(t *testing.T) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("gen identity: %v", err)
	}
	bearer := "tok_1a2b3c4d5e6f7890abcdef"
	ct, err := WrapToRecipient([]byte(bearer), id.Recipient().String())
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if ct == "" {
		t.Fatal("empty ciphertext")
	}
	plain, err := UnwrapWithIdentity(ct, id)
	if err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if string(plain) != bearer {
		t.Fatalf("roundtrip mismatch: got %q, want %q", plain, bearer)
	}
}

func TestWrap_UsesPublicRecipientOnly(t *testing.T) {
	// Encryption must only need the recipient string — the client
	// side has no identity, only Status().AgeRecipient.
	id, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("gen identity: %v", err)
	}
	recipient := id.Recipient().String()
	ct1, err := WrapToRecipient([]byte("hello"), recipient)
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	// Nondeterministic (age uses random ephemeral) — just verify a
	// second wrap produces a decryptable (but likely different) ciphertext.
	ct2, _ := WrapToRecipient([]byte("hello"), recipient)
	if ct1 == ct2 {
		t.Error("expected non-deterministic encryption")
	}
	plain, err := UnwrapWithIdentity(ct2, id)
	if err != nil || string(plain) != "hello" {
		t.Fatalf("unwrap ct2: plain=%q err=%v", plain, err)
	}
}

func TestUnwrap_WrongIdentityFails(t *testing.T) {
	id1, _ := age.GenerateX25519Identity()
	id2, _ := age.GenerateX25519Identity()
	ct, err := WrapToRecipient([]byte("secret"), id1.Recipient().String())
	if err != nil {
		t.Fatalf("wrap: %v", err)
	}
	if _, err := UnwrapWithIdentity(ct, id2); err == nil {
		t.Fatal("expected unwrap failure with wrong identity")
	}
}

func TestWrap_BadRecipient(t *testing.T) {
	_, err := WrapToRecipient([]byte("x"), "not-an-age-recipient")
	if err == nil || !strings.Contains(err.Error(), "parse age recipient") {
		t.Fatalf("expected parse error, got %v", err)
	}
}

func TestUnwrap_BadBase64(t *testing.T) {
	id, _ := age.GenerateX25519Identity()
	if _, err := UnwrapWithIdentity("!!!not-base64!!!", id); err == nil {
		t.Fatal("expected base64 error")
	}
}
