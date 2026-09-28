package capability

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

// --- envelope round-trip ---

func TestWriteRead_RoundTrip(t *testing.T) {
	bearer := "tok_1deadbeef"
	capID, _ := NewCapabilityID()
	env := map[string]string{
		"NOTION_TOKEN": "ntn_secret",
		"NOTION_URL":   "https://api.notion.com/v1",
	}
	exp := time.Now().Add(24 * time.Hour)

	var buf bytes.Buffer
	if _, err := Write(&buf, WriteOpts{
		CapabilityID: capID,
		Bearer:       bearer,
		Generation:   1,
		ExpiresAt:    exp,
		Env:          env,
	}); err != nil {
		t.Fatal(err)
	}

	got, hdr, err := Read(buf.Bytes(), ReadOpts{Bearer: bearer})
	if err != nil {
		t.Fatal(err)
	}
	if hdr.Generation != 1 {
		t.Fatalf("generation: %d", hdr.Generation)
	}
	if got.Env["NOTION_TOKEN"] != "ntn_secret" {
		t.Fatalf("env not preserved: %v", got.Env)
	}
	if got.Env["NOTION_URL"] != "https://api.notion.com/v1" {
		t.Fatalf("env not preserved: %v", got.Env)
	}
}

func TestRead_WrongBearer(t *testing.T) {
	capID, _ := NewCapabilityID()
	var buf bytes.Buffer
	Write(&buf, WriteOpts{
		CapabilityID: capID, Bearer: "tok_correct",
		Generation: 1, ExpiresAt: time.Now().Add(time.Hour),
		Env: map[string]string{"K": "V"},
	})
	_, _, err := Read(buf.Bytes(), ReadOpts{Bearer: "tok_wrong"})
	if err == nil {
		t.Fatal("expected error with wrong bearer")
	}
}

func TestRead_TamperedCiphertext(t *testing.T) {
	capID, _ := NewCapabilityID()
	var buf bytes.Buffer
	Write(&buf, WriteOpts{
		CapabilityID: capID, Bearer: "tok_x",
		Generation: 1, ExpiresAt: time.Now().Add(time.Hour),
		Env: map[string]string{"K": "V"},
	})
	b := buf.Bytes()
	// Flip a byte in the ciphertext region.
	b[len(b)-1] ^= 0xFF
	_, _, err := Read(b, ReadOpts{Bearer: "tok_x"})
	if err == nil {
		t.Fatal("expected error on tampered ciphertext")
	}
}

func TestRead_TamperedHeader(t *testing.T) {
	capID, _ := NewCapabilityID()
	var buf bytes.Buffer
	Write(&buf, WriteOpts{
		CapabilityID: capID, Bearer: "tok_x",
		Generation: 1, ExpiresAt: time.Now().Add(time.Hour),
		Env: map[string]string{"K": "V"},
	})
	b := buf.Bytes()
	// Tamper with generation field (offset 40).
	b[40+CapabilityIDBytes]++ // bump generation LSB
	_, _, err := Read(b, ReadOpts{Bearer: "tok_x"})
	if err == nil {
		t.Fatal("expected error on tampered header (AEAD AAD mismatch)")
	}
}

func TestRead_Expired(t *testing.T) {
	capID, _ := NewCapabilityID()
	var buf bytes.Buffer
	Write(&buf, WriteOpts{
		CapabilityID: capID, Bearer: "tok_x",
		Generation: 1, ExpiresAt: time.Now().Add(-time.Second), // already past
		Env: map[string]string{"K": "V"},
	})
	_, _, err := Read(buf.Bytes(), ReadOpts{Bearer: "tok_x"})
	if err == nil || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("expected expired error, got %v", err)
	}
}

func TestRead_GenerationRollback(t *testing.T) {
	capID, _ := NewCapabilityID()
	var buf bytes.Buffer
	Write(&buf, WriteOpts{
		CapabilityID: capID, Bearer: "tok_x",
		Generation: 3, ExpiresAt: time.Now().Add(time.Hour),
		Env: map[string]string{"K": "V"},
	})
	_, _, err := Read(buf.Bytes(), ReadOpts{Bearer: "tok_x", MinGeneration: 5})
	if err == nil || !strings.Contains(err.Error(), "superseded") {
		t.Fatalf("expected superseded error, got %v", err)
	}
}

func TestRead_ShortBundle(t *testing.T) {
	_, _, err := Read([]byte{1, 2, 3}, ReadOpts{Bearer: "tok_x"})
	if err == nil {
		t.Fatal("expected error on short bundle")
	}
}

func TestRead_BadMagic(t *testing.T) {
	b := make([]byte, MinBundleBytes)
	// leave magic as zeros — not "DOPB"
	_, _, err := Read(b, ReadOpts{Bearer: "tok_x"})
	if err == nil || !strings.Contains(err.Error(), "magic") {
		t.Fatalf("expected magic error, got %v", err)
	}
}

// --- domain separation ---

func TestDeriveWrapKey_DomainSeparation(t *testing.T) {
	bearer := "tok_1"
	var capA, capB [CapabilityIDBytes]byte
	capA[0] = 1
	capB[0] = 2
	kA, _ := deriveWrapKey(bearer, capA)
	kB, _ := deriveWrapKey(bearer, capB)
	if kA == kB {
		t.Fatal("different capability ids must derive different K_wrap")
	}
}

// --- bearer + lookup id helpers ---

func TestNewBearer_Shape(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		b, err := NewBearer()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(b, "tok_1") {
			t.Fatalf("bad prefix: %q", b)
		}
		if len(b) != len("tok_1")+32 {
			t.Fatalf("bad length: %d", len(b))
		}
		if seen[b] {
			t.Fatal("collision — vanishingly unlikely, but happened")
		}
		seen[b] = true
	}
}

func TestLookupID_StableAndOpaque(t *testing.T) {
	ctx := []byte("vault-context-random-bytes-12345")
	a := LookupID(ctx, "tok_a")
	b := LookupID(ctx, "tok_a")
	if a != b {
		t.Fatal("lookup id not deterministic")
	}
	c := LookupID(ctx, "tok_b")
	if a == c {
		t.Fatal("different bearers must map to different lookup ids")
	}
	if len(a) != 40 {
		t.Fatalf("expected 40-hex lookup id, got %d", len(a))
	}
	// Different vault context yields a different id even for the same bearer.
	otherCtx := []byte("different-vault-context-value_98")
	d := LookupID(otherCtx, "tok_a")
	if a == d {
		t.Fatal("lookup id must depend on vault context")
	}
}

// --- signing ---

func TestRecord_SignVerify(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rec := Record{
		CapabilityID: "abc123",
		Subject:      "research-agent",
		Grants:       []string{"notion.read"},
		CreatedAt:    time.Now().UTC().Round(time.Second),
		ExpiresAt:    time.Now().Add(24 * time.Hour).UTC().Round(time.Second),
		Generation:   1,
		LookupID:     "dead",
		BundleHash:   "cafe",
		Status:       RecordStatusActive,
	}
	if err := rec.Sign(priv); err != nil {
		t.Fatal(err)
	}
	if rec.Signature == "" {
		t.Fatal("signature not set")
	}
	if err := rec.Verify(); err != nil {
		t.Fatalf("verify failed: %v", err)
	}
}

func TestRecord_VerifyDetectsMutation(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	rec := Record{
		CapabilityID: "abc", Subject: "s",
		Grants: []string{"g"}, Generation: 1,
		LookupID: "l", BundleHash: "h", Status: RecordStatusActive,
		CreatedAt: time.Now().UTC(),
		ExpiresAt: time.Now().Add(time.Hour).UTC(),
	}
	rec.Sign(priv)
	// Mutate the grants list; signature no longer matches payload.
	rec.Grants = []string{"g", "other"}
	if err := rec.Verify(); err == nil {
		t.Fatal("expected verify to fail after mutation")
	}
}

func TestRecord_VerifyDetectsForgedSig(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	rec := Record{
		CapabilityID: "abc", Subject: "s", Grants: []string{"g"},
		Generation: 1, LookupID: "l", BundleHash: "h",
		Status:    RecordStatusActive,
		CreatedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(time.Hour).UTC(),
	}
	rec.Sign(priv)
	// Replace with an attacker-signed sig.
	_, attackerPriv, _ := ed25519.GenerateKey(rand.Reader)
	forged, _ := (Record{
		CapabilityID: "abc", Subject: "elevated", // attacker tries to promote subject
		Grants: []string{"g", "admin.everything"}, Generation: 999,
		LookupID: "l", BundleHash: "h", Status: RecordStatusActive,
		CreatedAt: rec.CreatedAt, ExpiresAt: rec.ExpiresAt,
	}).SigningPayload()
	forgedSig := ed25519.Sign(attackerPriv, forged)
	rec.Signature = hexEncode(forgedSig)
	// IssuedBy is still the real admin's pubkey → verify fails.
	if err := rec.Verify(); err == nil {
		t.Fatal("expected verify to fail with forged sig")
	}
}

// tiny helper to avoid pulling encoding/hex in the test file directly
func hexEncode(b []byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, x := range b {
		out[i*2] = hexDigits[x>>4]
		out[i*2+1] = hexDigits[x&0xF]
	}
	return string(out)
}

func TestHashBundle_Stable(t *testing.T) {
	b := []byte("some bytes")
	a := HashBundle(b)
	c := HashBundle(b)
	if a != c {
		t.Fatal("hash not deterministic")
	}
	d := HashBundle([]byte("other"))
	if a == d {
		t.Fatal("hash collision on trivial inputs")
	}
}
