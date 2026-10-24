package remoteuse

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"testing"
	"time"

	"github.com/fray/dop/internal/agentkey"
	"github.com/fray/dop/internal/vault"
)

// A request signed by an agent key verifies; a tampered one does not;
// an unsigned one reports unsigned without error.
func TestRequestSignVerify(t *testing.T) {
	t.Setenv("DOP_ALLOW_FILE_KEYS", "1")
	store, err := agentkey.NewFileBackend(t.TempDir()).Generate("lk", vault.KeyTypeP256)
	if err != nil {
		t.Fatal(err)
	}
	r := Request{RequestID: "id", Subject: "cam-shell", Host: "vps", Recipient: "age1x", RequestedAt: time.Now(), ExpiresAt: time.Now().Add(TTL), Nonce: "n"}
	if signed, err := r.Verify(); signed || err != nil {
		t.Fatalf("unsigned request: signed=%v err=%v", signed, err)
	}
	if err := r.Sign(store); err != nil {
		t.Fatal(err)
	}
	if signed, err := r.Verify(); !signed || err != nil {
		t.Fatalf("signed request: signed=%v err=%v", signed, err)
	}
	r.Subject = "other"
	if _, err := r.Verify(); err == nil {
		t.Fatal("tampered request verified")
	}
}

// A lease verifies only when signed by a trusted admin key, and not
// after any field changes.
func TestLeaseVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	l := Lease{RequestID: "id", Subject: "cam-shell", LeaseSubject: "cam-shell@vps", ExpiresAt: time.Now().Add(10 * time.Minute),
		Ciphertext: "c3VwZXI=", ApprovedAt: time.Now(), Approver: hex.EncodeToString(pub)}
	payload, _ := l.SigningPayload()
	l.Signature = hex.EncodeToString(ed25519.Sign(priv, payload))
	trusted := map[string]bool{hex.EncodeToString(pub): true}
	if err := l.Verify(trusted); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := l.Verify(map[string]bool{}); err == nil {
		t.Fatal("untrusted approver verified")
	}
	l.ExpiresAt = l.ExpiresAt.Add(time.Hour)
	if err := l.Verify(trusted); err == nil {
		t.Fatal("tampered lease verified")
	}
}
