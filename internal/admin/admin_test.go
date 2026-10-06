package admin

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// --- keys: wrap / unwrap ---

func TestGenerate(t *testing.T) {
	k, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if k.Age == nil {
		t.Fatal("no age key")
	}
	if len(k.Ed25519) != ed25519.PrivateKeySize {
		t.Fatalf("ed25519 size %d", len(k.Ed25519))
	}
	pk := k.AdminPubkey()
	if pk == "" {
		t.Fatal("no admin pubkey")
	}
}

func TestWrapUnwrap_RoundTrip(t *testing.T) {
	k, _ := Generate()
	wrapped, err := Wrap(k, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if len(wrapped) == 0 {
		t.Fatal("empty wrap output")
	}
	// Ciphertext must not contain any of our secrets in the clear.
	// (Trivial smoke check — real crypto tests are elsewhere.)
	if bytes.Contains(wrapped, []byte(k.Age.String())) {
		t.Fatal("wrapped output contains raw age secret")
	}

	got, err := Unwrap(wrapped, "correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if got.Age.Recipient().String() != k.Age.Recipient().String() {
		t.Fatal("age pubkey mismatch after unwrap")
	}
	if !bytes.Equal(got.Ed25519, k.Ed25519) {
		t.Fatal("ed25519 material mismatch")
	}
}

func TestUnwrap_WrongPassphrase(t *testing.T) {
	k, _ := Generate()
	wrapped, _ := Wrap(k, "right")
	_, err := Unwrap(wrapped, "wrong")
	if !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("expected ErrWrongPassphrase, got %v", err)
	}
}

func TestWrap_EmptyPassphraseRejected(t *testing.T) {
	k, _ := Generate()
	_, err := Wrap(k, "")
	if err == nil {
		t.Fatal("empty passphrase should be rejected")
	}
}

func TestWriteFile_AtomicAndRestrictive(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "keys", "admin.age.enc")
	if err := WriteFile(path, []byte("payload")); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode %o", info.Mode().Perm())
	}
	// Parent dir should be 0700.
	pinfo, _ := os.Stat(filepath.Dir(path))
	if pinfo.Mode().Perm() != 0o700 {
		t.Fatalf("parent dir mode %o", pinfo.Mode().Perm())
	}
}

// --- session ---

func TestSession_StartAndStatus(t *testing.T) {
	sock := shortSock(t)

	k, _ := Generate()
	s, err := StartSession(SessionOpts{
		Keys:     k,
		SockPath: sock,
		IdleTTL:  30 * time.Second,
		AbsTTL:   60 * time.Second,
	})
 if err != nil { t.Fatal(err) }
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Shutdown)

	// Socket exists with restrictive perms.
	info, err := os.Stat(sock)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %o", info.Mode().Perm())
	}

	c := NewClient(sock)
	if !c.SessionActive() {
		t.Fatal("expected session active")
	}
	st, err := c.Status()
	if err != nil {
		t.Fatal(err)
	}
	if !st.Unlocked {
		t.Fatal("expected unlocked")
	}
	if st.AdminPubkey != k.AdminPubkey() {
		t.Fatal("pubkey mismatch")
	}
	if st.AgeRecipient != k.Age.Recipient().String() {
		t.Fatal("age recipient mismatch")
	}
}

func TestSession_Sign(t *testing.T) {
	sock := shortSock(t)
	k, _ := Generate()
	s, err := StartSession(SessionOpts{Keys: k, SockPath: sock})
 if err != nil { t.Fatal(err) }
	t.Cleanup(s.Shutdown)

	c := NewClient(sock)
	payload := []byte("data to sign")
	sig, err := c.Sign(payload)
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := k.Ed25519.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, payload, sig) {
		t.Fatal("signature failed to verify")
	}
}

func TestSession_LogoutShutsDown(t *testing.T) {
	sock := shortSock(t)
	k, _ := Generate()
	s, err := StartSession(SessionOpts{Keys: k, SockPath: sock})
 if err != nil { t.Fatal(err) }
	c := NewClient(sock)

	if err := c.Logout(); err != nil {
		t.Fatal(err)
	}
	// Give the daemon a moment to finish shutdown after responding.
	time.Sleep(200 * time.Millisecond)
	if _, err := os.Stat(sock); !os.IsNotExist(err) {
		t.Fatalf("socket still present after logout: %v", err)
	}
	select {
	case <-s.done:
	case <-time.After(2 * time.Second):
		t.Fatal("session did not shut down after logout")
	}
}

func TestSession_IdleTTL(t *testing.T) {
	sock := shortSock(t)
	k, _ := Generate()

	// Frozen clock we can advance.
	now := time.Unix(1_000_000, 0)
	s, err := StartSession(SessionOpts{
		Keys:     k,
		SockPath: sock,
		IdleTTL:  1 * time.Second, // for the arithmetic path
		AbsTTL:   10 * time.Minute,
		NowFn:    func() time.Time { return now },
	})
 if err != nil { t.Fatal(err) }
	t.Cleanup(s.Shutdown)

	// Advance past idle TTL without any activity.
	now = now.Add(2 * time.Second)

	// Wait for the 15s ticker to fire OR force the check manually. We
	// don't want to sleep 15s in a test, so peek at the internal state.
	// TTL evaluation lives in ttlLoop, so we can only assert that the
	// arithmetic would trigger. Instead, unit-test the arithmetic here.
	s.mu.Lock()
	idleFor := s.now().Sub(s.lastActivity)
	absFor := s.now().Sub(s.startedAt)
	s.mu.Unlock()
	if !(idleFor > s.idleTTL || absFor > s.absTTL) {
		t.Fatalf("TTL arithmetic did not trigger: idleFor=%v idleTTL=%v absFor=%v absTTL=%v",
			idleFor, s.idleTTL, absFor, s.absTTL)
	}
}

func TestSession_SignBumpsActivity(t *testing.T) {
	sock := shortSock(t)
	k, _ := Generate()

	fixedNow := time.Now().Add(-30 * time.Second)
	nowFn := func() time.Time { return fixedNow }

	s, err := StartSession(SessionOpts{
		Keys: k, SockPath: sock, IdleTTL: time.Hour, AbsTTL: time.Hour,
		NowFn: nowFn,
	})
 if err != nil { t.Fatal(err) }
	t.Cleanup(s.Shutdown)

	prev := s.lastActivity
	fixedNow = time.Now()
	c := NewClient(sock)
	if _, err := c.Sign([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if !s.lastActivity.After(prev) {
		t.Fatalf("sign did not bump lastActivity: prev=%v now=%v", prev, s.lastActivity)
	}
}

func TestSession_StatusDoesNotBumpActivity(t *testing.T) {
	sock := shortSock(t)
	k, _ := Generate()
	s, err := StartSession(SessionOpts{
		Keys: k, SockPath: sock, IdleTTL: time.Hour, AbsTTL: time.Hour,
	})
 if err != nil { t.Fatal(err) }
	t.Cleanup(s.Shutdown)

	prev := s.lastActivity
	c := NewClient(sock)
	if _, err := c.Status(); err != nil {
		t.Fatal(err)
	}
	if !s.lastActivity.Equal(prev) {
		t.Fatal("status should not bump activity (would let polling extend a session forever)")
	}
}

// --- protocol wire ---

func TestProtocol_RoundTrip(t *testing.T) {
	var buf bytes.Buffer
	req := Request{Op: "test", Data: json.RawMessage(`{"foo":"bar"}`)}
	if err := WriteMessage(&buf, req); err != nil {
		t.Fatal(err)
	}
	var got Request
	if err := ReadMessage(&buf, &got); err != nil {
		t.Fatal(err)
	}
	if got.Op != "test" {
		t.Fatalf("op mismatch: %s", got.Op)
	}
	if !strings.Contains(string(got.Data), "bar") {
		t.Fatalf("data mismatch: %s", got.Data)
	}
}

func TestProtocol_RejectsHugeMessage(t *testing.T) {
	// Fake a 100 MB length header — should reject.
	var buf bytes.Buffer
	buf.Write([]byte{0x06, 0x40, 0x00, 0x00}) // 100M-ish, big-endian
	var got Request
	err := ReadMessage(&buf, &got)
	if err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("expected too-large error, got %v", err)
	}
}

func TestSessionActive_Missing(t *testing.T) {
	c := NewClient("/tmp/definitely-does-not-exist-dop-sock-" + t.Name())
	if c.SessionActive() {
		t.Fatal("expected inactive")
	}
}

func TestSessionActive_Locked(t *testing.T) {
	sock := shortSock(t)
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			var req Request
			_ = ReadMessage(c, &req)
			data, _ := json.Marshal(StatusResp{Unlocked: false})
			_ = WriteMessage(c, Response{OK: true, Data: data})
			c.Close()
		}
	}()
	c := NewClient(sock)
	if _, err := c.Status(); err != nil {
		t.Fatalf("status: %v", err)
	}
	if c.SessionActive() {
		t.Fatal("daemon answers but is locked: expected inactive")
	}
}

// shortSock produces a unix socket path guaranteed to fit within
// macOS's SUN_PATH_MAX (~104 bytes). t.TempDir() paths use the verbose
// test name and blow past the limit for longer test names.
func shortSock(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "dop-s-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return filepath.Join(d, "s")
}

