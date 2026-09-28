// Session runs inside the admin daemon process. It owns the unwrapped
// keys and serves RPCs over a unix socket until TTL expiry or explicit
// logout.
//
// TTL semantics:
//   - idleTTL: time since last activity. Reset on every non-status RPC.
//   - absTTL:  wall-clock time since session started. Not reset.
//   - Session exits when either exceeds its limit.

package admin

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

// Default TTLs. Overridable at Session creation.
const (
	DefaultIdleTTL = 15 * time.Minute
	DefaultAbsTTL  = 60 * time.Minute
)

// Session holds the unwrapped admin keys and serves RPCs on a unix socket.
// A single instance corresponds to one `dop admin login`.
type Session struct {
	keys     *Keys
	sockPath string
	listener net.Listener

	idleTTL time.Duration
	absTTL  time.Duration

	mu           sync.Mutex
	startedAt    time.Time
	lastActivity time.Time

	done chan struct{}

	// Optional: nowFn overrides time.Now for tests.
	nowFn func() time.Time
}

// SessionOpts configures StartSession.
type SessionOpts struct {
	Keys     *Keys
	SockPath string        // path to unix socket to create
	IdleTTL  time.Duration // default 15min
	AbsTTL   time.Duration // default 60min
	NowFn    func() time.Time
}

// StartSession creates the unix socket, begins accepting connections, and
// returns a Session. The caller is responsible for calling Session.Wait
// (or Session.Shutdown) to reap it.
func StartSession(opts SessionOpts) (*Session, error) {
	if opts.Keys == nil {
		return nil, errors.New("session: keys required")
	}
	if opts.SockPath == "" {
		return nil, errors.New("session: sock path required")
	}
	if opts.IdleTTL <= 0 {
		opts.IdleTTL = DefaultIdleTTL
	}
	if opts.AbsTTL <= 0 {
		opts.AbsTTL = DefaultAbsTTL
	}
	// Ensure parent dir exists with restrictive mode.
	if err := os.MkdirAll(filepath.Dir(opts.SockPath), 0o700); err != nil {
		return nil, err
	}
	// If a stale socket exists (previous daemon crash), remove it.
	// This is best-effort — a real running daemon on this path would
	// still accept, and Listen below would fail then.
	_ = os.Remove(opts.SockPath)

	lst, err := net.Listen("unix", opts.SockPath)
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	if err := os.Chmod(opts.SockPath, 0o600); err != nil {
		lst.Close()
		return nil, err
	}
	now := time.Now()
	if opts.NowFn != nil {
		now = opts.NowFn()
	}
	s := &Session{
		keys:         opts.Keys,
		sockPath:     opts.SockPath,
		listener:     lst,
		idleTTL:      opts.IdleTTL,
		absTTL:       opts.AbsTTL,
		startedAt:    now,
		lastActivity: now,
		done:         make(chan struct{}),
		nowFn:        opts.NowFn,
	}
	go s.acceptLoop()
	go s.ttlLoop()
	return s, nil
}

func (s *Session) now() time.Time {
	if s.nowFn != nil {
		return s.nowFn()
	}
	return time.Now()
}

// Wait blocks until the session shuts down.
func (s *Session) Wait() {
	<-s.done
}

// Shutdown is idempotent — safe to call multiple times.
func (s *Session) Shutdown() {
	select {
	case <-s.done:
		return
	default:
	}
	close(s.done)
	if s.listener != nil {
		s.listener.Close()
	}
	os.Remove(s.sockPath)
	// Zero out the key material in memory best-effort. Go doesn't
	// guarantee this survives GC, but it's better than leaving it.
	if s.keys != nil {
		for i := range s.keys.Ed25519 {
			s.keys.Ed25519[i] = 0
		}
		s.keys = nil
	}
}

func (s *Session) acceptLoop() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			// Listener closed → shutdown.
			return
		}
		go s.handleConn(conn)
	}
}

func (s *Session) ttlLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.mu.Lock()
			idleFor := s.now().Sub(s.lastActivity)
			absFor := s.now().Sub(s.startedAt)
			s.mu.Unlock()
			if idleFor > s.idleTTL || absFor > s.absTTL {
				s.Shutdown()
				return
			}
		}
	}
}

func (s *Session) handleConn(conn net.Conn) {
	defer conn.Close()
	// Enforce per-connection read timeout — the client should send its
	// request promptly.
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	var req Request
	if err := ReadMessage(conn, &req); err != nil {
		WriteMessage(conn, Response{Error: "read: " + err.Error()})
		return
	}
	conn.SetReadDeadline(time.Time{})
	resp := s.dispatch(req)
	WriteMessage(conn, resp)
}

func (s *Session) dispatch(req Request) Response {
	switch req.Op {
	case OpStatus:
		return s.opStatus()
	case OpKeepAlive:
		s.bumpActivity()
		return okResp(nil)
	case OpLogout:
		// Send OK then shut down after the response has flushed.
		go func() {
			time.Sleep(50 * time.Millisecond)
			s.Shutdown()
		}()
		return okResp(nil)
	case OpSign:
		return s.opSign(req.Data)
	case OpDecryptVault:
		return s.opDecryptVault(req.Data)
	case OpEncryptVault:
		return s.opEncryptVault(req.Data)
	default:
		return Response{Error: "unknown op: " + req.Op}
	}
}

func (s *Session) bumpActivity() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastActivity = s.now()
}

func (s *Session) opStatus() Response {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Status is read-only; deliberately does NOT bump activity so
	// polling doesn't extend a session forever.
	pk := ""
	rec := ""
	if s.keys != nil {
		pk = s.keys.AdminPubkey()
		rec = s.keys.Age.Recipient().String()
	}
	data, _ := json.Marshal(StatusResp{
		Unlocked:         s.keys != nil,
		AdminPubkey:      pk,
		AgeRecipient:     rec,
		IdleTTLSeconds:   int64(s.idleTTL.Seconds()),
		AbsTTLSeconds:    int64(s.absTTL.Seconds()),
		StartedAtUnix:    s.startedAt.Unix(),
		LastActivityUnix: s.lastActivity.Unix(),
	})
	return okResp(data)
}

func (s *Session) opSign(payload []byte) Response {
	var req SignReq
	if err := json.Unmarshal(payload, &req); err != nil {
		return Response{Error: "sign: bad payload: " + err.Error()}
	}
	data, err := hex.DecodeString(req.DataHex)
	if err != nil {
		return Response{Error: "sign: hex: " + err.Error()}
	}
	s.mu.Lock()
	if s.keys == nil {
		s.mu.Unlock()
		return Response{Error: "sign: session locked"}
	}
	sig := ed25519.Sign(s.keys.Ed25519, data)
	s.mu.Unlock()
	s.bumpActivity()
	body, _ := json.Marshal(SignResp{SigHex: hex.EncodeToString(sig)})
	return okResp(body)
}

// opDecryptVault — Phase 3. Reads the encrypted vault file and returns
// the plaintext. Uses the daemon's age key (never leaves the process).
func (s *Session) opDecryptVault(payload []byte) Response {
	var req DecryptVaultReq
	if err := json.Unmarshal(payload, &req); err != nil {
		return Response{Error: "decrypt_vault: bad payload"}
	}
	s.mu.Lock()
	if s.keys == nil {
		s.mu.Unlock()
		return Response{Error: "decrypt_vault: session locked"}
	}
	// Set SOPS_AGE_KEY (in-process env) so the sops subprocess uses our
	// key without it touching the filesystem. Restore after.
	prev, hadPrev := os.LookupEnv("SOPS_AGE_KEY")
	os.Setenv("SOPS_AGE_KEY", s.keys.Age.String())
	s.mu.Unlock()

	cmd := exec.Command("sops", "--decrypt", "--input-type", "yaml", "--output-type", "yaml", req.VaultPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	// Restore env immediately.
	if hadPrev {
		os.Setenv("SOPS_AGE_KEY", prev)
	} else {
		os.Unsetenv("SOPS_AGE_KEY")
	}

	if err != nil {
		return Response{Error: fmt.Sprintf("sops decrypt: %s (%v)", stderr.String(), err)}
	}
	s.bumpActivity()
	body, _ := json.Marshal(DecryptVaultResp{PlaintextB64: base64.StdEncoding.EncodeToString(stdout.Bytes())})
	return okResp(body)
}

func (s *Session) opEncryptVault(payload []byte) Response {
	var req EncryptVaultReq
	if err := json.Unmarshal(payload, &req); err != nil {
		return Response{Error: "encrypt_vault: bad payload"}
	}
	plaintext, err := base64.StdEncoding.DecodeString(req.PlaintextB64)
	if err != nil {
		return Response{Error: "encrypt_vault: bad base64"}
	}
	if req.AgeRecipient == "" {
		return Response{Error: "encrypt_vault: recipient required"}
	}
	// Stage plaintext to a tempfile next to the vault so sops picks up
	// the right .sops.yaml (if any) — but we pass --age explicitly, so
	// this is robust to path-based config quirks.
	dir := filepath.Dir(req.VaultPath)
	tmp, err := os.CreateTemp(dir, ".dop-encrypt-*.yaml")
	if err != nil {
		return Response{Error: err.Error()}
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(plaintext); err != nil {
		tmp.Close()
		return Response{Error: err.Error()}
	}
	tmp.Close()

	cmd := exec.Command("sops", "--encrypt",
		"--age", req.AgeRecipient,
		"--input-type", "yaml", "--output-type", "yaml",
		"--output", req.VaultPath, tmpPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return Response{Error: fmt.Sprintf("sops encrypt: %s (%v)", stderr.String(), err)}
	}
	s.bumpActivity()
	return okResp(nil)
}

func okResp(data []byte) Response {
	return Response{OK: true, Data: data}
}

// --- context-cancellation helper for shutdown-on-context ---

// RunWithContext blocks until the session ends or ctx is cancelled.
func (s *Session) RunWithContext(ctx context.Context) {
	select {
	case <-s.done:
	case <-ctx.Done():
		s.Shutdown()
	}
}

// discard is a scratch io.Writer used by daemonize (below) to eat any
// stragglers on stdout/stderr after we've reported readiness.
type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

var _ io.Writer = discard{}
