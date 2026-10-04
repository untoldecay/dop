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

	"github.com/fray/dop/internal/approval"
	"github.com/fray/dop/internal/approvalprompt"
	"github.com/fray/dop/internal/config"
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
	// v1.14.0-rc4 — Paths let the daemon reach the approval.hash
	// without a round-trip through the client. Needed for the
	// local-popup approval RPC.
	paths *config.Paths

	idleTTL time.Duration
	absTTL  time.Duration

	mu           sync.Mutex
	startedAt    time.Time
	lastActivity time.Time

	// v1.14.0-rc6 — shell trust cache for the eval/pipe pattern. Key is
	// "<pid>:<subject>". Set when a non-tty approval goes through on a
	// read surface (dop use, dop env); subsequent same-shell/same-subject
	// invocations pass without re-prompting. In-memory only; stale PIDs
	// after a shell dies are harmless (next shell has a new PID). Full
	// clear on admin logout (daemon exits). Protected by `mu`.
	trustedShells map[string]bool

	done chan struct{}

	// Optional: nowFn overrides time.Now for tests.
	nowFn func() time.Time
}

// SessionOpts configures StartSession.
type SessionOpts struct {
	Keys     *Keys
	Paths    *config.Paths // v1.14.0-rc4 — enables local approval popup
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
		keys:          opts.Keys,
		paths:         opts.Paths,
		sockPath:      opts.SockPath,
		listener:      lst,
		idleTTL:       opts.IdleTTL,
		absTTL:        opts.AbsTTL,
		startedAt:     now,
		lastActivity:  now,
		trustedShells: map[string]bool{},
		done:          make(chan struct{}),
		nowFn:         opts.NowFn,
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
	// Verify the peer runs as the same uid as this daemon. The socket
	// is already mode 0600 in a 0700 directory, but peer-cred adds
	// defense against fd inheritance, race conditions, and any
	// non-obvious path a different-uid process might reach the socket.
	if uid, err := peerUID(conn); err != nil {
		WriteMessage(conn, Response{Error: "peer-cred: " + err.Error()})
		return
	} else if uid != uint32(os.Geteuid()) {
		WriteMessage(conn, Response{Error: "peer uid mismatch"})
		return
	}
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
	case OpUnwrapPortable:
		return s.opUnwrapPortable(req.Data)
	case OpApprovalPopup:
		return s.opApprovalPopup(req.Data)
	case OpShellTrust:
		return s.opShellTrust(req.Data)
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

// opUnwrapPortable — v1.14.0-rc1. Decrypts a bearer value that was
// stashed at `token issue --portable` time (wrapped to the
// admin's own age recipient). Used by `dop use <subject>` to retrieve
// the bearer so the shell can set DOP_TOKEN.
//
// Only works while the session is unlocked (the age identity lives
// in s.keys.Age, same as DecryptVault). Returns the plaintext bearer
// as base64 so JSON stays binary-safe, mirroring DecryptVaultResp.
func (s *Session) opUnwrapPortable(payload []byte) Response {
	var req UnwrapPortableReq
	if err := json.Unmarshal(payload, &req); err != nil {
		return Response{Error: "unwrap_portable: bad payload"}
	}
	if req.CiphertextB64 == "" {
		return Response{Error: "unwrap_portable: ciphertext_b64 required"}
	}
	s.mu.Lock()
	if s.keys == nil {
		s.mu.Unlock()
		return Response{Error: "unwrap_portable: session locked"}
	}
	id := s.keys.Age
	s.mu.Unlock()
	plaintext, err := UnwrapWithIdentity(req.CiphertextB64, id)
	if err != nil {
		return Response{Error: "unwrap_portable: " + err.Error()}
	}
	s.bumpActivity()
	body, _ := json.Marshal(UnwrapPortableResp{
		PlaintextB64: base64.StdEncoding.EncodeToString(plaintext),
	})
	return okResp(body)
}

func okResp(data []byte) Response {
	return Response{OK: true, Data: data}
}

// opApprovalPopup — v1.14.0-rc4. Daemon-side handler for the local
// approval fast-path. Opens a native OS dialog (osascript on darwin),
// collects the typed passphrase, verifies against approval.hash, and
// returns the decision. Supports:
//   - approved: Approve clicked + passphrase verified
//   - denied: Deny / Cancel clicked
//   - timeout: dialog closed by its "giving up after" clause
//   - unsupported: platform without a native dialog OR
//     DOP_NO_POPUP=1 — caller falls back to tunnel+phone
//
// The typed passphrase lives only inside this handler's stack frame
// for the ~1 ms it takes to run Verify + zero it. Never written to disk,
// never passed through the socket to the caller.
func (s *Session) opApprovalPopup(payload []byte) Response {
	var req ApprovalPopupReq
	if err := json.Unmarshal(payload, &req); err != nil {
		return Response{Error: "approval_popup: bad payload"}
	}
	s.mu.Lock()
	if s.keys == nil {
		s.mu.Unlock()
		return Response{Error: "approval_popup: session locked"}
	}
	paths := s.paths
	s.mu.Unlock()
	// DOP_NO_POPUP escape hatch for headless CI running on macOS where
	// osascript would still succeed but there's no human to click.
	if os.Getenv("DOP_NO_POPUP") == "1" {
		body, _ := json.Marshal(ApprovalPopupResp{Decision: "unsupported", Reason: "DOP_NO_POPUP=1"})
		return okResp(body)
	}
	title := "DOP — " + req.Kind
	body := req.PromptText
	if body == "" {
		body = fmt.Sprintf("Approve %s for %q?", req.Kind, req.Subject)
	}
	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	res, err := approvalprompt.Ask(title, body, timeout)
	if err != nil {
		if errors.Is(err, approvalprompt.ErrUnsupported) {
			out, _ := json.Marshal(ApprovalPopupResp{Decision: "unsupported", Reason: err.Error()})
			return okResp(out)
		}
		return Response{Error: "approval_popup: " + err.Error()}
	}
	switch {
	case res.Timeout:
		out, _ := json.Marshal(ApprovalPopupResp{Decision: "timeout"})
		return okResp(out)
	case res.Denied:
		out, _ := json.Marshal(ApprovalPopupResp{Decision: "denied"})
		return okResp(out)
	case res.Approved:
		ok, verr := approval.Verify(paths, res.Passphrase)
		// Zero the passphrase as soon as Verify returns.
		res.Passphrase = ""
		if verr != nil {
			return Response{Error: "approval_popup: verify: " + verr.Error()}
		}
		if !ok {
			out, _ := json.Marshal(ApprovalPopupResp{Decision: "denied", Reason: "wrong_passphrase"})
			return okResp(out)
		}
		s.bumpActivity()
		out, _ := json.Marshal(ApprovalPopupResp{Decision: "approved"})
		return okResp(out)
	default:
		out, _ := json.Marshal(ApprovalPopupResp{Decision: "denied", Reason: "no_button"})
		return okResp(out)
	}
}

// opShellTrust — v1.14.0-rc6. Check or mark a (PID, subject) in the
// in-memory trust cache. Used by printguard to skip the approval
// popup on same-shell/same-subject repeat invocations after the
// first eval already got a passphrase.
func (s *Session) opShellTrust(payload []byte) Response {
	var req ShellTrustReq
	if err := json.Unmarshal(payload, &req); err != nil {
		return Response{Error: "shell_trust: bad payload"}
	}
	if req.PID <= 0 || req.Subject == "" {
		return Response{Error: "shell_trust: pid+subject required"}
	}
	key := fmt.Sprintf("%d:%s", req.PID, req.Subject)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.trustedShells == nil {
		s.trustedShells = map[string]bool{}
	}
	switch req.Mode {
	case "check":
		out, _ := json.Marshal(ShellTrustResp{Trusted: s.trustedShells[key]})
		return okResp(out)
	case "mark":
		s.trustedShells[key] = true
		out, _ := json.Marshal(ShellTrustResp{Trusted: true})
		return okResp(out)
	default:
		return Response{Error: "shell_trust: unknown mode " + req.Mode}
	}
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
