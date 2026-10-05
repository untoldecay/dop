// Package printapproval runs the tunnel+phone fallback for the
// print-approval flow when the admin daemon's local popup isn't
// available (timeout, daemon unreachable, platform unsupported).
//
// Shape mirrors `dop claim` approval:
//   1. Start a small HTTP server on 127.0.0.1:<random-port>.
//   2. Optionally spawn `cloudflared` for a public URL.
//   3. Print URL + terminal QR to stderr.
//   4. Wait for a POST /approve with the passphrase.
//   5. Verify via `internal/approval.Verify`; rate-limit on failure.
//   6. Return decision; clean up tunnel + server.
//
// Deliberately independent from `internal/approvalserver` because
// that server is tightly coupled to `pendingclaim.Record` (claim-
// specific fields). Reimplementing the server here is ~200 lines
// vs. ~500 for a generic refactor of approvalserver.
package printapproval

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"html"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mdp/qrterminal/v3"

	"github.com/fray/dop/internal/approval"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/tunnel"
)

// Decision is the human's answer, same vocabulary as approvalserver.
type Decision string

const (
	DecisionApproved Decision = "approved"
	DecisionRejected Decision = "rejected"
	DecisionExpired  Decision = "expired"
)

// Request bundles the inputs for Run.
type Request struct {
	Paths   *config.Paths
	Kind    string        // "print_use" / "print_issue" / "print_env" / "print_claim"
	Subject string        // bearer subject or similar
	TTL     time.Duration // overall wait budget; defaults to 5min
}

// Run spins up the fallback server, prints URL+QR to stderr, blocks
// until the human approves/rejects or TTL expires. Idempotent on
// cleanup — safe to defer-cancel the ctx without extra bookkeeping.
func Run(ctx context.Context, req Request) (Decision, error) {
	if req.Paths == nil {
		return "", errors.New("printapproval: Paths required")
	}
	if req.TTL <= 0 {
		req.TTL = 5 * time.Minute
	}

	// 1. Pick a random high port + bind.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("listen: %w", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port

	// 2. Build the display token (16 random hex).
	displayToken, err := newDisplayToken()
	if err != nil {
		return "", err
	}

	srv := newServer(req, displayToken)
	httpSrv := &http.Server{Handler: srv}
	srvDone := make(chan error, 1)
	go func() { srvDone <- httpSrv.Serve(ln) }()

	// 3. Try to spawn a tunnel. LAN-only fallback is fine for operators
	// whose phone is on the same network.
	var publicURL string
	tctx, tcancel := context.WithCancel(ctx)
	defer tcancel()
	t, terr := tunnel.Start(tctx, port, 15*time.Second)
	if terr == nil && t != nil {
		publicURL = t.URL
		defer t.Stop()
	}
	if publicURL == "" {
		// LAN fallback — look up a non-loopback IP.
		if ip := nonLoopbackIP(); ip != "" {
			publicURL = fmt.Sprintf("http://%s:%d/c/%s", ip, port, displayToken)
		} else {
			publicURL = fmt.Sprintf("http://127.0.0.1:%d/c/%s", port, displayToken)
		}
	} else {
		publicURL = strings.TrimRight(publicURL, "/") + "/c/" + displayToken
	}

	// 4. Print URL + QR to stderr.
	fmt.Fprintln(os.Stderr)
	fmt.Fprintf(os.Stderr, "dop %s: local approval unavailable — falling back to phone.\n", req.Kind)
	fmt.Fprintf(os.Stderr, "  Subject: %s\n", req.Subject)
	fmt.Fprintf(os.Stderr, "  URL: %s\n", publicURL)
	fmt.Fprintln(os.Stderr, "  Scan the QR on your phone or open the URL in a browser,")
	fmt.Fprintln(os.Stderr, "  then type your approval passphrase.")
	fmt.Fprintln(os.Stderr)
	qrterminal.GenerateHalfBlock(publicURL, qrterminal.L, os.Stderr)
	fmt.Fprintln(os.Stderr)

	// 5. Wait for decision OR TTL expiry OR ctx cancellation.
	timer := time.NewTimer(req.TTL)
	defer timer.Stop()
	select {
	case d := <-srv.decisionCh:
		shutdownHTTP(httpSrv)
		return d, nil
	case <-timer.C:
		shutdownHTTP(httpSrv)
		return DecisionExpired, nil
	case <-ctx.Done():
		shutdownHTTP(httpSrv)
		return DecisionExpired, ctx.Err()
	}
}

func shutdownHTTP(s *http.Server) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_ = s.Shutdown(ctx)
}

func newDisplayToken() (string, error) {
	// 16 hex = 8 bytes random.
	var b [8]byte
	for i := range b {
		b[i] = byte(rand.Uint32())
	}
	return hex.EncodeToString(b[:]), nil
}

// --- server ---

type server struct {
	req          Request
	displayToken string

	mu         sync.Mutex
	decided    bool
	failures   int
	decisionCh chan Decision
}

const maxFailures = 8

func newServer(req Request, displayToken string) *server {
	return &server{
		req:          req,
		displayToken: displayToken,
		decisionCh:   make(chan Decision, 1),
	}
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Route: GET /c/<token> → form; POST /c/<token>/approve → verify.
	path := strings.TrimPrefix(r.URL.Path, "/c/")
	if path == r.URL.Path {
		http.NotFound(w, r)
		return
	}
	segs := strings.SplitN(path, "/", 2)
	if len(segs) == 0 || segs[0] != s.displayToken {
		http.NotFound(w, r) // don't leak existence
		return
	}
	// Check decided state up-front.
	s.mu.Lock()
	if s.decided {
		s.mu.Unlock()
		http.Error(w, "already decided", http.StatusGone)
		return
	}
	s.mu.Unlock()

	if r.Method == http.MethodGet && (len(segs) == 1 || segs[1] == "") {
		s.renderForm(w, "")
		return
	}
	if r.Method == http.MethodPost && len(segs) == 2 && segs[1] == "approve" {
		s.handleApprove(w, r)
		return
	}
	if r.Method == http.MethodPost && len(segs) == 2 && segs[1] == "reject" {
		s.handleReject(w, r)
		return
	}
	http.NotFound(w, r)
}

func (s *server) renderForm(w http.ResponseWriter, errMsg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	// Mobile-first, no external resources. CSS inline.
	page := `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DOP approval</title>
<style>
body{font-family:-apple-system,BlinkMacSystemFont,system-ui,sans-serif;margin:0;padding:1.5rem;background:#fafafa;color:#111;}
@media(prefers-color-scheme:dark){body{background:#111;color:#eee;}input,button{background:#222;color:#eee;border-color:#444;}}
h1{font-size:1.3rem;margin:0 0 1rem 0;}
.subject{font-family:ui-monospace,monospace;background:#eee;padding:.5rem;border-radius:4px;margin-bottom:1rem;}
@media(prefers-color-scheme:dark){.subject{background:#222;}}
input[type=password]{width:100%;box-sizing:border-box;padding:1rem;font-size:1rem;border:1px solid #ccc;border-radius:6px;margin-bottom:1rem;}
button{min-height:44px;padding:1rem;font-size:1rem;border:1px solid #ccc;border-radius:6px;background:#fff;color:#111;cursor:pointer;}
button.primary{background:#0a7cff;color:#fff;border-color:#0a7cff;}
button.danger{background:#e03b3b;color:#fff;border-color:#e03b3b;}
.row{display:flex;gap:.5rem;}
.row button{flex:1;}
.err{color:#c00;margin-bottom:1rem;}
.hint{color:#666;font-size:.9rem;margin-top:1rem;}
@media(prefers-color-scheme:dark){.hint{color:#888;}}
</style></head><body>
<h1>Approve <code>` + html.EscapeString(s.req.Kind) + `</code>?</h1>
<div class="subject">` + html.EscapeString(s.req.Subject) + `</div>`
	if errMsg != "" {
		page += `<div class="err">` + html.EscapeString(errMsg) + `</div>`
	}
	page += `<form method="POST" action="/c/` + s.displayToken + `/approve">
<input type="password" name="passphrase" autofocus required placeholder="Approval passphrase">
<div class="row"><button type="submit" class="primary">Approve</button>
<button type="submit" formaction="/c/` + s.displayToken + `/reject" formmethod="POST" class="danger">Deny</button></div>
</form>
<div class="hint">A dop process on your machine is waiting for approval to print the secret above.</div>
</body></html>`
	_, _ = io.WriteString(w, page)
}

func (s *server) handleApprove(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	pass := r.PostFormValue("passphrase")
	ok, verr := approval.Verify(s.req.Paths, pass)
	if verr != nil {
		http.Error(w, "verify error", http.StatusInternalServerError)
		return
	}
	s.mu.Lock()
	if s.decided {
		s.mu.Unlock()
		http.Error(w, "already decided", http.StatusGone)
		return
	}
	if !ok {
		s.failures++
		remaining := maxFailures - s.failures
		if remaining <= 0 {
			s.decided = true
			s.mu.Unlock()
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, `<!doctype html><html><body><p>Too many failed attempts. Request auto-rejected.</p></body></html>`)
			s.decisionCh <- DecisionRejected
			return
		}
		s.mu.Unlock()
		s.renderForm(w, fmt.Sprintf("Wrong passphrase. %d attempts remaining.", remaining))
		return
	}
	s.decided = true
	s.mu.Unlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, `<!doctype html><html><body><p>Approved. You can close this page.</p></body></html>`)
	s.decisionCh <- DecisionApproved
}

func (s *server) handleReject(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	if s.decided {
		s.mu.Unlock()
		http.Error(w, "already decided", http.StatusGone)
		return
	}
	s.decided = true
	s.mu.Unlock()
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = io.WriteString(w, `<!doctype html><html><body><p>Denied. You can close this page.</p></body></html>`)
	s.decisionCh <- DecisionRejected
}

func nonLoopbackIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if v4 := ipnet.IP.To4(); v4 != nil {
				return v4.String()
			}
		}
	}
	return ""
}
