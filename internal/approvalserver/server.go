// Package approvalserver serves the small approval web page used by
// v1.6+. A `dop claim` spawns a listener, hands a one-shot Server to
// this package, and waits on Server.Decision() until either the human
// approves via the web form or the claim expires.
//
// Threat model:
//   - The URL is public (goes through Cloudflare Tunnel) and reachable
//     from any device with the QR / link. That's fine: viewing the page
//     confers no power. All approval authority is in the passphrase.
//   - The passphrase is verified via argon2id (approval package). A
//     wrong guess is rate-limited by argon cost (~200ms/attempt) — an
//     attacker with the URL cannot brute-force the passphrase within
//     the 2-min claim window.
//   - The one-shot display token in the URL identifies the specific
//     claim without leaking a bearer or pubkey to third parties who
//     might see the URL in a logs pipe.
package approvalserver

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/fray/dop/internal/approval"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/pendingclaim"
)

// Decision represents the human's answer.
type Decision string

const (
	DecisionApproved Decision = "approved"
	DecisionRejected Decision = "rejected"
	DecisionExpired  Decision = "expired"
)

// Server is a single-claim HTTP handler. Wire it into any http.Server;
// on the first successful POST it signals via the channel returned by
// Wait() and refuses further requests.
type Server struct {
	Paths        *config.Paths
	Pending      pendingclaim.Record // snapshot at server-start time
	DisplayToken string              // random hex checked in URL path

	mu       sync.Mutex
	decided  bool
	decision Decision
	doneCh   chan Decision

	// PublicURL is set by the caller once the tunnel is up — used only
	// for display / QR / return payload.
	PublicURL string
}

// NewDisplayToken returns 16 random hex chars for URL routing.
func NewDisplayToken() (string, error) {
	var b [8]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// New builds a Server. The caller supplies the pending record + a
// display token (must match what's baked into the QR URL).
func New(paths *config.Paths, p pendingclaim.Record, displayToken string) *Server {
	return &Server{
		Paths:        paths,
		Pending:      p,
		DisplayToken: displayToken,
		doneCh:       make(chan Decision, 1),
	}
}

// Wait blocks until a decision is reached, ctx is done, or the pending
// claim's own TTL passes. Returns the decision (or DecisionExpired).
func (s *Server) Wait(ctx context.Context) Decision {
	timer := time.NewTimer(time.Until(s.Pending.ExpiresAt))
	defer timer.Stop()
	select {
	case d := <-s.doneCh:
		return d
	case <-timer.C:
		s.markDecided(DecisionExpired)
		return DecisionExpired
	case <-ctx.Done():
		s.markDecided(DecisionExpired)
		return DecisionExpired
	}
}

// Handler returns an http.Handler that serves:
//
//   GET  /c/<token>          — approval page
//   POST /c/<token>/approve  — approve (requires passphrase)
//   POST /c/<token>/reject   — reject (no passphrase; you scanned the QR)
//   GET  /                   — 404 (no landing)
//
// Any request with the wrong token 404s. There's no directory listing;
// unknown tokens don't reveal whether a pending claim exists.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.serve)
	return mux
}

func (s *Server) serve(w http.ResponseWriter, r *http.Request) {
	// Route: /c/<token>[/action]
	path := strings.Trim(r.URL.Path, "/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[0] != "c" {
		http.NotFound(w, r)
		return
	}
	if !constantTimeEqual(parts[1], s.DisplayToken) {
		http.NotFound(w, r)
		return
	}
	action := ""
	if len(parts) >= 3 {
		action = parts[2]
	}

	s.mu.Lock()
	decided := s.decided
	s.mu.Unlock()
	if decided {
		http.Error(w, "this claim has already been decided.", http.StatusGone)
		return
	}
	if time.Now().After(s.Pending.ExpiresAt) {
		http.Error(w, "this claim has expired.", http.StatusGone)
		return
	}

	switch {
	case r.Method == http.MethodGet && action == "":
		s.renderPage(w, "", "")
	case r.Method == http.MethodPost && action == "approve":
		s.handleApprove(w, r)
	case r.Method == http.MethodPost && action == "reject":
		s.renderResult(w, "Rejected. You can close this tab.")
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		s.markDecided(DecisionRejected)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleApprove(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.renderPage(w, "malformed form", "")
		return
	}
	pw := r.PostForm.Get("passphrase")
	if pw == "" {
		s.renderPage(w, "passphrase required", "")
		return
	}
	ok, err := approval.Verify(s.Paths, pw)
	if err != nil {
		if errors.Is(err, approval.ErrNotSet) {
			s.renderPage(w, "no approval passphrase configured on this DOP install", "")
			return
		}
		s.renderPage(w, "verify: "+err.Error(), "")
		return
	}
	if !ok {
		// Constant-cost mismatch: argon2 already made this slow.
		s.renderPage(w, "incorrect passphrase", "")
		return
	}
	// Write the response FIRST so it starts flushing to the client
	// before we signal the caller (which may tear down the tunnel).
	s.renderResult(w, "Approved. You can close this tab.")
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	s.markDecided(DecisionApproved)
}

// markDecided is idempotent — first caller wins.
func (s *Server) markDecided(d Decision) {
	s.mu.Lock()
	if s.decided {
		s.mu.Unlock()
		return
	}
	s.decided = true
	s.decision = d
	s.mu.Unlock()
	// non-blocking send: doneCh is buffered (1).
	select {
	case s.doneCh <- d:
	default:
	}
}

// ---- rendering ----

// pageTmpl is intentionally minimal — no JS, no external assets. Works
// on any phone browser, no CSP surprises.
var pageTmpl = template.Must(template.New("page").Parse(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>DOP · approve claim</title>
<style>
  html,body{margin:0;padding:0;font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:#111;color:#eee}
  .wrap{max-width:420px;margin:2rem auto;padding:1.5rem;background:#1a1a1a;border-radius:10px}
  h1{font-size:1.1rem;color:#f5c93a;margin:0 0 1rem}
  dl{margin:0 0 1.5rem;font-size:.95rem}
  dt{color:#888;margin-top:.5rem}
  dd{margin:.1rem 0 0;word-break:break-all}
  label{display:block;font-size:.85rem;color:#888;margin:1rem 0 .25rem}
  input[type=password]{width:100%;padding:.6rem;background:#000;border:1px solid #333;color:#eee;border-radius:6px;font-size:1rem;box-sizing:border-box}
  .row{display:flex;gap:.5rem;margin-top:1rem}
  button{flex:1;padding:.7rem;border:0;border-radius:6px;font-size:.95rem;cursor:pointer}
  .approve{background:#10b981;color:#000;font-weight:600}
  .reject{background:#333;color:#eee}
  .err{color:#ef4444;font-size:.85rem;margin:.5rem 0 0}
  .ok{color:#10b981}
  form{margin:0}
</style></head><body><div class="wrap">
<h1>DOP · agent claim pending</h1>
<dl>
<dt>subject</dt><dd>{{.Subject}}</dd>
<dt>agent pubkey</dt><dd>{{.PubkeyShort}}</dd>
<dt>SAS</dt><dd>{{.SAS}}</dd>
<dt>expires in</dt><dd>{{.TTLLeft}}</dd>
</dl>
<form method="POST" action="/c/{{.Token}}/approve">
  <label for="p">Approval passphrase</label>
  <input id="p" name="passphrase" type="password" autocomplete="current-password" autofocus>
  {{if .Error}}<p class="err">{{.Error}}</p>{{end}}
  <div class="row">
    <button class="approve" type="submit">Approve</button>
    <button class="reject" type="submit" formaction="/c/{{.Token}}/reject" formmethod="POST">Reject</button>
  </div>
</form>
</div></body></html>`))

func (s *Server) renderPage(w http.ResponseWriter, errMsg, _ string) {
	pubShort := s.Pending.Pubkey
	if len(pubShort) > 24 {
		pubShort = pubShort[:24] + "…"
	}
	data := struct {
		Subject     string
		PubkeyShort string
		SAS         string
		TTLLeft     string
		Error       string
		Token       string
	}{
		Subject:     s.Pending.Subject,
		PubkeyShort: pubShort,
		SAS:         s.Pending.SAS,
		TTLLeft:     time.Until(s.Pending.ExpiresAt).Round(time.Second).String(),
		Error:       errMsg,
		Token:       s.DisplayToken,
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = pageTmpl.Execute(w, data)
}

func (s *Server) renderResult(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!doctype html><html><body style="font-family:sans-serif;padding:2rem;background:#111;color:#eee"><p>%s</p></body></html>`, template.HTMLEscapeString(msg))
}

// constantTimeEqual is a constant-time comparison of two ASCII-ish
// strings (no length leak).
func constantTimeEqual(a, b string) bool {
	return hmac.Equal([]byte(a), []byte(b))
}
