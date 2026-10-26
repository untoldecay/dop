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
	"github.com/fray/dop/internal/approvalcard"
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

	// Rate limiting for the approve endpoint. See handleApprove.
	rateFailures int
	rateWindow   time.Time

	// PublicURL is set by the caller once the tunnel is up — used only
	// for display / QR / return payload.
	PublicURL string
}

// approveRateMax is the hardcoded ceiling on failed-passphrase attempts
// per approval window. Passphrase entropy + argon2id cost + this cap
// = guessing is infeasible before the 5-min TTL expires.
const approveRateMax = 8

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
//	GET  /c/<token>          — approval page
//	POST /c/<token>/approve  — approve (requires passphrase)
//	POST /c/<token>/reject   — reject (no passphrase; you scanned the QR)
//	GET  /                   — 404 (no landing)
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
	// Shared rate limit — check the pending file's failure count so the
	// web endpoint and `dop approve` CLI share the same 8-attempt cap.
	// A same-uid attacker can't split attempts across the two paths.
	cur, ferr := pendingclaim.Read(s.Paths, s.Pending.LookupID)
	if ferr == nil && cur != nil && cur.FailureCount >= pendingclaim.MaxFailures {
		s.markDecided(DecisionRejected)
		http.Error(w, "too many failed passphrase attempts — claim aborted.", http.StatusTooManyRequests)
		return
	}

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
		newCount, autoReject, berr := pendingclaim.BumpFailure(s.Paths, s.Pending.LookupID)
		if berr != nil {
			// Fall back to in-memory counter so we don't fail-open on
			// a filesystem hiccup — better false-positive than
			// unlimited attempts.
			s.mu.Lock()
			s.rateFailures++
			newCount = s.rateFailures
			s.mu.Unlock()
			autoReject = newCount >= pendingclaim.MaxFailures
		}
		remaining := pendingclaim.MaxFailures - newCount
		if autoReject || remaining <= 0 {
			s.markDecided(DecisionRejected)
			http.Error(w, "too many failed passphrase attempts — claim aborted.", http.StatusTooManyRequests)
			return
		}
		s.renderPage(w, fmt.Sprintf("incorrect passphrase (%d attempt(s) left before this claim is aborted)", remaining), "")
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

// pageTmpl — mobile-first, no JS, no external assets.
// Breakpoints:
//   base (<= 480px):  full-bleed layout, 16px root, 44px tap targets
//   >= 481px         : centered card, still comfortable on tablet + desktop
//
// The page respects `prefers-color-scheme` so it looks native in either
// mode on iOS/Android. Autofocus is off on iOS to avoid the keyboard
// yanking the form off-screen before the user has looked at the details.

func (s *Server) renderPage(w http.ResponseWriter, errMsg, _ string) {
	pubShort := s.Pending.Pubkey
	if len(pubShort) > 24 {
		pubShort = pubShort[:24] + "…"
	}
	host := s.Pending.Host
	if host == "" {
		host = "(unknown host)"
	}
	card := approvalcard.Card{Kind: approvalcard.KindClaim, Subject: s.Pending.Subject,
		Who: "agent key " + pubShort, Where: host, Code: s.Pending.SAS, Expires: s.Pending.ExpiresAt}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = approvalcard.Page(w, approvalcard.Form{Card: card, Error: errMsg,
		Action: "/c/" + s.DisplayToken + "/approve", RejectAction: "/c/" + s.DisplayToken + "/reject",
		Left: time.Until(s.Pending.ExpiresAt).Round(time.Second).String()})
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
