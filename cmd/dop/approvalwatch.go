// Approval watcher — v1.21 (dop-5j8). While the admin session daemon
// runs on a Mac with a GUI, it pulls the vault repo every few seconds
// and puts up the native dialog for questions that arrived from other
// machines: remote claims and lease requests. The dialog is the same
// one local approvals use (contract 07), rendered from an approval card
// (contract 27); for a lease the middle button cycles the duration.
//
// Deny / Escape / timeout leave the request pending for the TUI; the
// dialog never rejects on its own. A wrong passphrase re-asks on the
// next tick; a denial or a timeout asks once per request.

package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/fray/dop/internal/approvalcard"
	"github.com/fray/dop/internal/approvalprompt"
	"github.com/fray/dop/internal/audit"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/remoteclaim"
	"github.com/fray/dop/internal/remoteuse"
	"github.com/fray/dop/internal/userprefs"
)

type approvalWatcher struct {
	paths   *config.Paths
	timeout time.Duration
	// seams for tests
	pull   func()
	prompt func(card approvalcard.Card, lease bool) (approvalprompt.Result, error)
	run    func(args []string, stdin string) error
	// touches names the grants of a subject (what the lease / claim
	// reaches); nil or "" when the vault can't be read right now.
	touches func(subject string) string
	seen    map[string]bool      // settled: approved, or denied by the operator
	asked   map[string]time.Time // last time the dialog was shown for an id
	reask   time.Duration        // a dialog nobody answered comes back after this
	report  func(string)         // what `dop admin status` shows for the watcher
	tally   struct {
		asked int
		last  string
	}
}

func newApprovalWatcher(paths *config.Paths) *approvalWatcher {
	w := &approvalWatcher{paths: paths, timeout: userprefs.Load(paths).ApprovalTimeout(), seen: map[string]bool{},
		reask: envDuration("DOP_WATCH_REASK", 3*time.Minute)}
	w.pull = func() { _ = autoPullAndMerge(paths) }
	w.prompt = func(card approvalcard.Card, lease bool) (approvalprompt.Result, error) {
		body := card.Body()
		if f := card.Footer(); f != "" {
			body += "\n\n" + f
		}
		body += "\n\n" + approvalcard.Passphrase + ":"
		if lease {
			return approvalprompt.AskLease(card.Title(), body, approvalcard.LeaseDurations, card.Default, w.timeout)
		}
		return approvalprompt.Ask(card.Title(), body, w.timeout)
	}
	w.touches = func(subject string) string {
		client, err := requireAdminSession(paths)
		if err != nil {
			return ""
		}
		v, _, err := loadVaultViaDaemon(client, paths)
		if err != nil {
			return ""
		}
		if _, crec, err := findActiveCapBySubject(v, subject); err == nil {
			return strings.Join(crec.Grants, ", ")
		}
		return ""
	}
	w.run = func(args []string, stdin string) error {
		self, err := os.Executable()
		if err != nil {
			return err
		}
		cmd := exec.Command(self, args...)
		cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_NO_POPUP=1")
		cmd.Stdin = strings.NewReader(stdin + "\n")
		var stderr strings.Builder
		cmd.Stderr = &stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("%s", strings.TrimSpace(stderr.String()))
		}
		return nil
	}
	return w
}

// loop runs until the process ends (the daemon exits with the session).
func (w *approvalWatcher) loop(every time.Duration) {
	for {
		time.Sleep(every)
		w.tick()
	}
}

// pending is one question to ask, already turned into a card.
type pendingQuestion struct {
	id    string
	card  approvalcard.Card
	lease bool
	args  func(choice string) []string // approve command, choice = lease duration
}

// scan lists the unanswered, unexpired questions in the vault repo.
func (w *approvalWatcher) scan() []pendingQuestion {
	now := time.Now()
	var out []pendingQuestion
	if reqs, err := remoteuse.ListRequests(w.paths); err == nil {
		for _, r := range reqs {
			if now.After(r.ExpiresAt) {
				continue
			}
			if _, answered := remoteuse.ReadLease(w.paths, r.RequestID); answered == nil {
				continue
			}
			who := r.AgentName
			if signed, err := r.Verify(); err != nil {
				continue // a bad signature never reaches the dialog
			} else if signed {
				who += " (signed by its agent key)"
			} else {
				who += " (unsigned request)"
			}
			id := r.RequestID
			out = append(out, pendingQuestion{
				id:    "lease:" + id,
				lease: true,
				card: approvalcard.Card{Kind: approvalcard.KindLease, Subject: r.Subject, Who: who, Where: r.Host,
					Touches: w.touchesOf(r.Subject), Expires: r.ExpiresAt, Options: approvalcard.LeaseOptions(), Default: 0},
				args: func(choice string) []string {
					return []string{"approve-remote", "--use", id, "--lease", choice, "--passphrase-stdin"}
				},
			})
		}
	}
	if claims, err := remoteclaim.List(w.paths); err == nil {
		for _, c := range claims {
			if now.After(c.ExpiresAt) || c.Verify() != nil {
				continue
			}
			subject := c.Subject
			out = append(out, pendingQuestion{
				id: "claim:" + c.LookupID,
				card: approvalcard.Card{Kind: approvalcard.KindRemoteClaim, Subject: subject,
					Who: "agent key " + c.EffectiveKeyType(), Where: c.Host, Touches: w.touchesOf(subject), Expires: c.ExpiresAt},
				args: func(string) []string {
					return []string{"approve-remote", "--subject", subject, "--passphrase-stdin"}
				},
			})
		}
	}
	return out
}

func (w *approvalWatcher) touchesOf(subject string) string {
	if w.touches == nil {
		return ""
	}
	return w.touches(subject)
}

// tick pulls, scans, and asks one open question at a time. A question
// the operator denied is settled; one nobody answered (timeout, Escape)
// comes back after `reask` while the request lives — rc3: a dialog that
// closed on its 60 s timeout while the operator was away never returned,
// and the request sat in the TUI only.
func (w *approvalWatcher) tick() {
	w.pull()
	if w.asked == nil {
		w.asked = map[string]time.Time{}
	}
	qs := w.scan()
	defer w.status(len(qs))
	for _, q := range qs {
		if w.seen[q.id] {
			continue
		}
		if t, ok := w.asked[q.id]; ok && time.Since(t) < w.reask {
			continue
		}
		w.asked[q.id] = time.Now()
		w.tally.asked++
		res, err := w.prompt(q.card, q.lease)
		if err != nil {
			w.note(q, "no dialog: "+err.Error())
			return // no GUI right now; the TUI still has it
		}
		switch {
		case res.Denied:
			w.seen[q.id] = true
			w.note(q, "denied")
			continue
		case !res.Approved:
			w.note(q, "unanswered") // timeout / Escape: back after reask
			continue
		}
		pass := res.Passphrase
		res.Passphrase = ""
		if err := w.run(q.args(res.Choice), pass); err != nil {
			// Wrong passphrase or a transient failure: ask again next tick.
			delete(w.asked, q.id)
			w.note(q, "approve failed: "+err.Error())
		} else {
			w.seen[q.id] = true
			w.note(q, "approved "+res.Choice)
		}
		return // one dialog per tick keeps the screen calm
	}
}

// note records one dialog outcome in the audit log (`dop watch --filter
// approval_dialog`) and in the status line. Never the passphrase.
func (w *approvalWatcher) note(q pendingQuestion, result string) {
	w.tally.last = fmt.Sprintf("%s %s → %s at %s", q.card.Kind, q.card.Subject, result, time.Now().Format("15:04:05"))
	audit.Append(w.paths, audit.Event{Kind: "approval_dialog", Subject: q.card.Subject, Host: q.card.Where,
		Extra: map[string]string{"id": q.id, "result": result}})
}

func (w *approvalWatcher) status(pending int) {
	if w.report == nil {
		return
	}
	s := fmt.Sprintf("on · checked %s · %d pending · %d dialog(s) shown", time.Now().Format("15:04:05"), pending, w.tally.asked)
	if w.tally.last != "" {
		s += " · last: " + w.tally.last
	}
	w.report(s)
}
