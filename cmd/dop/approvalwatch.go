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
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/remoteclaim"
	"github.com/fray/dop/internal/remoteuse"
	"github.com/fray/dop/internal/userprefs"
)

// leaseDurations are what the operator can pick in the dialog, shortest
// first; the CLI clamps to the bearer's cap.
var leaseDurations = []string{"10m", "30m", "1h"}

type approvalWatcher struct {
	paths   *config.Paths
	timeout time.Duration
	// seams for tests
	pull   func()
	prompt func(card approvalcard.Card, lease bool) (approvalprompt.Result, error)
	run    func(args []string, stdin string) error
	seen   map[string]bool // request / claim ids already asked
}

func newApprovalWatcher(paths *config.Paths) *approvalWatcher {
	w := &approvalWatcher{paths: paths, timeout: userprefs.Load(paths).ApprovalTimeout(), seen: map[string]bool{}}
	w.pull = func() { _ = autoPullAndMerge(paths) }
	w.prompt = func(card approvalcard.Card, lease bool) (approvalprompt.Result, error) {
		body := card.Body()
		if f := card.Footer(); f != "" {
			body += "\n\n" + f
		}
		body += "\n\nApproval passphrase:"
		if lease {
			return approvalprompt.AskLease(card.Title(), body, leaseDurations, card.Default, w.timeout)
		}
		return approvalprompt.Ask(card.Title(), body, w.timeout)
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
					Expires: r.ExpiresAt, Options: leaseOptions(), Default: 0},
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
					Who: "agent key " + c.EffectiveKeyType(), Where: c.Host, Expires: c.ExpiresAt},
				args: func(string) []string {
					return []string{"approve-remote", "--subject", subject, "--passphrase-stdin"}
				},
			})
		}
	}
	return out
}

func leaseOptions() []approvalcard.Option {
	labels := map[string]string{"10m": "10 min", "30m": "30 min", "1h": "1 hour"}
	var o []approvalcard.Option
	for _, d := range leaseDurations {
		o = append(o, approvalcard.Option{Label: labels[d], Value: d})
	}
	return o
}

// tick pulls, scans, and asks one unseen question at a time.
func (w *approvalWatcher) tick() {
	w.pull()
	for _, q := range w.scan() {
		if w.seen[q.id] {
			continue
		}
		w.seen[q.id] = true
		res, err := w.prompt(q.card, q.lease)
		if err != nil {
			return // no GUI right now; the TUI still has it
		}
		if !res.Approved {
			continue // deny / escape / timeout: leave it pending, ask once
		}
		pass := res.Passphrase
		res.Passphrase = ""
		if err := w.run(q.args(res.Choice), pass); err != nil {
			// Wrong passphrase or a transient failure: ask again next tick.
			delete(w.seen, q.id)
		}
		return // one dialog per tick keeps the screen calm
	}
}
