package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/fray/dop/internal/approvalcard"
	"github.com/fray/dop/internal/approvalprompt"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/remoteuse"
)

// The watcher asks once per request, runs the approve command with the
// picked duration on approval, leaves denied ones pending, and re-asks
// after a failed run (wrong passphrase).
func TestApprovalWatcherLeaseFlow(t *testing.T) {
	paths := &config.Paths{Vault: t.TempDir()}
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(remoteuse.WriteRequest(paths, remoteuse.Request{RequestID: "aaaa1111", Subject: "cam-shell", Host: "vps", AgentName: "buzz-reader",
		Recipient: "age1x", RequestedAt: time.Now(), ExpiresAt: time.Now().Add(remoteuse.TTL), Nonce: "n"}))
	must(remoteuse.WriteRequest(paths, remoteuse.Request{RequestID: "bbbb2222", Subject: "old", Host: "vps",
		Recipient: "age1x", RequestedAt: time.Now().Add(-time.Hour), ExpiresAt: time.Now().Add(-time.Minute), Nonce: "n"}))

	var prompted []approvalcard.Card
	var ran [][]string
	var stdins []string
	w := &approvalWatcher{paths: paths, seen: map[string]bool{}, pull: func() {}, reask: time.Hour}
	w.prompt = func(_ context.Context, c approvalcard.Card, lease bool) (approvalprompt.Result, error) {
		prompted = append(prompted, c)
		if !lease {
			t.Fatal("lease request must use the lease dialog")
		}
		return approvalprompt.Result{Approved: true, Passphrase: "secret", Choice: "30m"}, nil
	}
	runErr := errors.New("incorrect passphrase")
	w.run = func(args []string, stdin string) error {
		ran = append(ran, args)
		stdins = append(stdins, stdin)
		return runErr
	}

	w.tick()
	if len(prompted) != 1 || prompted[0].Kind != approvalcard.KindLease || prompted[0].Subject != "cam-shell" {
		t.Fatalf("prompted %+v", prompted)
	}
	if !strings.Contains(prompted[0].Who, "unsigned") {
		t.Fatalf("who should say unsigned: %q", prompted[0].Who)
	}
	if len(ran) != 1 || strings.Join(ran[0], " ") != "approve-remote --use aaaa1111 --lease 30m --passphrase-stdin" || stdins[0] != "secret" {
		t.Fatalf("ran %v stdin %v", ran, stdins)
	}
	// Failed run → asked again next tick.
	runErr = nil
	w.tick()
	if len(prompted) != 2 || len(ran) != 2 {
		t.Fatalf("expected a second ask after a failed run: prompted=%d ran=%d", len(prompted), len(ran))
	}
	// Approved → not asked again.
	w.tick()
	if len(prompted) != 2 {
		t.Fatalf("asked a third time")
	}
	// Denied requests are asked once.
	must(remoteuse.WriteRequest(paths, remoteuse.Request{RequestID: "cccc3333", Subject: "other", Host: "vps",
		Recipient: "age1x", RequestedAt: time.Now(), ExpiresAt: time.Now().Add(remoteuse.TTL), Nonce: "n"}))
	w.prompt = func(_ context.Context, c approvalcard.Card, lease bool) (approvalprompt.Result, error) {
		prompted = append(prompted, c)
		return approvalprompt.Result{Denied: true}, nil
	}
	w.tick()
	w.tick()
	if len(prompted) != 3 || len(ran) != 2 {
		t.Fatalf("denied should be asked once and never run: prompted=%d ran=%d", len(prompted), len(ran))
	}
	// Unanswered (timeout / Escape) comes back once the cooldown passed.
	must(remoteuse.WriteRequest(paths, remoteuse.Request{RequestID: "dddd4444", Subject: "away", Host: "vps",
		Recipient: "age1x", RequestedAt: time.Now(), ExpiresAt: time.Now().Add(remoteuse.TTL), Nonce: "n"}))
	w.prompt = func(_ context.Context, c approvalcard.Card, lease bool) (approvalprompt.Result, error) {
		prompted = append(prompted, c)
		return approvalprompt.Result{Timeout: true}, nil
	}
	w.tick()
	w.tick()
	if len(prompted) != 4 {
		t.Fatalf("unanswered should wait for the cooldown: prompted=%d", len(prompted))
	}
	w.reask = 0
	w.tick()
	if len(prompted) != 5 || prompted[4].Subject != "away" {
		t.Fatalf("unanswered should be asked again after the cooldown: prompted=%d", len(prompted))
	}
	// Answered elsewhere while the dialog is up: the dialog is closed
	// (ErrClosed), the question is settled here, nothing runs.
	must(remoteuse.WriteRequest(paths, remoteuse.Request{RequestID: "eeee5555", Subject: "shared", Host: "vps",
		Recipient: "age1x", RequestedAt: time.Now(), ExpiresAt: time.Now().Add(remoteuse.TTL), Nonce: "n"}))
	w.closeEvery, w.reask = 5*time.Millisecond, time.Hour // dddd4444 was asked a moment ago: not again
	pulls := 0
	w.pull = func() {
		pulls++
		if pulls == 2 { // the other device's approval arrives
			must(remoteuse.WriteLease(paths, remoteuse.Lease{RequestID: "eeee5555", LeaseSubject: "shared@vps", ExpiresAt: time.Now().Add(time.Hour)}))
		}
	}
	w.prompt = func(ctx context.Context, c approvalcard.Card, lease bool) (approvalprompt.Result, error) {
		prompted = append(prompted, c)
		<-ctx.Done()
		return approvalprompt.Result{}, approvalprompt.ErrClosed
	}
	ranBefore := len(ran)
	w.tick()
	if len(prompted) != 6 || len(ran) != ranBefore || !w.seen["lease:eeee5555"] {
		t.Fatalf("answered elsewhere: prompted=%d ran=%d seen=%v", len(prompted), len(ran), w.seen["lease:eeee5555"])
	}
	w.pull = func() {}
	// The expired request never reached the dialog.
	for _, c := range prompted {
		if c.Subject == "old" {
			t.Fatal("expired request was asked")
		}
	}
}

// Card wording: the effect names the asker and the subject; the body
// carries who / where; the footer explains the lease.
func TestLeaseCardWording(t *testing.T) {
	c := approvalcard.Card{Kind: approvalcard.KindLease, Subject: "cam-shell", Who: "buzz-reader (unsigned request)", Where: "hermes-vps"}
	if got := c.Effect(); got != "buzz-reader gets a short-lived bearer with the grants of cam-shell." {
		t.Fatalf("effect: %q", got)
	}
	if !strings.Contains(c.Body(), "from: buzz-reader (unsigned request) on hermes-vps") {
		t.Fatalf("body: %q", c.Body())
	}
	if c.Mood() != approvalcard.MoodRoutine || (approvalcard.Card{Kind: approvalcard.KindPrintKeys}).Mood() != approvalcard.MoodRed {
		t.Fatal("moods")
	}
}
