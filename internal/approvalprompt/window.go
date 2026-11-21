package approvalprompt

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/fray/dop/internal/approvalcard"
	"github.com/fray/dop/internal/approvalwindow"
)

// Question is one approval card to put in front of the operator.
type Question struct {
	Card    approvalcard.Card
	Lease   bool          // three buttons with the duration cycle
	Body    string        // extra text (the print guard's prompt); the system alert shows it instead of the card
	Timeout time.Duration // 0 → 60 s
}

// WindowWanted says whether the operator opted into dop's own window
// (DOP_APPROVER=window) instead of the system alert.
func WindowWanted() bool { return os.Getenv("DOP_APPROVER") == "window" }

// AskCard shows the question: dop's own window when WindowWanted and the
// helper can run, else the system alert. Cancelling ctx closes either and
// returns ErrClosed.
func AskCard(ctx context.Context, q Question) (Result, error) {
	if WindowWanted() {
		res, err := askWindow(ctx, q)
		if err == nil || errors.Is(err, ErrClosed) {
			return res, err
		}
		// Helper missing or unsupported: fall through to the alert.
	}
	body := q.Body
	if body == "" {
		body = q.Card.Body()
		if f := q.Card.Footer(); f != "" {
			body += "\n\n" + f
		}
		body += "\n\n" + approvalcard.Passphrase + ":"
	}
	if q.Lease {
		return AskLeaseCtx(ctx, q.Card.Title(), body, approvalcard.LeaseDurations, q.Card.Default, q.Timeout)
	}
	return AskCtx(ctx, q.Card.Title(), body, q.Timeout)
}

// askWindow runs `dop admin __approver` with the request on stdin and
// reads the decision from its stdout — the only place the passphrase
// travels, to the process that asked.
func askWindow(ctx context.Context, q Question) (Result, error) {
	self, err := os.Executable()
	if err != nil {
		return Result{}, err
	}
	timeout := q.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	req := approvalwindow.Request{Card: q.Card, Lease: q.Lease, Body: q.Body, TimeoutMs: int(timeout / time.Millisecond)}
	in, _ := json.Marshal(req)
	cmd := exec.CommandContext(ctx, self, "admin", "__approver")
	cmd.Stdin = bytes.NewReader(in)
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return Result{}, ErrClosed
		}
		return Result{}, errors.New("approval window: " + strings.TrimSpace(firstLineOf(stderr.String())))
	}
	var r approvalwindow.Result
	if err := json.Unmarshal(out.Bytes(), &r); err != nil {
		return Result{}, errors.New("approval window: unexpected result shape")
	}
	switch {
	case r.GaveUp:
		return Result{Timeout: true}, nil
	case r.Button == "Approve":
		return Result{Approved: true, Passphrase: r.Passphrase, Choice: r.Choice}, nil
	default:
		return Result{Denied: true}, nil
	}
}

func firstLineOf(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}
