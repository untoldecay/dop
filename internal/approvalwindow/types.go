// Package approvalwindow is dop's own approval window: the approval card
// (contract 27) on the left, the DOP character on the right, Deny ·
// duration ▸ · Approve and the passphrase field below. It replaces the
// AppleScript alert when DOP_APPROVER=window; the alert stays the
// fallback. The window runs in a helper process (`dop admin
// __approver`) because the native webview needs the main thread.
package approvalwindow

import (
	"errors"

	"github.com/fray/dop/internal/approvalcard"
)

// Request is what the helper reads on stdin.
type Request struct {
	Card      approvalcard.Card `json:"card"`
	Lease     bool              `json:"lease"`
	Body      string            `json:"body,omitempty"` // extra text under the card (print guard prompt)
	TimeoutMs int               `json:"timeout_ms"`
	Demo      bool              `json:"demo,omitempty"` // no decision expected; for looking at the character
}

// Result is what the helper prints on stdout. The passphrase travels
// this pipe only, to the daemon that spawned the helper.
type Result struct {
	GaveUp     bool   `json:"gave_up"`
	Button     string `json:"button"` // Approve | Deny | ""
	Choice     string `json:"choice,omitempty"`
	Passphrase string `json:"passphrase,omitempty"`
}

// ErrUnsupported — this build cannot open a native window (no cgo, not darwin).
var ErrUnsupported = errors.New("approvalwindow: native window unsupported in this build")
