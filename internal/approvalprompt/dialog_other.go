// Non-darwin build: no native dialog available. Caller MUST fall back
// to the tunnel+phone flow.

//go:build !darwin

package approvalprompt

import (
	"errors"
	"time"
)

type Result struct {
	Approved   bool
	Denied     bool
	Timeout    bool
	Passphrase string
	Choice     string // AskLease: picked duration (never set off darwin)
	cycle      bool
}

var ErrUnsupported = errors.New("approvalprompt: native dialog unsupported on this platform")

func Ask(title, body string, timeout time.Duration) (Result, error) {
	return Result{}, ErrUnsupported
}

// AskLease is the three-button lease variant; unsupported off darwin.
func AskLease(title, body string, durations []string, start int, timeout time.Duration) (Result, error) {
	return Result{}, ErrUnsupported
}
