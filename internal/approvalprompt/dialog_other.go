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
}

var ErrUnsupported = errors.New("approvalprompt: native dialog unsupported on this platform")

func Ask(title, body string, timeout time.Duration) (Result, error) {
	return Result{}, ErrUnsupported
}
