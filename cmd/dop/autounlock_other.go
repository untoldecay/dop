// Non-darwin stub for the native-dialog auto-unlock path.
// See autounlock_darwin.go for the real implementation.

//go:build !darwin

package main

import (
	"errors"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/config"
)

var (
	ErrAutoUnlockUnsupported = errors.New("admin auto-unlock: native dialog unsupported on this platform")
	ErrAutoUnlockCanceled    = errors.New("admin auto-unlock: operator canceled")
)

func autoUnlockPrompt(paths *config.Paths, title, body string) (*admin.Client, error) {
	return nil, ErrAutoUnlockUnsupported
}
