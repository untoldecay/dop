package tui

import (
	"os"
)

func fileExists(p string) bool {
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

// fmtStderr is wrapped so tests can swap it if needed. Currently just os.Stderr.
func fmtStderr() *os.File { return os.Stderr }
