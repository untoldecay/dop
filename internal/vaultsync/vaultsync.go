// Package vaultsync wraps git pull/push on the vault clone and tracks the
// last-pull timestamp so `dop exec` can auto-refresh a stale clone.
//
// Fails open on network errors — a working local vault is more important
// than fresh state for the hot path.
package vaultsync

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

const lastPullFilename = ".dop-last-pull"

// Pull runs `git -C <vaultDir> pull` and writes the last-pull timestamp on success.
func Pull(vaultDir string, out io.Writer) error {
	if err := gitRun(vaultDir, out, "pull", "--ff-only"); err != nil {
		return fmt.Errorf("git pull: %w", err)
	}
	return writeLastPull(vaultDir, time.Now())
}

// Push runs `git -C <vaultDir> push`. Bubble up any error including
// non-fast-forward — caller should decide whether to retry after pull.
func Push(vaultDir string, out io.Writer) error {
	// Stage anything under the vault (logs, updated vault.yaml).
	if err := gitRun(vaultDir, out, "add", "-A"); err != nil {
		return err
	}
	// Commit if there's anything to commit; git returns exit=1 on no-change,
	// which we swallow.
	if err := gitRunAllowExit(vaultDir, out, []int{0, 1}, "commit", "-m", "dop: sync "+time.Now().UTC().Format(time.RFC3339)); err != nil {
		return err
	}
	if err := gitRun(vaultDir, out, "push"); err != nil {
		return fmt.Errorf("git push: %w", err)
	}
	return nil
}

// IsStale returns true if the last pull was more than maxAge ago (or never).
func IsStale(vaultDir string, maxAge time.Duration) (bool, time.Time, error) {
	t, err := readLastPull(vaultDir)
	if err != nil {
		if os.IsNotExist(err) {
			return true, time.Time{}, nil
		}
		return true, time.Time{}, err
	}
	return time.Since(t) > maxAge, t, nil
}

// EnsureFresh pulls if the clone is stale beyond maxAge. Network failures
// downgrade to a warning on out — the resolve hot path is not blocked.
func EnsureFresh(vaultDir string, maxAge time.Duration, out io.Writer) {
	stale, lastPull, err := IsStale(vaultDir, maxAge)
	if err != nil {
		fmt.Fprintf(out, "dop: warning: cannot check vault freshness: %v\n", err)
		return
	}
	if !stale {
		return
	}
	if !lastPull.IsZero() {
		fmt.Fprintf(out, "dop: vault stale (last pull %s ago), pulling\n", time.Since(lastPull).Round(time.Second))
	}
	if err := Pull(vaultDir, out); err != nil {
		fmt.Fprintf(out, "dop: warning: auto-pull failed, continuing with local vault: %v\n", err)
	}
}

func writeLastPull(vaultDir string, t time.Time) error {
	path := filepath.Join(vaultDir, lastPullFilename)
	return os.WriteFile(path, []byte(strconv.FormatInt(t.Unix(), 10)), 0o644)
}

func readLastPull(vaultDir string) (time.Time, error) {
	path := filepath.Join(vaultDir, lastPullFilename)
	b, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, err
	}
	ts, err := strconv.ParseInt(string(bytes.TrimSpace(b)), 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse last-pull: %w", err)
	}
	return time.Unix(ts, 0), nil
}

func gitRun(dir string, out io.Writer, args ...string) error {
	return gitRunAllowExit(dir, out, []int{0}, args...)
}

func gitRunAllowExit(dir string, out io.Writer, allowedExits []int, args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Stdout = out
	cmd.Stderr = out
	err := cmd.Run()
	if err == nil {
		return nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		for _, allowed := range allowedExits {
			if exitErr.ExitCode() == allowed {
				return nil
			}
		}
	}
	return fmt.Errorf("git %v: %w", args, err)
}
