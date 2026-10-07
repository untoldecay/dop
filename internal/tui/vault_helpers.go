// Shared helpers for TUI views that need to read the vault.

package tui

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

// loadVaultForListing reads the vault via the admin daemon if encrypted,
// or directly if plaintext. Returns the parsed vault + the file path.
//
// Sentinels for callers to render plain-English messages:
//   errors.Is(err, vault.ErrNotAttached) → no vault yet on this machine
//   friendlyDecryptError() below wraps sops "identity did not match"
//   YAML parse failures include the original error but callers may prefer
//     a generic "vault file looks malformed — try dop pull --keep-team".
func loadVaultForListing(client *admin.Client, paths *config.Paths) (*vault.Vault, string, error) {
	// In-view reloads (tabs, back from a detail, after a save) pull
	// too; rate-limited, so right after a screen-entry sync it's a stat.
	if vaultSyncDue(paths) {
		syncVault(paths)
	}
	vp := paths.Vault + "/vault.yaml"
	raw, err := os.ReadFile(vp)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, vp, vault.ErrNotAttached
		}
		return nil, vp, err
	}
	if bytes.Contains(raw, []byte("\nsops:")) || bytes.HasPrefix(raw, []byte("sops:")) {
		plain, err := client.DecryptVault(vp)
		if err != nil {
			if isDaemonUnreachable(err) {
				return nil, vp, vault.ErrSessionEnded
			}
			return nil, vp, friendlyDecryptError(err)
		}
		raw = plain
	}
	var vv vault.Vault
	if err := yaml.Unmarshal(raw, &vv); err != nil {
		return nil, vp, err
	}
	return &vv, vp, nil
}

// friendlyDecryptError rewrites the raw sops "identity did not match"
// stderr blob into a message that names the actual problem: this
// machine's admin key isn't on the vault's recipient list.
func friendlyDecryptError(err error) error {
	if err == nil {
		return nil
	}
	s := err.Error()
	if containsAny(s, "identity did not match", "no matching creation rules", "no master key was able to decrypt") {
		return errors.New(
			"couldn't decrypt the vault with this machine's admin key.\n" +
				"  You may not be on the vault's admin list yet — ask the vault owner\n" +
				"  to run 'dop team invite --name <you>' from their machine.")
	}
	return err
}

func containsAny(hay string, needles ...string) bool {
	for _, n := range needles {
		if strings.Contains(hay, n) {
			return true
		}
	}
	return false
}

// renderNoVault returns a one-line plain-English message telling the
// operator they need to attach a vault before this view has anything
// to show. `noun` is what the view was trying to list ("integrations",
// "grants", "tokens", "admins").
func renderNoVault(noun string) string {
	return "No vault attached to this machine yet — nothing to show under " + noun + ".\n\n" +
		"From the main menu, pick 'Attach vault' and paste your vault URL,\n" +
		"or on the CLI:  dop init --vault <URL>"
}

// renderSessionEnded returns the plain-English "your admin session
// ended, log in again" text that every view uses when it hits
// vault.ErrSessionEnded.
func renderSessionEnded() string {
	return "Your admin session ended (idle timeout).\n\n" +
		"Press esc to go back to the main menu, then pick 'Login' to unlock again."
}

// isDaemonUnreachable returns true when err looks like a socket-connect
// failure to the admin daemon. Matches Go's net.OpError and the raw
// string patterns from the socket call.
func isDaemonUnreachable(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	return containsAny(s,
		"connect: connection refused",
		"connect: no such file",
		"dial unix",
		"broken pipe",
		"use of closed network connection",
	)
}

// vaultAttached returns true iff the vault directory is a git clone.
// The signal is `.git/` — a successful clone always creates it, even for
// an empty remote. Waiting for vault.yaml or .sops.yaml would hide the
// mutation menu until the user's first save, which is exactly the moment
// they need those options.
func vaultAttached(paths *config.Paths) bool {
	if paths == nil {
		return false
	}
	if _, err := os.Stat(paths.Vault + "/.git"); err == nil {
		return true
	}
	// Belt + suspenders: also accept a file called `.git` (git worktree
	// pointer) — happens if the user manually converted their setup.
	if fi, err := os.Stat(paths.Vault + "/.git"); err == nil && !fi.IsDir() {
		return true
	}
	// And still accept vault.yaml alone — covers weird test setups.
	if _, err := os.Stat(paths.Vault + "/vault.yaml"); err == nil {
		return true
	}
	return false
}

// vaultSyncDue reports whether a screen-entry pull should run: the
// vault is a git checkout, auto-pull isn't disabled, and the last pull
// (last-pull.ts, shared with the CLI) is older than the freshness
// window — 15s, or DOP_AUTOPULL_MAX_AGE_SEC.
func vaultSyncDue(paths *config.Paths) bool {
	if paths == nil || os.Getenv("DOP_NO_AUTO_PULL") == "1" {
		return false
	}
	if _, err := os.Stat(filepath.Join(paths.Vault, ".git")); err != nil {
		return false
	}
	maxAge := 15 * time.Second
	if raw := os.Getenv("DOP_AUTOPULL_MAX_AGE_SEC"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			maxAge = time.Duration(n) * time.Second
		}
	}
	fi, err := os.Stat(filepath.Join(paths.Root, "last-pull.ts"))
	return err != nil || time.Since(fi.ModTime()) >= maxAge
}

// syncVault runs `dop pull --auto` (fetch + smart merge, rate-limited,
// quiet). Returns a merge-conflict line for the status bar, or "".
func syncVault(paths *config.Paths) string {
	if testing.Testing() {
		return "" // os.Executable is the test binary, not dop
	}
	self, err := os.Executable()
	if err != nil {
		return ""
	}
	cmd := exec.Command(self, "pull", "--auto")
	cmd.Env = append(os.Environ(), "DOP_NO_TUI=1", "DOP_FROM_TUI=1")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	_ = cmd.Run()
	return strings.Trim(strings.TrimSpace(stderr.String()), "()")
}
