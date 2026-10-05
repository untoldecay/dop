// Native-dialog auto-unlock for the admin session on macOS.
//
// Pre-rc6f, a locked admin session on an `eval "$(dop use ...)"` call
// errored out with "no active admin session — run `dop admin login`
// first". Cam asked for a direct unlock path: pop a native passphrase
// dialog, run the login dance, continue the operation.
//
// Non-darwin builds get a stub (autounlock_other.go) that returns
// ErrAutoUnlockUnsupported so callers fall through to the plain error.
//
// Called by requireAdminSessionOrUnlock; opt-in per command (dop use
// is the main surface — operator-driven, not agent-driven).

//go:build darwin

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/config"
)

// ErrAutoUnlockUnsupported — the platform or environment can't show a
// GUI passphrase dialog (non-darwin, headless macOS, osascript missing).
var ErrAutoUnlockUnsupported = errors.New("admin auto-unlock: native dialog unsupported on this platform/environment")

// ErrAutoUnlockCanceled — the operator closed the dialog without
// entering a passphrase. Caller falls back to the plain
// "run dop admin login" error so the operator can retry at a terminal.
var ErrAutoUnlockCanceled = errors.New("admin auto-unlock: operator canceled")

// canShowGUIDialog reports whether this process can plausibly reach
// WindowServer to render a native osascript dialog.
//
// rc6k (handoff 4cca9621 finding [C]): pre-rc6k we blindly ran
// osascript and swallowed any failure as "no active admin session —
// run dop admin login first". In agent harnesses like Orca where the
// subprocess inherits a non-Aqua environment, osascript silently
// fails and the operator never learns the dialog was attempted.
//
// Positive signals (both required):
//   - launchctl managername == "Aqua" — tells us we're in a GUI session
//   - /dev/console owner uid == our uid — tells us the active console
//     user matches the invoking user (not a background daemon context)
//
// Deliberately NOT checked (anti-patterns from the handoff):
//   - $TERM — set to "xterm-256color" in agent shells despite no tty
//   - isatty(stdin/stdout/stderr) — always false in agent shells
//   - $DISPLAY — macOS doesn't use it
//
// Returns (ok, reason). When ok is false, reason names the first
// failing check so operators can see why the dialog was skipped
// (surfaced to stderr by callers).
func canShowGUIDialog() (bool, string) {
	out, err := exec.Command("launchctl", "managername").Output()
	if err != nil {
		return false, "launchctl managername failed: " + err.Error()
	}
	mgr := strings.TrimSpace(string(out))
	if mgr != "Aqua" {
		return false, fmt.Sprintf("launchctl managername = %q, want Aqua (no GUI session reachable from here)", mgr)
	}
	var st syscall.Stat_t
	if err := syscall.Stat("/dev/console", &st); err != nil {
		return false, "stat /dev/console: " + err.Error()
	}
	if int(st.Uid) != os.Getuid() {
		return false, fmt.Sprintf("console uid %d != process uid %d (dialog would surface for a different user)", st.Uid, os.Getuid())
	}
	return true, ""
}

// autoUnlockPrompt shows a native osascript dialog asking for the
// admin passphrase, then calls performAdminLogin with the result.
// Returns a connected admin.Client once the session is live.
//
// The dialog is intentionally minimal: no `activation phrase` field,
// no extra copy — just "Admin passphrase:" + Approve/Deny buttons. The
// title names the subject so an operator with multiple vaults can
// recognize which install is asking.
//
// Side effects on success: a fresh session daemon is forked and the
// socket is reachable before this function returns.
func autoUnlockPrompt(paths *config.Paths, title, body string) (*admin.Client, error) {
	// rc6k — gate on GUI reachability BEFORE calling osascript. Avoids
	// the pre-rc6k failure mode where osascript silently fails in agent
	// subprocess contexts and the operator never sees the dialog nor
	// learns why.
	if ok, reason := canShowGUIDialog(); !ok {
		return nil, fmt.Errorf("%w: %s", ErrAutoUnlockUnsupported, reason)
	}
	if title == "" {
		title = "DOP admin unlock"
	}
	if body == "" {
		body = "Enter admin passphrase to unlock the session."
	}
	// Escape for AppleScript — same shape as approvalprompt.Ask.
	escape := func(s string) string {
		s = strings.ReplaceAll(s, `\`, `\\`)
		s = strings.ReplaceAll(s, `"`, `\"`)
		return s
	}
	script := fmt.Sprintf(
		`display dialog "%s" default answer "" with hidden answer with title "%s" with icon note buttons {"Cancel","Unlock"} default button "Unlock" cancel button "Cancel" giving up after 60`,
		escape(body),
		escape(title),
	)
	cmd := exec.Command("osascript", "-e", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		s := string(out)
		if strings.Contains(s, "User canceled") || strings.Contains(s, "User cancelled") {
			return nil, ErrAutoUnlockCanceled
		}
		return nil, fmt.Errorf("%w: osascript: %s", ErrAutoUnlockUnsupported, strings.TrimSpace(s))
	}
	line := strings.TrimSpace(string(out))
	if strings.Contains(line, "gave up:true") {
		return nil, ErrAutoUnlockCanceled
	}
	var button, pass string
	for _, p := range strings.Split(line, ", ") {
		kv := strings.SplitN(p, ":", 2)
		if len(kv) != 2 {
			continue
		}
		switch strings.TrimSpace(kv[0]) {
		case "button returned":
			button = strings.TrimSpace(kv[1])
		case "text returned":
			pass = strings.TrimSpace(kv[1])
		}
	}
	if button != "Unlock" || pass == "" {
		return nil, ErrAutoUnlockCanceled
	}
	if err := performAdminLogin(paths, pass); err != nil {
		return nil, fmt.Errorf("admin auto-unlock: %w", err)
	}
	// Daemon just signaled ready — connect a fresh client.
	client := admin.NewClient(admin.SockPath(paths))
	deadline := time.Now().Add(2 * time.Second)
	for !client.SessionActive() {
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("admin auto-unlock: daemon ready but SessionActive still false")
		}
		time.Sleep(50 * time.Millisecond)
	}
	return client, nil
}
