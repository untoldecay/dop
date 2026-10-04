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
	"os/exec"
	"strings"
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
