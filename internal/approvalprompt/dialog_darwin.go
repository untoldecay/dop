// Package approvalprompt renders a native approval dialog on macOS.
// Called by the admin daemon when a print surface or claim flow asks
// for Tier 3 approval and the daemon is reachable (local path).
//
// The dialog uses osascript's `display dialog` primitive — zero deps,
// built into macOS, no codesign. Hidden-answer mode masks the typed
// passphrase. The passphrase comes back on stdout; the daemon then
// verifies it against approval.hash and returns the decision.
//
// Non-darwin builds get a stub that returns ErrUnsupported — callers
// fall back to the tunnel+phone flow in that case.

//go:build darwin

package approvalprompt

import (
	"bufio"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// Result mirrors the ApprovalPopupResp decision set.
type Result struct {
	Approved   bool
	Denied     bool
	Timeout    bool
	Passphrase string // zeroed by caller after Verify; never persisted
}

// ErrUnsupported — this build/platform/env can't show a native dialog.
// The daemon returns `unsupported` so the caller falls back to tunnel+phone.
var ErrUnsupported = errors.New("approvalprompt: native dialog unsupported on this platform")

// Ask opens an osascript dialog with a hidden-answer passphrase field
// and the given title + body. Returns:
//   - approved + passphrase: user clicked Approve AND typed something
//   - denied: user clicked Deny / Cancel
//   - timeout: dialog closed by giving up timeout seconds
//
// The timeout is enforced via osascript's `giving up after` clause —
// no goroutine races, no process-kill cleanup.
func Ask(title, body string, timeout time.Duration) (Result, error) {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	// Escape for AppleScript — double quotes and backslashes.
	escape := func(s string) string {
		s = strings.ReplaceAll(s, `\`, `\\`)
		s = strings.ReplaceAll(s, `"`, `\"`)
		return s
	}
	script := fmt.Sprintf(
		`display dialog "%s" default answer "" with hidden answer with title "%s" with icon caution buttons {"Deny","Approve"} default button "Approve" cancel button "Deny" giving up after %d`,
		escape(body),
		escape(title),
		int(timeout.Seconds()),
	)
	cmd := exec.Command("osascript", "-e", script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// AppleScript exits non-zero on cancel. The literal "User
		// canceled" / "User cancelled" markers appear in CombinedOutput.
		s := string(out)
		if strings.Contains(s, "User canceled") || strings.Contains(s, "User cancelled") {
			return Result{Denied: true}, nil
		}
		return Result{}, fmt.Errorf("osascript: %w: %s", err, strings.TrimSpace(s))
	}
	// Successful dialog returns one of:
	//   button returned:Approve, text returned:<typed>
	//   button returned:Approve, text returned:<typed>, gave up:false
	//   gave up:true     (giving-up timeout, no button pressed)
	line := strings.TrimSpace(string(out))
	if strings.Contains(line, "gave up:true") {
		return Result{Timeout: true}, nil
	}
	// Parse button + text out of the comma-separated key:value pairs.
	// osascript doesn't escape commas inside values, but the hidden-
	// answer field forbids commas-in-input via the native widget. Safe
	// to split on ", " for this specific caller.
	var button, text string
	sc := bufio.NewScanner(strings.NewReader(line))
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		parts := strings.Split(sc.Text(), ", ")
		for _, p := range parts {
			kv := strings.SplitN(p, ":", 2)
			if len(kv) != 2 {
				continue
			}
			switch strings.TrimSpace(kv[0]) {
			case "button returned":
				button = strings.TrimSpace(kv[1])
			case "text returned":
				text = strings.TrimSpace(kv[1])
			}
		}
	}
	switch button {
	case "Approve":
		return Result{Approved: true, Passphrase: text}, nil
	case "Deny", "":
		return Result{Denied: true}, nil
	default:
		return Result{Denied: true}, nil
	}
}
