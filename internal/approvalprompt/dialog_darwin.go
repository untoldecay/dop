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
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// Result mirrors the ApprovalPopupResp decision set.
type Result struct {
	Approved   bool
	Denied     bool
	Timeout    bool
	Passphrase string // zeroed by caller after Verify; never persisted
	Choice     string // AskLease: the duration shown on the middle button when Approve was pressed
	cycle      bool   // AskLease: the middle button was pressed
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
	return run(title, body, "", timeout)
}

// AskLease is the three-button variant for a remote lease request:
// Deny · "<duration> ▸" · Approve. The middle button cycles through
// durations by closing and reopening the dialog with an EMPTY
// passphrase field (the typed text never travels into script source);
// Approve submits the duration shown. Returns the picked duration in
// Result.Choice. Escape and timeout deny.
func AskLease(title, body string, durations []string, start int, timeout time.Duration) (Result, error) {
	if len(durations) == 0 {
		return Ask(title, body, timeout)
	}
	i := start % len(durations)
	for {
		res, err := run(title, body, durations[i]+" ▸", timeout)
		if err != nil {
			return res, err
		}
		if res.cycle {
			i = (i + 1) % len(durations)
			continue
		}
		res.Choice = durations[i]
		return res, nil
	}
}

// run shows the dialog once. middle is the optional third button. The
// passphrase comes back on osascript's stdout, read by this process
// only, parsed from a fixed three-line shape (no comma splitting).
func run(title, body, middle string, timeout time.Duration) (Result, error) {
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	escape := func(s string) string {
		s = strings.ReplaceAll(s, `\`, `\\`)
		s = strings.ReplaceAll(s, `"`, `\"`)
		return s
	}
	buttons := `{"Deny","Approve"}`
	if middle != "" {
		buttons = `{"Deny","` + escape(middle) + `","Approve"}`
	}
	// Neutral icon on purpose: a caution glyph over a hidden-answer field
	// is the silhouette of fake password prompts (contract 27).
	dialog := fmt.Sprintf(
		`set r to display dialog "%s" default answer "" with hidden answer with title "%s" with icon note buttons %s default button "Approve" cancel button "Deny" giving up after %d`,
		escape(body), escape(title), buttons, int(timeout.Seconds()))
	// Fixed shape: gave-up flag, button, then the text on its own line.
	report := `return ((gave up of r) as text) & linefeed & (button returned of r) & linefeed & (text returned of r)`
	cmd := exec.Command("osascript", "-e", dialog, "-e", report)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		se := stderr.String()
		if strings.Contains(se, "User canceled") || strings.Contains(se, "User cancelled") || strings.Contains(se, "-128") {
			return Result{Denied: true}, nil
		}
		// Never echo osascript output into the error: on a weird exit it
		// could carry the dialog result. The AppleScript error number is
		// safe and is what tells a locked screen from a bad script.
		return Result{}, fmt.Errorf("osascript failed (%v%s)", err, appleScriptCode(se))
	}
	return parseReport(stdout.String(), middle)
}

// appleScriptCode pulls "(-1712)"-style error numbers out of osascript's
// stderr, with the one-word reason for the common ones.
func appleScriptCode(stderr string) string {
	m := appleCodeRe.FindString(stderr)
	if m == "" {
		return ""
	}
	why := map[string]string{"-1712": "AppleEvent timed out", "-1743": "not permitted to control System Events",
		"-600": "no GUI application", "-10810": "could not launch", "-1708": "dialog not handled (screen locked?)"}[strings.Trim(m, "()")]
	if why != "" {
		return ", AppleScript " + m + " " + why
	}
	return ", AppleScript " + m
}

var appleCodeRe = regexp.MustCompile(`\(-\d+\)`)

// parseReport reads the fixed three-line shape osascript prints:
// gave-up flag, button, text. A dialog that gave up prints "true" and
// two empty lines (rc8 read that as a malformed result).
func parseReport(out, middle string) (Result, error) {
	parts := strings.SplitN(strings.TrimSuffix(out, "\n"), "\n", 3)
	if parts[0] == "true" {
		return Result{Timeout: true}, nil
	}
	if len(parts) < 2 {
		return Result{}, errors.New("osascript: unexpected result shape")
	}
	text := ""
	if len(parts) == 3 {
		text = parts[2]
	}
	switch parts[1] {
	case "Approve":
		return Result{Approved: true, Passphrase: text}, nil
	case "Deny":
		return Result{Denied: true}, nil
	default:
		if middle != "" && parts[1] == middle {
			return Result{cycle: true}, nil
		}
		return Result{}, errors.New("osascript: unexpected button")
	}
}
