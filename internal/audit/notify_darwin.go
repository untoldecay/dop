//go:build darwin

package audit

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// Notify fires a native macOS notification for high-signal events.
// Best-effort: swallows all errors, returns nothing. Skipped when
// DOP_NO_NOTIFY is set (used by tests + CI).
func Notify(e Event) {
	if os.Getenv("DOP_NO_NOTIFY") != "" {
		return
	}
	title, body, ok := renderNotify(e)
	if !ok {
		return
	}
	// osascript is universally present on macOS; no extra deps.
	// Escape any double quotes so a subject with " doesn't break the script.
	title = escapeAppleScript(title)
	body = escapeAppleScript(body)
	script := fmt.Sprintf(`display notification "%s" with title "DOP" subtitle "%s"`, body, title)
	_ = exec.Command("osascript", "-e", script).Run()
}

func renderNotify(e Event) (title, body string, ok bool) {
	switch e.Kind {
	case EventClaimPending:
		sas := ""
		if e.Extra != nil {
			sas = e.Extra["sas"]
		}
		return "approval needed", fmt.Sprintf("%s wants to bind — SAS %s", e.Subject, sas), true
	case EventClaim:
		return "agent bound", fmt.Sprintf("%s claimed a bearer", e.Subject), true
	case EventClaimDenied:
		reason := ""
		if e.Extra != nil {
			reason = e.Extra["reason"]
		}
		return "claim denied", fmt.Sprintf("%s: %s", e.Subject, reason), true
	case EventRevoke:
		return "revoked", fmt.Sprintf("%s was revoked", e.Subject), true
	}
	return "", "", false
}

func escapeAppleScript(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}
