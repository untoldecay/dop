//go:build darwin

package approvalprompt

import "testing"

// The three shapes osascript prints: gave up, a button with the typed
// text, a button alone.
func TestParseReport(t *testing.T) {
	if r, err := parseReport("true\n\n\n", "30m ▸"); err != nil || !r.Timeout {
		t.Fatalf("gave up: %+v %v", r, err)
	}
	if r, err := parseReport("false\nApprove\nhunter2 pass\n", ""); err != nil || !r.Approved || r.Passphrase != "hunter2 pass" {
		t.Fatalf("approve: %+v %v", r, err)
	}
	if r, err := parseReport("false\nDeny\n\n", ""); err != nil || !r.Denied {
		t.Fatalf("deny: %+v %v", r, err)
	}
	if r, err := parseReport("false\n30m ▸\n\n", "30m ▸"); err != nil || !r.cycle {
		t.Fatalf("cycle: %+v %v", r, err)
	}
	if _, err := parseReport("garbage", ""); err == nil {
		t.Fatal("garbage must error")
	}
	if got := appleScriptCode("execution error: Not authorized (-1743)"); got != ", AppleScript (-1743) not permitted to control System Events" {
		t.Fatalf("code %q", got)
	}
}
