// v1.13.0-rc14 — contract regression guard for the handoff text shape.
// Pins the invariants from _rules/_requirements/contracts/13_handoff_text_shape.md.
// Breaks loudly if a future edit reintroduces imperative prose that
// prompt-injection detectors flag.

package tui

import (
	"strings"
	"testing"
)

// forbiddenPhrases MUST NOT appear in the pasted handoff. Each one
// was already in the rc10 → rc13 regression; keeping the list verbatim
// documents what we're guarding against.
var forbiddenPhrases = []string{
	"poll",
	"--status",
	"--cancel",
	" state ", // leading/trailing space so "run this in your shell" doesn't trip
	"approved",
	"expired",
	"absent",
	"abort",
	"Run this in your shell",
	"it blocks until",
	"poll progress every",
	"state field means",
	"If the user wants to abort",
	"QR image:",   // belongs in dop claim runtime output
	"Public URL:", // same
	"SAS",         // same
}

func TestHandoffText_NoForbiddenPhrases(t *testing.T) {
	for _, tc := range handoffCases() {
		t.Run(tc.name, func(t *testing.T) {
			got := buildHandoffText(tc.bearer, tc.pin, tc.allowFileKeys)
			lower := strings.ToLower(got)
			for _, f := range forbiddenPhrases {
				if strings.Contains(lower, strings.ToLower(f)) {
					t.Errorf("handoff contains forbidden phrase %q\n--- handoff ---\n%s", f, got)
				}
			}
		})
	}
}

func TestHandoffText_ExactlyOneClaimCommand(t *testing.T) {
	for _, tc := range handoffCases() {
		t.Run(tc.name, func(t *testing.T) {
			got := buildHandoffText(tc.bearer, tc.pin, tc.allowFileKeys)
			if n := strings.Count(got, "dop claim "); n != 1 {
				t.Errorf("want exactly 1 `dop claim ` substring, got %d\n--- handoff ---\n%s", n, got)
			}
		})
	}
}

func TestHandoffText_ContainsBearerAndPIN(t *testing.T) {
	for _, tc := range handoffCases() {
		t.Run(tc.name, func(t *testing.T) {
			got := buildHandoffText(tc.bearer, tc.pin, tc.allowFileKeys)
			if !strings.Contains(got, tc.bearer) {
				t.Errorf("handoff missing bearer %q\n--- handoff ---\n%s", tc.bearer, got)
			}
			if tc.pin != "" && !strings.Contains(got, tc.pin) {
				t.Errorf("handoff missing PIN %q\n--- handoff ---\n%s", tc.pin, got)
			}
		})
	}
}

func TestHandoffText_AllowFileKeysEmbedded(t *testing.T) {
	got := buildHandoffText("tok_test", "AB-CD-EF", true)
	if !strings.Contains(got, "DOP_ALLOW_FILE_KEYS=1") {
		t.Errorf("want DOP_ALLOW_FILE_KEYS=1 in command when allowFileKeys=true\n--- handoff ---\n%s", got)
	}
	if !strings.Contains(got, "--key-type p256") {
		t.Errorf("want --key-type p256 in command when allowFileKeys=true\n--- handoff ---\n%s", got)
	}
}

func TestHandoffText_LinesBoundedAfterCommand(t *testing.T) {
	// Contract: nothing after the single `dop claim …` line.
	got := buildHandoffText("tok_test", "AB-CD-EF", false)
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	// Find the claim line.
	claimIdx := -1
	for i, l := range lines {
		if strings.Contains(l, "dop claim ") {
			claimIdx = i
			break
		}
	}
	if claimIdx < 0 {
		t.Fatalf("no claim line found in handoff:\n%s", got)
	}
	// Nothing non-whitespace after the claim line.
	for i := claimIdx + 1; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) != "" {
			t.Errorf("handoff has content after the claim command (line %d): %q\n--- handoff ---\n%s", i, lines[i], got)
		}
	}
}

type handoffCase struct {
	name          string
	bearer        string
	pin           string
	allowFileKeys bool
}

func handoffCases() []handoffCase {
	return []handoffCase{
		{"pin-bind default", "tok_1abcdef0123456789", "AB-CD-EF", false},
		{"pin-bind allow-file-keys", "tok_1abcdef0123456789", "AB-CD-EF", true},
	}
}
