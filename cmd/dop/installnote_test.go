package main

import (
	"strings"
	"testing"
)

func TestAddInstallNotes(t *testing.T) {
	env := map[string]string{
		"BOILER_CLI_INSTALL":    "curl -fsSL https://x/install.sh | sh",
		"YT_CLI_INSTALL":        "go install example.com/yt@v1.2.0",
		"YT_CLI_INSTALL_VERIFY": "v1.2.0",
		"NOTION_TOKEN":          "secret",
		"EMPTY_CLI_INSTALL":     " ",
	}
	addInstallNotes(env)
	b := env["BOILER_CLI_INSTALL_NOTE"]
	if !strings.HasPrefix(b, installNoteText) || !strings.Contains(b, "Bash(curl -fsSL https://x/install.sh | sh)") || !strings.Contains(b, "BOILER_CLI_INSTALL_VERIFY") {
		t.Fatalf("boiler note: %q", b)
	}
	if y := env["YT_CLI_INSTALL_NOTE"]; !strings.HasPrefix(y, installNoteText) || strings.Contains(y, "_VERIFY is set") {
		t.Fatalf("verified install note: %q", y)
	}
	if _, ok := env["EMPTY_CLI_INSTALL_NOTE"]; ok {
		t.Fatal("note for an empty install hint")
	}
	if _, ok := env["NOTION_TOKEN_NOTE"]; ok {
		t.Fatal("note for a non-install key")
	}
	for _, v := range env {
		if strings.Contains(strings.ToLower(v), "reviewed") || strings.Contains(strings.ToLower(v), "approved") {
			t.Fatalf("a note must never claim review or approval: %q", v)
		}
	}
}
