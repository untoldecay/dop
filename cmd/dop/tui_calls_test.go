package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The TUI drives dop by running its own binary with CLI arguments. A
// renamed or mistyped subcommand only fails at run time — the Uninstall
// screen called `dop admin uninstall` (never existed) from 2026-10-06
// until v1.20.0-rc3. This checks every call the TUI makes against the
// commands main() and each sub-dispatcher actually handle.

var caseRe = regexp.MustCompile(`case ((?:"[^"]+"(?:, )?)+):`)

// casesIn returns the case labels in the body of func name in file.
func casesIn(t *testing.T, file, name string) map[string]bool {
	t.Helper()
	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	i := strings.Index(src, "func "+name+"(")
	if i < 0 {
		t.Fatalf("%s not found in %s", name, file)
	}
	body := src[i:]
	if j := strings.Index(body[1:], "\nfunc "); j >= 0 {
		body = body[:j+1]
	}
	out := map[string]bool{}
	for _, m := range caseRe.FindAllStringSubmatch(body, -1) {
		for _, lit := range strings.Split(m[1], ", ") {
			out[strings.Trim(lit, `"`)] = true
		}
	}
	return out
}

func TestTUICallsExistingCommands(t *testing.T) {
	top := casesIn(t, "main.go", "main")
	sub := map[string]map[string]bool{
		"admin":       casesIn(t, "admincmd.go", "runAdmin"),
		"team":        casesIn(t, "stubs.go", "runTeam"),
		"token":       casesIn(t, "tokencmd.go", "runToken"),
		"integration": casesIn(t, "integrationcmd.go", "runIntegration"),
		"grant":       casesIn(t, "integrationcmd.go", "runGrant"),
		"vault":       casesIn(t, "vaultedit.go", "runVault"),
	}
	callRe := regexp.MustCompile(`exec\.Command\(self, "([^"]+)"(?:, "([^"]+)")?`)
	argsRe := regexp.MustCompile(`return \[\]string\{"([^"]+)"(?:, "([^"]+)")?`)
	files, _ := filepath.Glob("../../internal/tui/*.go")
	n := 0
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		src := string(b)
		matches := callRe.FindAllStringSubmatch(src, -1)
		if strings.HasSuffix(f, "reset_view.go") {
			matches = append(matches, argsRe.FindAllStringSubmatch(src, -1)...)
		}
		for _, m := range matches {
			n++
			cmd, arg := m[1], m[2]
			if !top[cmd] {
				t.Errorf("%s: `dop %s` — no such top-level command", filepath.Base(f), cmd)
				continue
			}
			if s, ok := sub[cmd]; ok && arg != "" && !strings.HasPrefix(arg, "-") && !s[arg] {
				t.Errorf("%s: `dop %s %s` — no such subcommand", filepath.Base(f), cmd, arg)
			}
		}
	}
	if n < 15 {
		t.Fatalf("only %d TUI calls found — the scan is broken", n)
	}
}
