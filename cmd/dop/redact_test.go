package main

import (
	"bytes"
	"strings"
	"testing"
)

func redactAll(t *testing.T, env map[string]string, chunks ...string) string {
	t.Helper()
	var out bytes.Buffer
	vals, labels := redactTargets(env)
	w := newRedactWriter(&out, vals, labels)
	for _, c := range chunks {
		if _, err := w.Write([]byte(c)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	return out.String()
}

var redactEnv = map[string]string{
	"NOTION_TOKEN":    "ntn_abcdefghijklmnopqrstuvwxyz0123456789",
	"NOTION_KIND":     "api-kind",
	"NOTION_BASE_URL": "https://api.notion.com/v1",
	"SHORT_TOKEN":     "abc",
}

func TestRedactMasksInjectedSecret(t *testing.T) {
	got := redactAll(t, redactEnv, "Authorization: Bearer ntn_abcdefghijklmnopqrstuvwxyz0123456789\n")
	if strings.Contains(got, "ntn_abc") || !strings.Contains(got, "‹NOTION_TOKEN›") {
		t.Fatalf("secret not masked: %q", got)
	}
}

func TestRedactCatchesValueSplitAcrossWrites(t *testing.T) {
	got := redactAll(t, redactEnv, "tok=ntn_abcdefghijklm", "nopqrstuvwxyz0123456789 done\n")
	if strings.Contains(got, "ntn_") || !strings.Contains(got, "tok=‹NOTION_TOKEN› done") {
		t.Fatalf("split secret leaked: %q", got)
	}
}

func TestRedactLeavesMetadataAndShortValues(t *testing.T) {
	in := "kind=api-kind url=https://api.notion.com/v1 short=abc\n"
	if got := redactAll(t, redactEnv, in); got != in {
		t.Fatalf("metadata / short values must stay readable: %q", got)
	}
}

func TestRedactPassesUnrelatedOutputIntact(t *testing.T) {
	in := strings.Repeat("hello world ", 50) + "\n"
	if got := redactAll(t, redactEnv, in[:7], in[7:300], in[300:]); got != in {
		t.Fatalf("unrelated output changed")
	}
}
