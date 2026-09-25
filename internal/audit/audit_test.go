package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHashBearer_StableAndTruncated(t *testing.T) {
	h1 := HashBearer("tok_deadbeef")
	h2 := HashBearer("tok_deadbeef")
	if h1 != h2 {
		t.Fatal("hash not deterministic")
	}
	if len(h1) != 16 {
		t.Fatalf("expected 16 hex chars, got %d", len(h1))
	}
	if strings.Contains(h1, "tok_") {
		t.Fatal("hash leaked bearer content")
	}
	if HashBearer("") != "" {
		t.Fatal("empty bearer must hash to empty")
	}
}

func TestTruncCmdHead(t *testing.T) {
	if got := TruncCmdHead([]string{"env"}); got != "env" {
		t.Fatalf("short: %q", got)
	}
	if got := TruncCmdHead(nil); got != "" {
		t.Fatalf("nil: %q", got)
	}
	long := []string{"curl", "-fsSL", strings.Repeat("x", 200)}
	got := TruncCmdHead(long)
	if !strings.HasSuffix(got, "…") {
		t.Fatalf("expected truncation, got %q", got)
	}
}

func TestWriter_LogRoundTrip(t *testing.T) {
	dir := t.TempDir()
	w := &Writer{LogsDir: dir, Host: "testhost"}

	e := Event{
		Op:         "exec",
		AgentName:  "claude-r1",
		AuthMethod: "bearer",
		TokenHash:  HashBearer("tok_abc"),
		Grants:     []string{"boiler.read"},
		Outcome:    "ok",
	}
	if err := w.Log(e); err != nil {
		t.Fatal(err)
	}

	// Locate the file — filename uses YYYY-MM slice of the ts we didn't set.
	// Since Log fills ts, look at whatever file is present.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 log file, got %d: %v", len(entries), entries)
	}
	name := entries[0].Name()
	if !strings.HasPrefix(name, "access-testhost-") || !strings.HasSuffix(name, ".jsonl") {
		t.Fatalf("unexpected filename %q", name)
	}
	data, _ := os.ReadFile(filepath.Join(dir, name))
	var got Event
	if err := json.Unmarshal([]byte(strings.TrimSpace(string(data))), &got); err != nil {
		t.Fatalf("could not parse log line: %v\nline: %q", err, data)
	}
	if got.Op != "exec" || got.AgentName != "claude-r1" || got.Outcome != "ok" {
		t.Fatalf("event fields mangled: %#v", got)
	}
	if got.TS == "" {
		t.Fatal("ts not filled")
	}
	if got.Host != "testhost" {
		t.Fatalf("host mangled: %q", got.Host)
	}
}

func TestWriter_AppendsMultipleLines(t *testing.T) {
	dir := t.TempDir()
	w := &Writer{LogsDir: dir, Host: "th"}
	for i := 0; i < 5; i++ {
		if err := w.Log(Event{Op: "exec", Outcome: "ok", TS: time.Now().UTC().Format(time.RFC3339)}); err != nil {
			t.Fatal(err)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("expected 1 file, got %d", len(entries))
	}
	data, _ := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 5 {
		t.Fatalf("expected 5 lines, got %d", len(lines))
	}
}

func TestWriter_NilAndEmpty_NoPanicNoWrite(t *testing.T) {
	var w *Writer
	if err := w.Log(Event{Op: "test"}); err != nil {
		t.Fatalf("nil writer should be a no-op: %v", err)
	}
	empty := &Writer{}
	if err := empty.Log(Event{Op: "test"}); err != nil {
		t.Fatalf("empty writer should be a no-op: %v", err)
	}
}
