package main

import (
	"bytes"
	"io"
	"sort"
	"strings"
	"sync"
)

// redactMetaSuffixes are injected env names that carry hints, not
// secrets (integration kind, URLs, CLI usage) — left readable.
var redactMetaSuffixes = []string{"_KIND", "_BASE_URL", "_MCP_URL", "_URL", "_CMD", "_HINT", "_HELP", "_ARGS_HINT", "_INSTALL", "_AUTH_STYLE", "_AUTH_HEADER", "_ENDPOINTS_URL", "_ALLOWED"}

// redactMinLen skips short values: too likely to match ordinary output.
const redactMinLen = 8

// redactTargets picks the injected values worth masking and the label
// that replaces each, longest value first so overlapping secrets mask
// whole.
func redactTargets(env map[string]string) (vals, labels [][]byte) {
	type t struct{ val, label string }
	var ts []t
	for k, v := range env {
		if len(v) < redactMinLen || strings.Contains(v, "://") {
			continue
		}
		meta := false
		for _, s := range redactMetaSuffixes {
			if strings.HasSuffix(k, s) {
				meta = true
				break
			}
		}
		if !meta {
			ts = append(ts, t{v, "‹" + k + "›"})
		}
	}
	sort.Slice(ts, func(i, j int) bool { return len(ts[i].val) > len(ts[j].val) })
	for _, x := range ts {
		vals = append(vals, []byte(x.val))
		labels = append(labels, []byte(x.label))
	}
	return vals, labels
}

// redactWriter masks injected secret values in a stream before it
// reaches the terminal — and so an agent harness transcript or the AI
// provider (dop-8g7 follow-up). It holds back the last longest-value-1
// bytes so a value split across two writes is still caught; Flush
// releases them when the child exits.
//
// It stops accidental leaks (printenv, curl -v, error dumps), not a
// child that encodes the value on purpose.
type redactWriter struct {
	mu     sync.Mutex
	out    io.Writer
	vals   [][]byte
	labels [][]byte
	hold   int
	buf    []byte
}

func newRedactWriter(out io.Writer, vals, labels [][]byte) *redactWriter {
	hold := 0
	for _, v := range vals {
		if len(v)-1 > hold {
			hold = len(v) - 1
		}
	}
	return &redactWriter{out: out, vals: vals, labels: labels, hold: hold}
}

func (w *redactWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf = append(w.buf, p...)
	for i, v := range w.vals {
		w.buf = bytes.ReplaceAll(w.buf, v, w.labels[i])
	}
	if n := len(w.buf) - w.hold; n > 0 {
		if _, err := w.out.Write(w.buf[:n]); err != nil {
			return 0, err
		}
		w.buf = append(w.buf[:0], w.buf[n:]...)
	}
	return len(p), nil
}

// Flush writes whatever is still held back.
func (w *redactWriter) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.buf) == 0 {
		return nil
	}
	_, err := w.out.Write(w.buf)
	w.buf = w.buf[:0]
	return err
}
