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
// provider. It holds back only an output tail that could be the start
// of a secret (so a value split across writes is still caught); every
// other byte goes out at once, so interactive prompts aren't delayed.
// Flush releases the tail when the child exits.
//
// It stops accidental leaks (printenv, curl -v, error dumps), not a
// child that encodes the value on purpose. A write error stops all
// further output (fail closed: never fall back to unmasked).
type redactWriter struct {
	mu     sync.Mutex
	out    io.Writer
	vals   [][]byte
	labels [][]byte
	buf    []byte
	failed error
}

func newRedactWriter(out io.Writer, vals, labels [][]byte) *redactWriter {
	return &redactWriter{out: out, vals: vals, labels: labels}
}

// pendingPrefix is the length of the longest tail of b that is a proper
// prefix of some secret — the bytes that must wait for the next write.
func (w *redactWriter) pendingPrefix(b []byte) int {
	best := 0
	for _, v := range w.vals {
		for k := min(len(b), len(v)-1); k > best; k-- {
			if bytes.HasSuffix(b, v[:k]) {
				best = k
				break
			}
		}
	}
	return best
}

func (w *redactWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.failed != nil {
		return 0, w.failed
	}
	w.buf = append(w.buf, p...)
	for i, v := range w.vals {
		w.buf = bytes.ReplaceAll(w.buf, v, w.labels[i])
	}
	if n := len(w.buf) - w.pendingPrefix(w.buf); n > 0 {
		if _, err := w.out.Write(w.buf[:n]); err != nil {
			w.failed = err
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
	if len(w.buf) == 0 || w.failed != nil {
		return w.failed
	}
	_, err := w.out.Write(w.buf)
	w.buf = w.buf[:0]
	return err
}
