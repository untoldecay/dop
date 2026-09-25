// Package audit writes JSONL access logs.
//
// Log location: <config>/logs/access-<host>-<YYYY-MM>.jsonl
// One line per attempted operation (exec, whoami, env, token issue/revoke,
// denied). Bearer tokens are NEVER written raw — always hashed and truncated.
//
// Files are per-host so two machines pulling into the same vault repo do
// not fight over the same file on commit.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Event is one log line's shape. `omitempty` throughout so tests, CLI, and
// human readers see a compact record.
type Event struct {
	TS         string   `json:"ts"`                     // RFC3339 UTC
	Host       string   `json:"host,omitempty"`         // short hostname
	Op         string   `json:"op"`                     // exec, whoami, env, token-issue, token-revoke, ...
	AgentName  string   `json:"agent_name,omitempty"`   // self-reported for bearer; verified for signed
	AuthMethod string   `json:"auth_method,omitempty"`  // bearer, signed, "-"
	TokenHash  string   `json:"token_hash,omitempty"`   // sha256(bearer) first 16 hex chars — never the raw bearer
	Grants     []string `json:"grants_used,omitempty"`
	Outcome    string   `json:"outcome"`                // ok, denied, error
	Reason     string   `json:"reason,omitempty"`       // short string on non-ok
	CmdHead    string   `json:"cmd_head,omitempty"`     // first ~60 chars of child cmd (exec only)
}

// Writer is a lightweight audit-log sink. Zero value works; the LogsDir is
// resolved lazily so package init doesn't blow up on non-DOP hosts.
type Writer struct {
	LogsDir string // e.g. ~/.config/dop/logs
	Host    string // resolved at first write, cached
}

// New returns a Writer scoped to logsDir. If logsDir is empty, Log() is a
// silent no-op (useful in tests, or for callers that haven't run `dop init`).
func New(logsDir string) *Writer {
	return &Writer{LogsDir: logsDir}
}

// Log emits an event to the per-host, per-month JSONL file. Returns any
// filesystem error but callers typically ignore it — audit failure must
// not break the credential resolution hot path.
func (w *Writer) Log(e Event) error {
	if w == nil || w.LogsDir == "" {
		return nil
	}
	if e.TS == "" {
		e.TS = time.Now().UTC().Format(time.RFC3339)
	}
	if e.Host == "" {
		e.Host = w.hostname()
	}
	if err := os.MkdirAll(w.LogsDir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(w.LogsDir, w.filenameFor(e.TS))
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	line, err := json.Marshal(e)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	return nil
}

func (w *Writer) filenameFor(ts string) string {
	// ts is RFC3339; carve out YYYY-MM.
	ym := "unknown"
	if len(ts) >= 7 {
		ym = ts[:7]
	}
	host := w.hostname()
	return fmt.Sprintf("access-%s-%s.jsonl", host, ym)
}

func (w *Writer) hostname() string {
	if w.Host != "" {
		return w.Host
	}
	h, _ := os.Hostname()
	if h == "" {
		h = "unknown"
	}
	// Short hostname (before any dot). Keeps filenames reasonable on macOS
	// where hostname often includes .local / .lan suffixes.
	if i := strings.IndexByte(h, '.'); i > 0 {
		h = h[:i]
	}
	// Filesystem-safe.
	h = strings.NewReplacer("/", "-", " ", "-", ":", "-").Replace(h)
	w.Host = h
	return h
}

// HashBearer returns the first 16 hex chars of sha256(bearer). Deterministic,
// non-reversible identifier — safe to log.
func HashBearer(bearer string) string {
	if bearer == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(bearer))
	return hex.EncodeToString(sum[:])[:16]
}

// TruncCmdHead trims a child command's argv[0] + args to a short display
// string for the audit log. Never leaks env vars, only what appears after
// `dop exec ... --`.
func TruncCmdHead(argv []string) string {
	if len(argv) == 0 {
		return ""
	}
	s := strings.Join(argv, " ")
	const max = 60
	if len(s) > max {
		s = s[:max] + "…"
	}
	return s
}
