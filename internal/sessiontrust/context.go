// Package sessiontrust resolves the "trust context" for the current
// `dop` invocation — the stable identifier under which an operator's
// approval is cached so burst invocations in the same conversation /
// terminal / shell session don't re-trigger the approval popup.
//
// Precedence (counselor E design, rc6i):
//
//  1. DOP_SESSION_ID               explicit, caller-provided
//  2. CLAUDE_CODE_SESSION_ID       recognized harness adapter (opt-in)
//  3. controlling tty              /dev/pts/… for terminal sessions
//  4. getsid()                     POSIX session id (best-effort kernel signal)
//  5. getppid()                    parent process id (final compatibility fallback)
//
// Each context carries a Kind namespace so a raw UUID from Claude Code
// is never conflated with the same raw UUID from a user-set
// DOP_SESSION_ID or a hypothetical future harness adapter. The daemon
// keys its grant cache on `<Kind>:<Value>:<Subject>` so cross-adapter
// collisions are structurally impossible.
//
// The resolver is intentionally allocation-light and side-effect-free:
// it reads env, calls one or two syscalls, and returns. Testable by
// seeding env and comparing output.

package sessiontrust

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// Kind namespaces a trust context so values from different sources
// can share the daemon's grant map without colliding.
type Kind string

const (
	// KindExplicit — the operator (or wrapping harness) exported
	// DOP_SESSION_ID. Treated as the authoritative session identity.
	KindExplicit Kind = "explicit"
	// KindHarness — a recognized harness exposed a session id. The
	// kind-value is `harness:<adapter>:<id>` so Claude Code's UUID is
	// never conflated with a Cursor adapter even if the raw UUIDs
	// happened to match. Opt-in via DOP_INFER_HARNESS_SESSION=1 for
	// now; counselor recommended a cautious rollout.
	KindHarness Kind = "harness"
	// KindTTY — controlling terminal device path. Stable across shell
	// invocations in the same terminal; absent in headless agents.
	KindTTY Kind = "tty"
	// KindSID — POSIX session id from getsid(0). Best-effort kernel
	// signal; stable within a POSIX session but reset by setsid(),
	// which many PTY allocators / supervisors / IDE integrations do.
	KindSID Kind = "sid"
	// KindPPID — parent process id. One-shot in LLM Bash tools that
	// spawn fresh bashes per call; works fine in interactive shells.
	// Final-fallback compatibility level matching pre-rc6i behavior.
	KindPPID Kind = "ppid"
)

// Context is the stable identifier the daemon keys its grant map on.
// Zero-value Context is NOT valid; always build via Resolve().
type Context struct {
	Kind  Kind
	Value string
}

// String returns the canonical `<kind>:<value>` form used as part of
// the daemon's grant-map key. Never log the raw value in operator-
// facing output; use Describe() for the human-readable form instead.
func (c Context) String() string {
	return string(c.Kind) + ":" + c.Value
}

// Describe returns an operator-friendly label for diagnostic output
// (e.g. "trust context: explicit session id" or "tty /dev/pts/4").
// Safe for stderr / audit — never prints raw session id values.
func (c Context) Describe() string {
	switch c.Kind {
	case KindExplicit:
		return "explicit session id (DOP_SESSION_ID)"
	case KindHarness:
		switch {
		case strings.HasPrefix(c.Value, "claude:"):
			return "harness session (CLAUDE_CODE_SESSION_ID)"
		case strings.HasPrefix(c.Value, "codex:"):
			return "harness session (CODEX_THREAD_ID)"
		case strings.HasPrefix(c.Value, "opencode:"):
			return "harness session (OPENCODE_SESSION_ID)"
		default:
			return "harness session"
		}
	case KindTTY:
		return "tty " + c.Value
	case KindSID:
		return "kernel session id " + c.Value
	case KindPPID:
		return "parent pid " + c.Value
	default:
		return "unknown"
	}
}

// Resolve walks the precedence stack and returns the first viable
// context. Guaranteed to return a non-empty context (the PPID path
// is always available). Does not consult the daemon or any external
// state — pure function of env + current process.
func Resolve() Context {
	return resolveWith(resolverEnv{
		getenv:   os.Getenv,
		getsid:   defaultGetsid,
		getppid:  os.Getppid,
		readTTY:  readControllingTTY,
	})
}

// resolverEnv lets tests inject env + runtime calls without touching
// the real process. Not exported; tests live in the same package.
type resolverEnv struct {
	getenv  func(string) string
	getsid  func(pid int) (int, error)
	getppid func() int
	readTTY func() (string, bool)
}

func resolveWith(e resolverEnv) Context {
	if v := e.getenv("DOP_SESSION_ID"); isValidSessionID(v) {
		return Context{Kind: KindExplicit, Value: v}
	}
	// rc7i — multi-harness adapter. Precedence inside the harness
	// branch is determined by DOP_HARNESS:
	//
	//   claude-code → try CLAUDE_CODE_SESSION_ID only
	//   codex       → try CODEX_THREAD_ID only
	//   opencode    → try OPENCODE_SESSION_ID only
	//   any         → try all three in Claude → Codex → opencode order
	//   none / unset → fall through to tty/sid/ppid
	//
	// Legacy DOP_INFER_HARNESS_SESSION=1 is treated as DOP_HARNESS=any
	// so pre-rc7i configs keep working without changes. The CLI entry
	// points (printguard, trust context) set DOP_HARNESS from
	// userprefs.Harness before calling Resolve, so operators who
	// picked a harness in Settings never need to touch an env var.
	harness := strings.ToLower(strings.TrimSpace(e.getenv("DOP_HARNESS")))
	if harness == "" && e.getenv("DOP_INFER_HARNESS_SESSION") == "1" {
		harness = "any"
	}
	if h := harnessContext(e, harness); h.Kind != "" {
		return h
	}
	if tty, ok := e.readTTY(); ok {
		return Context{Kind: KindTTY, Value: tty}
	}
	if sid, err := e.getsid(0); err == nil && sid > 0 {
		return Context{Kind: KindSID, Value: strconv.Itoa(sid)}
	}
	return Context{Kind: KindPPID, Value: strconv.Itoa(e.getppid())}
}

// harnessContext consults the harness env vars according to the
// requested harness mode and returns the first viable match. Returns
// a zero-Kind Context when nothing matches (caller falls through to
// tty/sid/ppid).
func harnessContext(e resolverEnv, mode string) Context {
	type adapter struct {
		mode   string // DOP_HARNESS value that selects THIS adapter alone
		envVar string
		prefix string // namespace prefix in Context.Value
	}
	all := []adapter{
		{mode: "claude-code", envVar: "CLAUDE_CODE_SESSION_ID", prefix: "claude:"},
		{mode: "codex", envVar: "CODEX_THREAD_ID", prefix: "codex:"},
		{mode: "opencode", envVar: "OPENCODE_SESSION_ID", prefix: "opencode:"},
	}
	switch mode {
	case "", "none":
		return Context{}
	case "any":
		for _, a := range all {
			if v := e.getenv(a.envVar); isValidSessionID(v) {
				return Context{Kind: KindHarness, Value: a.prefix + v}
			}
		}
	default:
		for _, a := range all {
			if a.mode != mode {
				continue
			}
			if v := e.getenv(a.envVar); isValidSessionID(v) {
				return Context{Kind: KindHarness, Value: a.prefix + v}
			}
		}
	}
	return Context{}
}

// isValidSessionID enforces the "opaque, bounded, no control chars"
// hygiene the counselor flagged for IDs sourced from env. Rejects
// empty, overlong, and ASCII-control-containing values. Does NOT
// enforce randomness or format; callers can hand us UUIDs, hex, or
// any opaque bytes that round-trip as a string.
func isValidSessionID(v string) bool {
	if v == "" || len(v) > 256 {
		return false
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// defaultGetsid wraps unix.Getsid for the resolver injection point.
// Uses golang.org/x/sys/unix because syscall.Getsid is Darwin-only
// in the stdlib — the x/sys variant works on both Darwin and Linux.
func defaultGetsid(pid int) (int, error) {
	return unix.Getsid(pid)
}

// readControllingTTY builds a stable identifier for the controlling
// terminal if one of our standard streams is attached to a real tty.
// Returns ("", false) when no stream is a tty — the normal case for
// LLM-driven Bash tools, which run commands with pipes for stdio.
//
// Why not os.File.Name(): Go hardcodes "/dev/stdin" / "/dev/stdout" /
// "/dev/stderr" as the Name() of inherited stdio regardless of the
// underlying device. Using that string would make every operator on
// the host share the SAME tty value — total cross-context collision.
// Instead we read the kernel's device-number (Rdev) from fstat, which
// is unique per pty on the host and stable across shell invocations
// in the same terminal.
func readControllingTTY() (string, bool) {
	// Order: stdin first (most reliably attached in operator shells),
	// stderr second, stdout last (often piped under $() capture even
	// in operator-at-terminal flows).
	for _, f := range []*os.File{os.Stdin, os.Stderr, os.Stdout} {
		fd := int(f.Fd())
		// term.IsTerminal is the real "is this a tty" check — more
		// precise than fstat mode bits, and matches what the operator
		// means by "I'm at a terminal."
		if !term.IsTerminal(fd) {
			continue
		}
		fi, err := f.Stat()
		if err != nil {
			continue
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		// Rdev is the device number of the special file (major:minor).
		// Unique per pty on the host; stable while the pty exists.
		return fmt.Sprintf("rdev:%d", st.Rdev), true
	}
	return "", false
}
