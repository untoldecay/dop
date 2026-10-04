package sessiontrust

import (
	"errors"
	"strings"
	"testing"
)

// stubbed resolverEnv that lets each test name exactly which signals
// are present.
type stubEnv struct {
	env map[string]string
	sid int
	tty string
	ppid int
}

func (s stubEnv) toResolverEnv() resolverEnv {
	return resolverEnv{
		getenv: func(k string) string { return s.env[k] },
		getsid: func(_ int) (int, error) {
			if s.sid == 0 {
				return 0, errors.New("no sid")
			}
			return s.sid, nil
		},
		getppid: func() int { return s.ppid },
		readTTY: func() (string, bool) {
			if s.tty == "" {
				return "", false
			}
			return s.tty, true
		},
	}
}

func TestResolve_ExplicitWins(t *testing.T) {
	ctx := resolveWith(stubEnv{
		env: map[string]string{
			"DOP_SESSION_ID":          "operator-session-abc",
			"CLAUDE_CODE_SESSION_ID":  "claude-xyz",
			"DOP_INFER_HARNESS_SESSION": "1",
		},
		tty:  "/dev/pts/4",
		sid:  1234,
		ppid: 9999,
	}.toResolverEnv())
	if ctx.Kind != KindExplicit {
		t.Fatalf("expected explicit, got %v (%v)", ctx.Kind, ctx)
	}
	if ctx.Value != "operator-session-abc" {
		t.Fatalf("value wrong: %q", ctx.Value)
	}
}

func TestResolve_HarnessRequiresOptIn(t *testing.T) {
	// Without DOP_INFER_HARNESS_SESSION=1 the Claude variable is
	// ignored and the resolver falls through to tty.
	ctx := resolveWith(stubEnv{
		env: map[string]string{
			"CLAUDE_CODE_SESSION_ID": "claude-xyz",
		},
		tty:  "/dev/pts/4",
		ppid: 9999,
	}.toResolverEnv())
	if ctx.Kind != KindTTY {
		t.Fatalf("expected tty (harness not opted in), got %v", ctx)
	}
}

func TestResolve_HarnessOptedIn(t *testing.T) {
	ctx := resolveWith(stubEnv{
		env: map[string]string{
			"CLAUDE_CODE_SESSION_ID":    "claude-xyz",
			"DOP_INFER_HARNESS_SESSION": "1",
		},
		tty:  "/dev/pts/4",
		ppid: 9999,
	}.toResolverEnv())
	if ctx.Kind != KindHarness {
		t.Fatalf("expected harness, got %v", ctx)
	}
	if !strings.HasPrefix(ctx.Value, "claude:") {
		t.Fatalf("value missing claude: prefix: %q", ctx.Value)
	}
}

func TestResolve_TTYBeforeSID(t *testing.T) {
	ctx := resolveWith(stubEnv{
		env:  map[string]string{},
		tty:  "/dev/pts/4",
		sid:  1234,
		ppid: 9999,
	}.toResolverEnv())
	if ctx.Kind != KindTTY {
		t.Fatalf("expected tty before sid, got %v", ctx)
	}
}

func TestResolve_SIDFallback(t *testing.T) {
	// Headless agent: no tty, no explicit id. getsid wins over ppid.
	ctx := resolveWith(stubEnv{
		env:  map[string]string{},
		sid:  5678,
		ppid: 9999,
	}.toResolverEnv())
	if ctx.Kind != KindSID {
		t.Fatalf("expected sid, got %v", ctx)
	}
	if ctx.Value != "5678" {
		t.Fatalf("sid value wrong: %q", ctx.Value)
	}
}

func TestResolve_PPIDFinalFallback(t *testing.T) {
	// Everything missing — PPID is the compatibility floor.
	ctx := resolveWith(stubEnv{
		env:  map[string]string{},
		ppid: 42,
	}.toResolverEnv())
	if ctx.Kind != KindPPID {
		t.Fatalf("expected ppid, got %v", ctx)
	}
	if ctx.Value != "42" {
		t.Fatalf("ppid value wrong: %q", ctx.Value)
	}
}

func TestResolve_RejectsControlChars(t *testing.T) {
	// Operator exported a value containing a control char — resolver
	// should refuse to treat it as an explicit id. Falls through.
	ctx := resolveWith(stubEnv{
		env: map[string]string{
			"DOP_SESSION_ID": "bad\x01value",
		},
		ppid: 1,
	}.toResolverEnv())
	if ctx.Kind == KindExplicit {
		t.Fatalf("control char should have been rejected, got %v", ctx)
	}
}

func TestResolve_RejectsOverlong(t *testing.T) {
	// Value > 256 bytes — defensive against runaway env.
	huge := strings.Repeat("x", 300)
	ctx := resolveWith(stubEnv{
		env: map[string]string{
			"DOP_SESSION_ID": huge,
		},
		ppid: 1,
	}.toResolverEnv())
	if ctx.Kind == KindExplicit {
		t.Fatalf("overlong value should have been rejected, got %v", ctx)
	}
}

func TestContext_StringAndDescribe(t *testing.T) {
	cases := []struct {
		ctx        Context
		wantString string
		wantHuman  string
	}{
		{Context{KindExplicit, "abc"}, "explicit:abc", "explicit session id (DOP_SESSION_ID)"},
		{Context{KindHarness, "claude:xyz"}, "harness:claude:xyz", "harness session (CLAUDE_CODE_SESSION_ID)"},
		{Context{KindTTY, "/dev/pts/4"}, "tty:/dev/pts/4", "tty /dev/pts/4"},
		{Context{KindSID, "1234"}, "sid:1234", "kernel session id 1234"},
		{Context{KindPPID, "9999"}, "ppid:9999", "parent pid 9999"},
	}
	for _, c := range cases {
		if got := c.ctx.String(); got != c.wantString {
			t.Errorf("String(%v) = %q, want %q", c.ctx, got, c.wantString)
		}
		if got := c.ctx.Describe(); got != c.wantHuman {
			t.Errorf("Describe(%v) = %q, want %q", c.ctx, got, c.wantHuman)
		}
	}
}
