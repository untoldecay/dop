// dop-8g7 — a claimed agent that proved its bound key prints its env
// without approval; every other surface keeps the gate.

package printguard

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fray/dop/internal/config"
)

func guardPaths(t *testing.T) *config.Paths {
	t.Helper()
	root := t.TempDir()
	t.Setenv("DOP_FROM_TUI", "")
	t.Setenv("DOP_APPROVAL_PASSPHRASE", "")
	return &config.Paths{Root: root, KeysDir: filepath.Join(root, "keys"), Logs: filepath.Join(root, "logs")}
}

func auditLog(t *testing.T, p *config.Paths) string {
	t.Helper()
	var b strings.Builder
	files, _ := filepath.Glob(filepath.Join(p.Logs, "*"))
	for _, f := range files {
		data, _ := os.ReadFile(f)
		b.Write(data)
	}
	return b.String()
}

func TestKeyProvenEnvSkipsApproval(t *testing.T) {
	p := guardPaths(t)
	err := Guard(Request{Kind: KindEnv, Subject: "honey", Out: &bytes.Buffer{}, Paths: p, KeyProven: true, LookupID: "abc123"})
	if err != nil {
		t.Fatalf("key-proven env print must not need approval: %v", err)
	}
	if log := auditLog(t, p); !strings.Contains(log, "key_proof") || !strings.Contains(log, "print_approval_granted") {
		t.Fatalf("key-proof grant must be audited, got %q", log)
	}
}

// Without a usable approval the gate refuses; a wrong scripted
// passphrase is the fast, network-free way to reach that refusal.
func refusesWithoutApproval(t *testing.T, req Request) {
	t.Helper()
	t.Setenv("DOP_APPROVAL_PASSPHRASE", "not-the-passphrase")
	if err := Guard(req); err == nil {
		t.Fatalf("%s (KeyProven=%v) must still require approval", req.Kind, req.KeyProven)
	}
}

func TestKeyProofDoesNotCoverUse(t *testing.T) {
	p := guardPaths(t)
	refusesWithoutApproval(t, Request{Kind: KindUse, Subject: "s", Out: &bytes.Buffer{}, Paths: p, KeyProven: true})
}

func TestKeyProofDoesNotCoverIssueOrClaim(t *testing.T) {
	p := guardPaths(t)
	refusesWithoutApproval(t, Request{Kind: KindTokenIssue, Subject: "s", Out: &bytes.Buffer{}, Paths: p, KeyProven: true})
	refusesWithoutApproval(t, Request{Kind: KindClaim, Subject: "s", Out: &bytes.Buffer{}, Paths: p, KeyProven: true})
}

func TestEnvWithoutProofStillGated(t *testing.T) {
	p := guardPaths(t)
	refusesWithoutApproval(t, Request{Kind: KindEnv, Subject: "s", Out: &bytes.Buffer{}, Paths: p})
}
