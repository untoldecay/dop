package agentrules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fray/dop/internal/config"
)

func TestAckNudgeConfirmed(t *testing.T) {
	root := t.TempDir()
	paths := &config.Paths{Root: root, Vault: filepath.Join(root, "vault")}
	must := func(err error) {
		if err != nil {
			t.Fatal(err)
		}
	}
	must(os.MkdirAll(filepath.Join(root, "agent-keys"), 0o700))
	must(os.WriteFile(filepath.Join(root, "agent-keys", "abc123.p256"), []byte("k"), 0o600))
	if !NudgeDue(paths) || NudgeDue(paths) {
		t.Fatal("nudge once an hour while unacknowledged")
	}
	if rel, err := Record(paths); err != nil || rel != "" {
		t.Fatalf("no vault repo → local ack only: %q %v", rel, err)
	}
	if !AckedHere(paths) || NudgeDue(paths) || !Confirmed(paths)["abc123"] {
		t.Fatal("ack must stop the nudge and confirm the local key")
	}
	must(os.MkdirAll(filepath.Join(paths.Vault, ".git"), 0o755))
	rel, err := Record(paths)
	if err != nil || rel != "agent-rules" {
		t.Fatalf("vault entry: %q %v", rel, err)
	}
	other := &config.Paths{Root: t.TempDir(), Vault: paths.Vault}
	must(os.MkdirAll(filepath.Join(other.Root, "agent-keys"), 0o700))
	must(os.WriteFile(filepath.Join(other.Root, "agent-keys", "def456.key"), []byte("k"), 0o600))
	if _, err := Record(other); err != nil {
		t.Fatal(err)
	}
	admin := &config.Paths{Root: t.TempDir(), Vault: paths.Vault}
	acks := Load(admin)
	if !Confirmed(admin)["abc123"] || !Confirmed(admin)["def456"] {
		t.Fatal("both installs on the host must stay confirmed")
	}
	host, _ := os.Hostname()
	// Bound bearer: by key. Lease: by the host in its subject. Portable
	// original: nothing. Unclaimed PIN bearer: not yet.
	if d := Describe(acks, "abc123", "buzz", true, false); !d.Show || d.Status != "confirmed" || !strings.HasPrefix(d.Detail, "confirmed by ") {
		t.Fatalf("bound %+v", d)
	}
	if d := Describe(acks, "zzz", "buzz", true, false); d.Status != "unconfirmed" {
		t.Fatalf("unconfirmed %+v", d)
	}
	if d := Describe(acks, "lease1", "cam-shell@"+host, false, false); !d.Show || d.Status != "confirmed" {
		t.Fatalf("lease by host %+v", d)
	}
	if d := Describe(acks, "lease2", "cam-shell@elsewhere", false, false); d.Status != "unconfirmed" {
		t.Fatalf("lease on an unacked host %+v", d)
	}
	if d := Describe(acks, "p1", "cam-shell", false, true); d.Show {
		t.Fatalf("portable original shows nothing %+v", d)
	}
	if d := Describe(acks, "u1", "new-agent", false, false); !d.Show || d.Status != "" {
		t.Fatalf("unclaimed %+v", d)
	}
	if HostOf("a@b@c") != "c" || HostOf("plain") != "" {
		t.Fatal("HostOf")
	}
	if len(Text) < 200 || Text[0] != '#' || !strings.Contains(Text, "dop exec --use") {
		t.Fatal("rules text embedded")
	}
}
