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
	// A vault repo here → the host's entry travels with it.
	must(os.MkdirAll(filepath.Join(paths.Vault, ".git"), 0o755))
	rel, err := Record(paths)
	if err != nil || rel != "agent-rules" {
		t.Fatalf("vault entry: %q %v", rel, err)
	}
	if _, err := os.Stat(filepath.Join(paths.Vault, rel, "abc123.json")); err != nil {
		t.Fatal(err)
	}
	// A second install on the same host must not erase the first.
	other := &config.Paths{Root: t.TempDir(), Vault: paths.Vault}
	must(os.MkdirAll(filepath.Join(other.Root, "agent-keys"), 0o700))
	must(os.WriteFile(filepath.Join(other.Root, "agent-keys", "def456.key"), []byte("k"), 0o600))
	if _, err := Record(other); err != nil {
		t.Fatal(err)
	}
	if c := Confirmed(&config.Paths{Root: t.TempDir(), Vault: paths.Vault}); !c["abc123"] || !c["def456"] {
		t.Fatalf("both installs on the host must stay confirmed: %v", c)
	}
	// The admin reads the vault entries of other hosts.
	admin := &config.Paths{Root: t.TempDir(), Vault: paths.Vault}
	if !Confirmed(admin)["abc123"] {
		t.Fatal("admin must see the host's ack through the vault")
	}
	if Status(Confirmed(admin), "abc123", true) != "confirmed" || Status(Confirmed(admin), "zzz", true) != "unconfirmed" || Status(nil, "x", false) != "" {
		t.Fatal("status words")
	}
	if d := Detail(Acks(admin), "abc123", true); !strings.HasPrefix(d, "confirmed by ") {
		t.Fatalf("detail %q", d)
	}
	if d := Detail(Acks(admin), "zzz", true); !strings.HasPrefix(d, "not confirmed") {
		t.Fatalf("detail %q", d)
	}
	if len(Text) < 200 || Text[0] != '#' {
		t.Fatal("rules text embedded")
	}
}
