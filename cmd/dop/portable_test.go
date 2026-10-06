package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/approval"
	"github.com/fray/dop/internal/capability"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

// TestTokenPortable runs dop token portable against a fixture HOME with an
// in-process admin session (real signing, real sops round-trip).
func TestTokenPortable(t *testing.T) {
	if _, err := exec.LookPath("sops"); err != nil {
		t.Skip("sops not on PATH")
	}
	home, err := os.MkdirTemp("/tmp", "dopport") // short: unix socket path limit
	must(t, err)
	t.Cleanup(func() { os.RemoveAll(home) })
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("DOP_NO_AUTO_PUSH", "1")
	t.Setenv("DOP_FROM_TUI", "1")
	paths, err := config.Resolve()
	must(t, err)
	if !strings.HasPrefix(paths.Root, home) {
		t.Fatalf("paths escaped the fixture HOME: %s", paths.Root)
	}
	for _, d := range []string{paths.Vault, paths.KeysDir, paths.Logs} {
		must(t, os.MkdirAll(d, 0o700))
	}
	keys, err := admin.Generate()
	must(t, err)
	sess, err := admin.StartSession(admin.SessionOpts{Keys: keys, SockPath: admin.SockPath(paths)})
	must(t, err)
	t.Cleanup(sess.Shutdown)
	client := admin.NewClient(admin.SockPath(paths))

	agentKey, err := ecdh.P256().GenerateKey(rand.Reader)
	must(t, err)
	must(t, os.WriteFile(filepath.Join(paths.Vault, "vault.yaml"), []byte(`schema_version: v1
vault_context: 00112233445566778899aabbccddeeff00112233
generations: {agent: 3, laptop: 1, gone: 1}
admins:
  me:
    age_recipient: `+keys.Age.Recipient().String()+`
    ed25519_pubkey: `+keys.AdminPubkey()+`
integrations:
  gh:
    kind: cli
    tokens:
      gh: {value: ghp_fixture}
grants:
  github: {integration: gh, token: gh}
capabilities:
  claimed:
    subject: agent
    grants: [github]
    expires_at: 2999-01-01T00:00:00Z
    generation: 3
    lookup_id: aaaaaaaaaaaaaaaaaaaaaaaa
    status: active
    binding: {kind: pubkey, key_type: p256, pubkey: `+hex.EncodeToString(agentKey.PublicKey().Bytes())+`}
  unclaimed:
    subject: laptop
    grants: [github]
    expires_at: 2999-01-01T00:00:00Z
    generation: 1
    lookup_id: bbbbbbbbbbbbbbbbbbbbbbbb
    status: active
    portable_wrapped: old-stash
    binding: {kind: pin, pin_expiry: 2999-01-01T00:00:00Z}
  gone:
    subject: gone
    grants: [github]
    generation: 1
    lookup_id: cccccccccccccccccccccccc
    status: revoked
`), 0o600))
	load := func() *vault.Vault {
		v, _, err := loadVaultViaDaemon(client, paths)
		must(t, err)
		return v
	}
	active := func(v *vault.Vault, subject string) vault.Capability {
		id, err := activeBySubject(v, subject)
		must(t, err)
		return v.Capabilities[id]
	}
	unwrap := func(c vault.Capability) string {
		b, err := admin.UnwrapWithIdentity(c.PortableWrapped, keys.Age)
		must(t, err)
		return string(b)
	}

	// --off clears the stash, no re-issue, behind the approval passphrase.
	must(t, approval.Set(paths, "fixture-pass"))
	r, w, _ := os.Pipe()
	w.WriteString("fixture-pass\n")
	w.Close()
	stdin := os.Stdin
	os.Stdin = r
	rc := runTokenPortable([]string{"--subject", "laptop", "--off", "--passphrase-stdin"})
	os.Stdin = stdin
	if c := load().Capabilities["unclaimed"]; rc != 0 || c.PortableWrapped != "" || c.Status != capability.RecordStatusActive {
		t.Fatalf("--off: rc=%d stash=%q status=%s", rc, c.PortableWrapped, c.Status)
	}

	// Claimed: rotated, the new record carries the stash.
	if rc := runTokenPortable([]string{"--subject", "agent", "--on"}); rc != 0 {
		t.Fatalf("--on claimed: rc=%d", rc)
	}
	v := load()
	if old := v.Capabilities["claimed"]; old.Status != capability.RecordStatusRotated || old.Generation != 4 || old.BearerWrapped == nil {
		t.Fatalf("old claimed record: status=%s gen=%d wrapped=%v", old.Status, old.Generation, old.BearerWrapped != nil)
	}
	n := active(v, "agent")
	ctx, _ := hex.DecodeString(v.VaultContext)
	if n.Generation != 4 || n.Binding.Pubkey == "" || capability.LookupID(ctx, unwrap(n)) != n.LookupID {
		t.Fatalf("new claimed record: gen=%d lookup=%s", n.Generation, n.LookupID)
	}

	// Unclaimed: re-issued with a new PIN, old revoked; bearer + PIN on stdout.
	r, w, _ = os.Pipe()
	stdout := os.Stdout
	os.Stdout = w
	rc = runTokenPortable([]string{"--subject", "laptop", "--on"})
	os.Stdout = stdout
	w.Close()
	out, _ := io.ReadAll(r)
	if rc != 0 {
		t.Fatalf("--on unclaimed: rc=%d", rc)
	}
	v = load()
	if old := v.Capabilities["unclaimed"]; old.Status != capability.RecordStatusRevoked {
		t.Fatalf("old unclaimed record: status=%s", old.Status)
	}
	n = active(v, "laptop")
	lines := strings.Fields(string(out))
	if len(lines) != 2 || lines[0] != unwrap(n) || n.Binding.Kind != vault.BindingKindPIN || capability.LookupID(ctx, lines[0]) != n.LookupID {
		t.Fatalf("unclaimed re-issue: stdout=%q binding=%v", out, n.Binding)
	}

	// Revoked: refused.
	if rc := runTokenPortable([]string{"--subject", "gone", "--on"}); rc != 1 {
		t.Fatalf("--on revoked: rc=%d", rc)
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
