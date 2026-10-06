package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/approval"
	"github.com/fray/dop/internal/capability"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

// TestTokenPortable runs dop token portable against a fixture HOME with an
// in-process admin session (real signing, real sops round-trip).
func TestTokenPortable(t *testing.T) {
	paths, client, keys := tokenFixture(t)
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

	// Plain rotate carries the stash to the new record and audits it.
	if rc := runTokenRotate([]string{"agent"}); rc != 0 {
		t.Fatalf("rotate: rc=%d", rc)
	}
	v = load()
	r2 := active(v, "agent")
	if r2.LookupID == n.LookupID || r2.PortableWrapped == "" || capability.LookupID(ctx, unwrap(r2)) != r2.LookupID {
		t.Fatalf("rotate lost the portable copy: lookup=%s stash=%q", r2.LookupID, r2.PortableWrapped)
	}
	if b, _ := os.ReadFile(filepath.Join(paths.Logs, "audit.jsonl")); !strings.Contains(string(b), `"event":"rotate"`) {
		t.Fatalf("no rotate audit event: %s", b)
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

// TestTokenRepin: repin re-issues an unclaimed bearer with a new PIN,
// the old one revoked and its portable stash carried to the new bearer.
func TestTokenRepin(t *testing.T) {
	paths, client, keys := tokenFixture(t)
	r, w, _ := os.Pipe()
	stdout := os.Stdout
	os.Stdout = w
	before := time.Now()
	rc := runTokenRepin([]string{"--subject", "laptop", "--pin-ttl", "5m"})
	os.Stdout = stdout
	w.Close()
	out, _ := io.ReadAll(r)
	if rc != 0 {
		t.Fatalf("repin unclaimed: rc=%d", rc)
	}
	v, _, err := loadVaultViaDaemon(client, paths)
	must(t, err)
	if old := v.Capabilities["unclaimed"]; old.Status != capability.RecordStatusRevoked {
		t.Fatalf("old record: status=%s", old.Status)
	}
	id, err := activeBySubject(v, "laptop")
	must(t, err)
	n := v.Capabilities[id]
	lines := strings.Fields(string(out))
	ctx, _ := hex.DecodeString(v.VaultContext)
	if len(lines) != 2 || n.LookupID == "bbbbbbbbbbbbbbbbbbbbbbbb" || capability.LookupID(ctx, lines[0]) != n.LookupID {
		t.Fatalf("new record: stdout=%q lookup=%s", out, n.LookupID)
	}
	if n.Binding == nil || n.Binding.Kind != vault.BindingKindPIN || n.Binding.Pubkey != "" {
		t.Fatalf("new binding: %+v", n.Binding)
	}
	if d := n.Binding.PinExpiry.Sub(before); d < 4*time.Minute || d > 6*time.Minute {
		t.Fatalf("PIN TTL: expiry %s is %s after the run", n.Binding.PinExpiry, d)
	}
	b, err := admin.UnwrapWithIdentity(n.PortableWrapped, keys.Age)
	if err != nil || string(b) != lines[0] {
		t.Fatalf("stash not carried over: %v", err)
	}
	for _, s := range []string{"agent", "gone"} { // claimed, revoked: refused
		if rc := runTokenRepin([]string{"--subject", s}); rc != 1 {
			t.Fatalf("repin %s: rc=%d", s, rc)
		}
	}
}

// TestTokenPrune: old revoked/rotated records go, recent ones and active
// ones stay, generations are untouched, one audit event, --dry-run is inert.
func TestTokenPrune(t *testing.T) {
	paths, client, _ := tokenFixture(t)
	v, vaultPath, err := loadVaultViaDaemon(client, paths)
	must(t, err)
	old, recent := time.Now().Add(-40*24*time.Hour), time.Now().Add(-24*time.Hour)
	add := func(id, status string, at time.Time) {
		c := vault.Capability{Subject: id, Grants: []string{"github"}, CreatedAt: old, ExpiresAt: tokenNeverSentinel(),
			LookupID: strings.Repeat(id[:1], 24), Status: status}
		switch {
		case status == capability.RecordStatusRotated:
			c.BearerWrapped = &vault.WrappedBearer{SealedAt: at} // rotation time, not creation, guards the record
		case id == "yrevday":
			c.CreatedAt, c.RevokedAt = time.Now().Add(-90*24*time.Hour), at // ages from RevokedAt, not CreatedAt
		default:
			c.CreatedAt = at
		}
		v.Capabilities[id] = c
	}
	add("rotold", capability.RecordStatusRotated, old)
	add("frotnew", capability.RecordStatusRotated, recent)
	add("revnew", capability.RecordStatusRevoked, recent)
	add("yrevday", capability.RecordStatusRevoked, recent)
	must(t, saveVaultViaDaemon(client, paths, vaultPath, v))
	rec := filepath.Join(paths.Vault, "capabilities", "cccccccccccccccccccccccc.record")
	must(t, os.MkdirAll(filepath.Dir(rec), 0o700))
	must(t, os.WriteFile(rec, []byte("{}"), 0o600))
	gens := v.Generations

	if rc := runTokenPrune([]string{"--dry-run"}); rc != 0 {
		t.Fatalf("dry-run: rc=%d", rc)
	}
	v, _, err = loadVaultViaDaemon(client, paths)
	must(t, err)
	if len(v.Capabilities) != 7 {
		t.Fatalf("dry-run changed the vault: %d records", len(v.Capabilities))
	}
	if rc := runTokenPrune([]string{"--older-than", "30d"}); rc != 0 {
		t.Fatalf("prune: rc=%d", rc)
	}
	v, _, err = loadVaultViaDaemon(client, paths)
	must(t, err)
	for _, id := range []string{"gone", "rotold"} {
		if _, ok := v.Capabilities[id]; ok {
			t.Fatalf("%s not pruned", id)
		}
	}
	for _, id := range []string{"claimed", "unclaimed", "frotnew", "revnew", "yrevday"} {
		if _, ok := v.Capabilities[id]; !ok {
			t.Fatalf("%s pruned", id)
		}
	}
	if _, err := os.Stat(rec); !os.IsNotExist(err) {
		t.Fatalf("record file left behind: %v", err)
	}
	if fmt.Sprint(v.Generations) != fmt.Sprint(gens) {
		t.Fatalf("generations changed: %v -> %v", gens, v.Generations)
	}
	b, _ := os.ReadFile(filepath.Join(paths.Logs, "audit.jsonl"))
	if !strings.Contains(string(b), `"event":"prune"`) || !strings.Contains(string(b), "cccccccccccc,rrrrrrrrrrrr") {
		t.Fatalf("no prune audit event: %s", b)
	}
	if rc := runTokenPrune(nil); rc != 0 {
		t.Fatalf("second prune: rc=%d", rc)
	}
}

// tokenFixture is a temporary HOME with an in-process admin session and a
// vault holding a claimed (agent), an unclaimed PIN-bound with a portable
// stash (laptop) and a revoked (gone) bearer.
func tokenFixture(t *testing.T) (*config.Paths, *admin.Client, *admin.Keys) {
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
	return paths, client, keys
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
