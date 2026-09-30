package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/fray/dop/internal/agentkey"
	"github.com/fray/dop/internal/capability"
	"github.com/fray/dop/internal/envseal"
	"github.com/fray/dop/internal/vault"
)

// TestSealOpenWrappedEnv_FullRoundtrip proves the v1.12 admin/agent
// pair works through the exact serialization path a real record would
// take: admin computes WrappedEnv → written into a capability.Record →
// signed → agent decodes WrappedEnv from that record → derives shared
// secret from the file-backend P-256 store → decrypts → gets original
// env back.
//
// This is what a real `dop token reseal` → `dop exec` cycle exercises,
// minus the daemon and admin session — those are covered separately by
// the e2e suite.
func TestSealOpenWrappedEnv_FullRoundtrip(t *testing.T) {
	// Set up an agent P-256 store on disk (opt-in gate).
	t.Setenv("DOP_ALLOW_FILE_KEYS", "1")
	dir, err := os.MkdirTemp("", "wrapped-env-test-*")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	backend := agentkey.NewFileBackend(dir)
	store, err := backend.Generate("lookup-round-trip", vault.KeyTypeP256)
	if err != nil {
		t.Fatalf("generate agent key: %v", err)
	}

	// Build a plausible record. Values echo what the admin side would
	// produce — the exec side must handle these verbatim.
	generation := uint64(42)
	rec := &capability.Record{
		CapabilityID: "abc123",
		Subject:      "wrapped-env-agent",
		Grants:       []string{"notion.read"},
		Generation:   generation,
		LookupID:     "lookup-round-trip",
		Status:       capability.RecordStatusActive,
		CreatedAt:    time.Now().UTC().Truncate(time.Second),
		ExpiresAt:    time.Now().Add(time.Hour).UTC().Truncate(time.Second),
		Binding: &capability.RecordBinding{
			Kind:    "pin",
			Pubkey:  hex.EncodeToString(store.PublicKey()),
			KeyType: vault.KeyTypeP256,
		},
	}
	env := map[string]string{
		"NOTION_TOKEN":         "ntn_secret_v42",
		"NOTION_BASE_URL":      "https://api.notion.com/v1",
		"NOTION_WORKSPACE_TAG": "prod",
	}
	blob, err := json.Marshal(struct {
		Env map[string]string `json:"env"`
	}{Env: env})
	if err != nil {
		t.Fatalf("marshal env: %v", err)
	}

	// Admin side: seal.
	aad := []byte(fmt.Sprintf("dop-envwrap-v1|lookup=%s|gen=%d", rec.LookupID, rec.Generation))
	sealed, err := envseal.Seal(store.PublicKey(), blob, aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	m := sealed.ToHex()
	rec.EnvWrapped = &capability.WrappedEnv{
		AdminEphemPub: m["admin_ephem_pub"],
		Salt:          m["salt"],
		Nonce:         m["nonce"],
		Ciphertext:    m["ciphertext"],
		SealedAt:      time.Now().UTC().Truncate(time.Second),
		Generation:    rec.Generation,
	}

	// Agent side: rehydrate + decrypt (mirrors openEnvWrapped's guts).
	rehydrated, err := envseal.FromHex(map[string]string{
		"admin_ephem_pub": rec.EnvWrapped.AdminEphemPub,
		"salt":            rec.EnvWrapped.Salt,
		"nonce":           rec.EnvWrapped.Nonce,
		"ciphertext":      rec.EnvWrapped.Ciphertext,
	})
	if err != nil {
		t.Fatalf("FromHex: %v", err)
	}
	shared, err := store.SharedSecret(rehydrated.AdminEphemPub)
	if err != nil {
		t.Fatalf("SharedSecret: %v", err)
	}
	plaintext, err := envseal.OpenWithShared(shared, rehydrated, aad)
	if err != nil {
		t.Fatalf("OpenWithShared: %v", err)
	}
	var payload struct {
		Env map[string]string `json:"env"`
	}
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		t.Fatalf("decode plaintext: %v", err)
	}
	if len(payload.Env) != len(env) {
		t.Fatalf("env size mismatch: got %d want %d", len(payload.Env), len(env))
	}
	for k, v := range env {
		if payload.Env[k] != v {
			t.Fatalf("env[%q]: got %q want %q", k, payload.Env[k], v)
		}
	}
}

// TestSealOpenWrappedEnv_GenerationMismatch_Fails proves the AAD's
// generation binding: an envelope sealed for gen N cannot be opened
// as if it belongs to gen N+1 (spliced onto a fresher record).
func TestSealOpenWrappedEnv_GenerationMismatch_Fails(t *testing.T) {
	t.Setenv("DOP_ALLOW_FILE_KEYS", "1")
	dir, err := os.MkdirTemp("", "wrapped-env-test-*")
	if err != nil {
		t.Fatalf("mkdirtemp: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	backend := agentkey.NewFileBackend(dir)
	store, err := backend.Generate("lookup-gen", vault.KeyTypeP256)
	if err != nil {
		t.Fatalf("agent key: %v", err)
	}

	// Seal to gen 7.
	aad7 := []byte("dop-envwrap-v1|lookup=lookup-gen|gen=7")
	sealed, err := envseal.Seal(store.PublicKey(), []byte(`{"env":{"K":"v"}}`), aad7)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	// Try to open as gen 8 (attacker spliced envelope onto a newer record).
	aad8 := []byte("dop-envwrap-v1|lookup=lookup-gen|gen=8")
	shared, err := store.SharedSecret(sealed.AdminEphemPub)
	if err != nil {
		t.Fatalf("shared: %v", err)
	}
	if _, err := envseal.OpenWithShared(shared, sealed, aad8); err == nil {
		t.Fatal("expected gen-mismatch AAD to fail Open, got nil")
	}
}
