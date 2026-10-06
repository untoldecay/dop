package main

import (
	"strings"
	"testing"

	"filippo.io/age"
	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/capability"
	"github.com/fray/dop/internal/vault"
)

func TestSetPortable(t *testing.T) {
	ctx := []byte("fixture-vault-context")
	bearer := "dop_fixture_bearer"
	id, _ := age.GenerateX25519Identity()
	fresh := func() *vault.Vault {
		return &vault.Vault{Capabilities: map[string]vault.Capability{
			"a": {Subject: "laptop", Status: capability.RecordStatusActive, LookupID: capability.LookupID(ctx, bearer), PortableWrapped: "old"},
			"b": {Subject: "gone", Status: capability.RecordStatusRevoked, LookupID: capability.LookupID(ctx, bearer)},
		}}
	}

	v := fresh()
	if _, err := setPortable(v, "laptop", "", nil, ""); err != nil || v.Capabilities["a"].PortableWrapped != "" {
		t.Fatalf("off: err=%v stash=%q", err, v.Capabilities["a"].PortableWrapped)
	}

	v = fresh()
	if _, err := setPortable(v, "laptop", bearer, ctx, id.Recipient().String()); err != nil {
		t.Fatal(err)
	}
	got, err := admin.UnwrapWithIdentity(v.Capabilities["a"].PortableWrapped, id)
	if err != nil || string(got) != bearer {
		t.Fatalf("on: unwrap=%q err=%v", got, err)
	}

	v = fresh()
	if _, err := setPortable(v, "laptop", "wrong", ctx, id.Recipient().String()); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("mismatch: %v", err)
	}
	if v.Capabilities["a"].PortableWrapped != "old" {
		t.Fatal("mismatch must leave the stash alone")
	}
	if _, err := setPortable(v, "gone", bearer, ctx, id.Recipient().String()); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked: %v", err)
	}
}
