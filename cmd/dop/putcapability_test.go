package main

import (
	"testing"

	"github.com/fray/dop/internal/capability"
	"github.com/fray/dop/internal/vault"
)

// Every record rewrite (revoke, repin, reseal, grant edit, rotate, cascade)
// goes through putCapability; the portable stash must survive all of them.
func TestPutCapabilityKeepsPortableStash(t *testing.T) {
	rewrites := map[string]func(*capability.Record){
		"revoke":     func(r *capability.Record) { r.Status = capability.RecordStatusRevoked },
		"reseal":     func(r *capability.Record) { r.EnvWrapped = &capability.WrappedEnv{Ciphertext: "x", Generation: 2} },
		"grants":     func(r *capability.Record) { r.Grants = append(r.Grants, "g2") },
		"resign":     func(r *capability.Record) { r.Signature = "new" },
		"generation": func(r *capability.Record) { r.Generation++ },
	}
	for name, mut := range rewrites {
		t.Run(name, func(t *testing.T) {
			v := &vault.Vault{Capabilities: map[string]vault.Capability{
				"id1": {Subject: "s", Grants: []string{"g1"}, Status: capability.RecordStatusActive, PortableWrapped: "age-stash"},
			}}
			rec := vaultCapability2Record(v.Capabilities["id1"], "id1")
			mut(&rec)
			putCapability(v, "id1", rec)
			if got := v.Capabilities["id1"].PortableWrapped; got != "age-stash" {
				t.Fatalf("stash dropped: %q", got)
			}
		})
	}
	v := &vault.Vault{}
	putCapability(v, "fresh", capability.Record{Subject: "s"})
	if v.Capabilities["fresh"].PortableWrapped != "" {
		t.Fatal("fresh id must not inherit a stash")
	}
}
