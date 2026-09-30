package vault

import (
	"testing"
)

// The field-reported bug that motivated the guard: a saveVaultViaDaemon
// call on M1 wrote an admin list that dropped macmini, silently
// cryptographically-orphaning M2. The merge honored this "removal" on
// the next auto-merge because the input truly looked like a removal to
// the merge. So the merge itself is arguably correct; these tests pin
// its behavior so we notice if the invariant ever changes.

func TestMerge_AddedOnBothSides_UnionsBoth(t *testing.T) {
	base := &Vault{SchemaVersion: SchemaVersion, Admins: map[string]Admin{
		"a": {Ed25519Pubkey: "PA", AgeRecipient: "RA"},
	}}
	local := &Vault{SchemaVersion: SchemaVersion, Admins: map[string]Admin{
		"a": {Ed25519Pubkey: "PA", AgeRecipient: "RA"},
		"b": {Ed25519Pubkey: "PB", AgeRecipient: "RB"},
	}}
	remote := &Vault{SchemaVersion: SchemaVersion, Admins: map[string]Admin{
		"a": {Ed25519Pubkey: "PA", AgeRecipient: "RA"},
		"c": {Ed25519Pubkey: "PC", AgeRecipient: "RC"},
	}}
	r := Merge(base, local, remote)
	if len(r.Conflicts) != 0 {
		t.Fatalf("expected no conflicts, got %d: %+v", len(r.Conflicts), r.Conflicts)
	}
	if len(r.Merged.Admins) != 3 {
		t.Fatalf("expected 3 admins after union, got %d: %+v", len(r.Merged.Admins), r.Merged.Admins)
	}
	for _, k := range []string{"a", "b", "c"} {
		if _, ok := r.Merged.Admins[k]; !ok {
			t.Errorf("missing admin %q in merged result", k)
		}
	}
}

func TestMerge_LocalRemovedRemoteKept_HonorsRemoval(t *testing.T) {
	// If local's Admins has one fewer than base and remote is unchanged,
	// the merge treats it as a local removal — which is CORRECT if the
	// user really ran `dop team remove` locally. The point of the
	// v1.10.4 guard is to make sure we never REACH this state via
	// accident.
	base := &Vault{SchemaVersion: SchemaVersion, Admins: map[string]Admin{
		"a": {Ed25519Pubkey: "PA", AgeRecipient: "RA"},
		"b": {Ed25519Pubkey: "PB", AgeRecipient: "RB"},
	}}
	local := &Vault{SchemaVersion: SchemaVersion, Admins: map[string]Admin{
		"a": {Ed25519Pubkey: "PA", AgeRecipient: "RA"},
	}}
	remote := &Vault{SchemaVersion: SchemaVersion, Admins: map[string]Admin{
		"a": {Ed25519Pubkey: "PA", AgeRecipient: "RA"},
		"b": {Ed25519Pubkey: "PB", AgeRecipient: "RB"},
	}}
	r := Merge(base, local, remote)
	if _, ok := r.Merged.Admins["b"]; ok {
		t.Fatalf("expected b removed after local-side removal, still present")
	}
	if _, ok := r.Merged.Admins["a"]; !ok {
		t.Fatalf("expected a to survive")
	}
}

func TestMerge_RemoteRemovedLocalKept_HonorsRemoval(t *testing.T) {
	base := &Vault{SchemaVersion: SchemaVersion, Admins: map[string]Admin{
		"a": {Ed25519Pubkey: "PA", AgeRecipient: "RA"},
		"b": {Ed25519Pubkey: "PB", AgeRecipient: "RB"},
	}}
	local := &Vault{SchemaVersion: SchemaVersion, Admins: map[string]Admin{
		"a": {Ed25519Pubkey: "PA", AgeRecipient: "RA"},
		"b": {Ed25519Pubkey: "PB", AgeRecipient: "RB"},
	}}
	remote := &Vault{SchemaVersion: SchemaVersion, Admins: map[string]Admin{
		"a": {Ed25519Pubkey: "PA", AgeRecipient: "RA"},
	}}
	r := Merge(base, local, remote)
	if _, ok := r.Merged.Admins["b"]; ok {
		t.Fatalf("expected b removed after remote-side removal, still present")
	}
}

func TestMerge_BothEditedSameKey_Conflicts(t *testing.T) {
	base := &Vault{SchemaVersion: SchemaVersion, Grants: map[string]Grant{
		"g": {Integration: "s", Token: "t"},
	}}
	local := &Vault{SchemaVersion: SchemaVersion, Grants: map[string]Grant{
		"g": {Integration: "s", Token: "t", Projects: []string{"proj-local"}},
	}}
	remote := &Vault{SchemaVersion: SchemaVersion, Grants: map[string]Grant{
		"g": {Integration: "s", Token: "t", Projects: []string{"proj-remote"}},
	}}
	r := Merge(base, local, remote)
	if len(r.Conflicts) != 1 {
		t.Fatalf("expected 1 conflict on grants.g, got %d", len(r.Conflicts))
	}
	if r.Conflicts[0].Key != "g" {
		t.Errorf("unexpected conflict key %q", r.Conflicts[0].Key)
	}
}

func TestMerge_CapabilitiesUnion(t *testing.T) {
	base := &Vault{SchemaVersion: SchemaVersion, Capabilities: map[string]Capability{}}
	local := &Vault{SchemaVersion: SchemaVersion, Capabilities: map[string]Capability{
		"aa": {Subject: "tokenL", Status: "active", Generation: 1, BundleHash: "hL", Signature: "sL"},
	}}
	remote := &Vault{SchemaVersion: SchemaVersion, Capabilities: map[string]Capability{
		"bb": {Subject: "tokenR", Status: "active", Generation: 1, BundleHash: "hR", Signature: "sR"},
	}}
	r := Merge(base, local, remote)
	if len(r.Merged.Capabilities) != 2 {
		t.Fatalf("expected 2 capabilities, got %d", len(r.Merged.Capabilities))
	}
	if r.Summary.AddedCapabilities < 2 {
		t.Errorf("expected AddedCapabilities>=2, got %d", r.Summary.AddedCapabilities)
	}
}

func TestMerge_GenerationsTakeMax(t *testing.T) {
	base := &Vault{SchemaVersion: SchemaVersion, Generations: map[string]uint64{"agent": 3}}
	local := &Vault{SchemaVersion: SchemaVersion, Generations: map[string]uint64{"agent": 5}}
	remote := &Vault{SchemaVersion: SchemaVersion, Generations: map[string]uint64{"agent": 7}}
	r := Merge(base, local, remote)
	if r.Merged.Generations["agent"] != 7 {
		t.Fatalf("expected max=7, got %d", r.Merged.Generations["agent"])
	}
}

func TestMerge_SelfNoteNotSpecial(t *testing.T) {
	// The "self" note is an authoring hint from the machine that wrote
	// the entry — it must not be treated as a role during merge.
	base := &Vault{SchemaVersion: SchemaVersion, Admins: map[string]Admin{
		"m1": {Ed25519Pubkey: "P1", AgeRecipient: "R1", Note: "self"},
		"m2": {Ed25519Pubkey: "P2", AgeRecipient: "R2", Note: "joined via invite"},
	}}
	local := &Vault{SchemaVersion: SchemaVersion, Admins: base.Admins}
	remote := &Vault{SchemaVersion: SchemaVersion, Admins: base.Admins}
	r := Merge(base, local, remote)
	if len(r.Merged.Admins) != 2 {
		t.Fatalf("expected both admins to survive an identity merge, got %d", len(r.Merged.Admins))
	}
}
