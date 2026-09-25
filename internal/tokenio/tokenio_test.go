package tokenio

import (
	"strings"
	"testing"
)

const fixtureVault = `schema_version: 1

integrations:
  boiler:
    description: "test"
    metadata:
      base_url: "https://boiler.example"
    tokens:
      read:
        value: "blr_ro_xxx"
        scope_note: "read-only"
      write:
        value: "blr_rw_xxx"
        scope_note: "read+write"
      admin:
        value: "blr_ad_xxx"
        scope_note: "admin — DANGEROUS"

grants:
  boiler.read:
    integration: boiler
    token: read
    env_prefix: BOILER
  boiler.write:
    integration: boiler
    token: write
    env_prefix: BOILER
  boiler.admin:
    integration: boiler
    token: admin
    env_prefix: BOILER

auth_tokens:
  tok_existing:
    name: "pre-existing"
    grants: [boiler.read]
`

func TestTokenBearer_ShapeAndUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		b, err := TokenBearer()
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(b, "tok_") {
			t.Fatalf("bearer missing prefix: %q", b)
		}
		if len(b) != 4+24 { // "tok_" + 24 hex
			t.Fatalf("bearer wrong length: %q", b)
		}
		if seen[b] {
			t.Fatalf("bearer collision after %d draws", i)
		}
		seen[b] = true
	}
}

func TestKnownGrants(t *testing.T) {
	root, err := ParseTree([]byte(fixtureVault))
	if err != nil {
		t.Fatal(err)
	}
	known := KnownGrants(root)
	for _, want := range []string{"boiler.read", "boiler.write", "boiler.admin"} {
		if !known[want] {
			t.Fatalf("missing %q in KnownGrants: %v", want, known)
		}
	}
	if known["nope.nope"] {
		t.Fatal("KnownGrants included non-existent grant")
	}
}

func TestSensitiveGrants(t *testing.T) {
	root, err := ParseTree([]byte(fixtureVault))
	if err != nil {
		t.Fatal(err)
	}
	got := SensitiveGrants(root, []string{"boiler.read", "boiler.write", "boiler.admin"})
	// read-only should NOT trigger; write + admin should.
	wantSet := map[string]bool{"boiler.write": true, "boiler.admin": true}
	if len(got) != len(wantSet) {
		t.Fatalf("expected %d sensitive, got %v", len(wantSet), got)
	}
	for _, g := range got {
		if !wantSet[g] {
			t.Fatalf("unexpected sensitive grant %q", g)
		}
	}
	// Empty grant list → empty result.
	if len(SensitiveGrants(root, nil)) != 0 {
		t.Fatal("expected empty sensitive for empty input")
	}
	// Read-only alone → empty.
	if len(SensitiveGrants(root, []string{"boiler.read"})) != 0 {
		t.Fatal("read-only grant should not be sensitive")
	}
}

func TestAddAndListTokens(t *testing.T) {
	root, err := ParseTree([]byte(fixtureVault))
	if err != nil {
		t.Fatal(err)
	}

	err = AddAuthToken(root, "tok_new_1", TokenRecord{
		Name:   "issued-in-test",
		Grants: []string{"boiler.read", "boiler.write"},
		Note:   "test note",
	}, "test@example")
	if err != nil {
		t.Fatal(err)
	}

	list := ListTokens(root)
	if len(list) != 2 {
		t.Fatalf("expected 2 tokens after add, got %d: %v", len(list), list)
	}
	// Sorted by name; "issued-in-test" < "pre-existing"
	if list[0].Name != "issued-in-test" {
		t.Fatalf("expected first name issued-in-test, got %q", list[0].Name)
	}
	if len(list[0].Grants) != 2 || list[0].Grants[0] != "boiler.read" {
		t.Fatalf("grants mangled: %v", list[0].Grants)
	}
	if list[0].CreatedAt == "" {
		t.Fatal("created_at not set")
	}
}

func TestFindByNameAndRemove(t *testing.T) {
	root, err := ParseTree([]byte(fixtureVault))
	if err != nil {
		t.Fatal(err)
	}
	_ = AddAuthToken(root, "tok_target", TokenRecord{Name: "target", Grants: []string{"boiler.read"}}, "")

	hits := FindByName(root, "target")
	if len(hits) != 1 || hits[0] != "tok_target" {
		t.Fatalf("FindByName(target): expected [tok_target], got %v", hits)
	}
	hits = FindByName(root, "tok_targ") // prefix match
	if len(hits) != 1 || hits[0] != "tok_target" {
		t.Fatalf("FindByName(prefix): expected [tok_target], got %v", hits)
	}

	if !RemoveAuthToken(root, "tok_target") {
		t.Fatal("RemoveAuthToken returned false")
	}
	if len(FindByName(root, "target")) != 0 {
		t.Fatal("token still findable after remove")
	}
}

func TestRoundTrip_PlaintextEmit(t *testing.T) {
	// Prove that a mutation round-trips through parse → mutate → emit → parse
	// without losing structure.
	root, err := ParseTree([]byte(fixtureVault))
	if err != nil {
		t.Fatal(err)
	}
	bearer, _ := TokenBearer()
	if err := AddAuthToken(root, bearer, TokenRecord{
		Name:   "roundtrip",
		Grants: []string{"boiler.read"},
	}, ""); err != nil {
		t.Fatal(err)
	}
	out, err := EmitTree(root)
	if err != nil {
		t.Fatal(err)
	}
	root2, err := ParseTree(out)
	if err != nil {
		t.Fatalf("emitted YAML does not re-parse: %v\n%s", err, out)
	}
	list := ListTokens(root2)
	if len(list) != 2 {
		t.Fatalf("expected 2 tokens after roundtrip, got %d", len(list))
	}
}
