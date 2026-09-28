package views

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestInjectIntegration_MinimalVault(t *testing.T) {
	// Empty-ish vault → add one integration with two tokens
	src := "schema_version: 1\n"
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatal(err)
	}

	f := addIntFields{
		name:        "notion",
		description: "Fray Notion",
		baseURL:     "https://api.notion.com/v1",
		envPrefix:   "NOTION",
	}
	tokens := []tokenDraft{
		{name: "read", value: "ntn_ro_test", scopeNote: "read-only"},
		{name: "write", value: "ntn_rw_test", scopeNote: "read+write"},
	}
	injectIntegration(&doc, f, tokens)

	// Round-trip: emit, re-parse, then assert structure.
	var buf strings.Builder
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	// Must contain the integration + both tokens with values.
	for _, want := range []string{
		"integrations:",
		"notion:",
		"description: Fray Notion",
		"base_url: https://api.notion.com/v1",
		"value: ntn_ro_test",
		"value: ntn_rw_test",
		"scope_note: read-only",
		"scope_note: read+write",
		"grants:",
		"notion.read:",
		"notion.write:",
		"env_prefix: NOTION",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("emitted YAML missing %q:\n%s", want, out)
		}
	}
}

func TestInjectIntegration_ReplacesExisting(t *testing.T) {
	// Existing integration with the same name should be overwritten,
	// not duplicated.
	src := `schema_version: 1

integrations:
  notion:
    description: OLD
    tokens:
      read:
        value: OLD_VALUE
        scope_note: read-only

grants:
  notion.read:
    integration: notion
    token: read
    env_prefix: NOTION
`
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(src), &doc); err != nil {
		t.Fatal(err)
	}
	injectIntegration(&doc, addIntFields{
		name:        "notion",
		description: "NEW",
		baseURL:     "https://api.notion.com/v1",
		envPrefix:   "NOTION",
	}, []tokenDraft{
		{name: "read", value: "NEW_VALUE", scopeNote: "read-only"},
	})

	var buf strings.Builder
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	_ = enc.Encode(&doc)
	out := buf.String()

	if strings.Contains(out, "OLD_VALUE") {
		t.Fatalf("old value not replaced:\n%s", out)
	}
	if strings.Contains(out, "OLD") {
		t.Fatalf("old description not replaced:\n%s", out)
	}
	if !strings.Contains(out, "NEW_VALUE") {
		t.Fatalf("new value missing:\n%s", out)
	}
	// The grants block should stay intact, not duplicated.
	if strings.Count(out, "notion.read:") != 1 {
		t.Fatalf("grants block duplicated:\n%s", out)
	}
}

func TestInjectIntegration_DefaultsEnvPrefix(t *testing.T) {
	// envPrefix left blank should fall back to uppercased integration name.
	src := "schema_version: 1\n"
	var doc yaml.Node
	_ = yaml.Unmarshal([]byte(src), &doc)
	injectIntegration(&doc, addIntFields{
		name: "boiler",
	}, []tokenDraft{
		{name: "read", value: "x", scopeNote: "read-only"},
	})
	var buf strings.Builder
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	_ = enc.Encode(&doc)
	if !strings.Contains(buf.String(), "env_prefix: BOILER") {
		t.Fatalf("expected env_prefix BOILER, got:\n%s", buf.String())
	}
}
