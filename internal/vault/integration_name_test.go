package vault

import "testing"

func TestNormalizeIntegrationName(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		// rc6c: case is preserved. Cam wants "SvcRename" to stay "SvcRename".
		// Spaces still collapse to hyphens, non-alnum still collapses.
		{"Boiler Pensieve", "Boiler-Pensieve"},
		{"Notion", "Notion"},
		{"notion", "notion"},
		{"SvcRename", "SvcRename"},
		// Hyphens and dots preserved for display legibility.
		{"my-service.v2", "my-service.v2"},
		// Collapsing runs of non-alnum, case preserved.
		{"  Weird  / Name  ", "Weird-Name"},
		// Leading / trailing non-alnum trimmed.
		{"--foo--", "foo"},
		// All-non-alnum → empty (caller validates).
		{"///", ""},
		// Numbers stay.
		{"github2", "github2"},
	}
	for _, c := range cases {
		if got := NormalizeIntegrationName(c.in); got != c.want {
			t.Errorf("NormalizeIntegrationName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFindIntegrationKey(t *testing.T) {
	v := &Vault{
		Integrations: map[string]Integration{
			// Legacy pre-rc4 unnormalized key — must still be findable.
			"Boiler Pensieve": {},
			// Post-rc4 normalized key.
			"notion": {},
		},
	}
	// Literal match on a legacy key.
	if k, ok := v.FindIntegrationKey("Boiler Pensieve"); !ok || k != "Boiler Pensieve" {
		t.Errorf("literal legacy lookup failed: %q %v", k, ok)
	}
	// Case-insensitive match against legacy key.
	if k, ok := v.FindIntegrationKey("boiler pensieve"); !ok || k != "Boiler Pensieve" {
		t.Errorf("case-insensitive legacy lookup failed: %q %v", k, ok)
	}
	// Normalized form resolves to legacy entry (so grants referencing
	// the normalized name still find the stored legacy integration).
	if k, ok := v.FindIntegrationKey("boiler-pensieve"); !ok || k != "Boiler Pensieve" {
		t.Errorf("normalized → legacy lookup failed: %q %v", k, ok)
	}
	// Normalized exact match.
	if k, ok := v.FindIntegrationKey("notion"); !ok || k != "notion" {
		t.Errorf("normalized exact lookup failed: %q %v", k, ok)
	}
	// Variant case → normalized match.
	if k, ok := v.FindIntegrationKey("Notion"); !ok || k != "notion" {
		t.Errorf("Notion → notion failed: %q %v", k, ok)
	}
	// Not found → returns normalized form (case preserved) for creation.
	k, ok := v.FindIntegrationKey("GitHub Enterprise")
	if ok {
		t.Errorf("expected not found, got %q", k)
	}
	if k != "GitHub-Enterprise" {
		t.Errorf("missing-key fallback = %q, want \"GitHub-Enterprise\"", k)
	}
}

func TestGrant_EffectivePrefix_SanitizesExplicitOverride(t *testing.T) {
	// Pre-rc4 regression: an explicit --env-prefix with spaces was
	// returned verbatim, producing invalid env var names at runtime.
	g := Grant{
		Integration: "notion",
		Token:       "read",
		EnvPrefix:   "BOILER PENSIEVE", // spaces!
	}
	got := g.EffectivePrefix()
	if got != "BOILER_PENSIEVE" {
		t.Errorf("EffectivePrefix with spaces: got %q, want %q", got, "BOILER_PENSIEVE")
	}
}
