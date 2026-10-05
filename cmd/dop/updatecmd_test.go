package main

import "testing"

// TestNeedsConfirmation locks the semver-aware comparison added in
// v1.14.1 so the "pre-release → stable" upgrade path (rc7n-smoke →
// v1.14.0) never gets re-flagged as a downgrade.
func TestNeedsConfirmation(t *testing.T) {
	cases := []struct {
		name string
		from string
		to   string
		want bool
	}{
		{"dev build always upgrades", "dev", "v1.14.0", false},
		{"pre-release to stable same base", "v1.14.0-rc7n-smoke", "v1.14.0", false},
		{"stable to pre-release same base", "v1.14.0", "v1.14.0-rc7-smoke", true},
		{"two pre-releases lex-forward", "v1.14.0-rc6-smoke", "v1.14.0-rc7-smoke", false},
		{"two pre-releases lex-backward", "v1.14.0-rc7-smoke", "v1.14.0-rc6-smoke", true},
		{"same version", "v1.14.0", "v1.14.0", false},
		{"patch upgrade", "v1.14.0", "v1.14.1", false},
		{"patch downgrade", "v1.14.1", "v1.14.0", true},
		{"minor upgrade", "v1.14.0", "v1.15.0", true}, // cross-minor is cross-major-minor
		{"major upgrade", "v1.14.0", "v2.0.0", true},
	}
	for _, c := range cases {
		got := needsConfirmation(c.from, c.to)
		if got != c.want {
			t.Errorf("needsConfirmation(%q → %q) = %v, want %v", c.from, c.to, got, c.want)
		}
	}
}

func TestSplitBaseAndPrerelease(t *testing.T) {
	cases := []struct {
		tag  string
		base string
		pre  string
	}{
		{"v1.14.0", "v1.14.0", ""},
		{"v1.14.0-rc7n-smoke", "v1.14.0", "rc7n-smoke"},
		{"1.14.0-alpha", "1.14.0", "alpha"},
		{"v1.14.0-smoke", "v1.14.0", "smoke"},
	}
	for _, c := range cases {
		b, p := splitBaseAndPrerelease(c.tag)
		if b != c.base || p != c.pre {
			t.Errorf("splitBaseAndPrerelease(%q) = (%q, %q), want (%q, %q)",
				c.tag, b, p, c.base, c.pre)
		}
	}
}
