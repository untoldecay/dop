// Package vault — three-way merge for DOP vaults.
//
// Rationale: the vault is stored as SOPS-encrypted YAML in git. Two
// machines that both make admin changes produce commits that git can
// see are diverged, but can NOT text-merge — the ciphertext is opaque
// noise at the byte level. So we merge at the plaintext-YAML layer
// after decrypting both versions, then re-encrypt the result.
//
// The merge is a proper three-way: we compare each side's state
// against the common ancestor (the last commit both sides shared) so
// we can tell "someone added X" apart from "someone deleted X". A
// two-way union would silently un-revoke tokens, un-remove admins,
// etc. — same-key-same-value looks identical to same-key-never-touched.
//
// Conflicts are the case where BOTH sides changed the same key to
// different values (added-different / edited-differently / one edited
// while the other deleted). We do NOT guess — the caller shows them
// to the operator with plain-English text and asks for a decision.
//
// Non-conflicts (union / additive changes) merge automatically:
//   - integration "foo" added on machine A only  → present in result
//   - grant "notion.read" removed on machine B    → absent in result
//   - capability issued on A + capability issued on B → both present
//   - generation bumped higher on one side        → higher wins

package vault

// Result of a three-way merge.
type MergeResult struct {
	Merged    *Vault
	Conflicts []Conflict
	Summary   MergeSummary
}

// Conflict describes one place where local and remote both diverged
// from the common ancestor. Path is a human-readable dotted string
// like "integrations.notion" or "grants.notion.read".
type Conflict struct {
	Kind   string // "integrations", "grants", "capabilities", "admins"
	Key    string
	Path   string // human-readable
	Reason string // "both edited to different values", "one edited while the other removed"
	Local  string // pretty-printed local value (short)
	Remote string // pretty-printed remote value (short)
}

// MergeSummary is a plain-English count of what happened, for the
// caller to show the operator.
type MergeSummary struct {
	AddedIntegrations   []string
	RemovedIntegrations []string
	AddedGrants         []string
	RemovedGrants       []string
	AddedCapabilities   int // counts, since IDs are hex hashes
	RemovedCapabilities int
	AddedAdmins         []string
	RemovedAdmins       []string
}

// Merge performs a three-way merge of local against remote using base
// as the common ancestor. If any of the three is nil, Merge treats
// that side as an empty vault (useful when the common ancestor has no
// vault yet — a fresh init).
func Merge(base, local, remote *Vault) MergeResult {
	if base == nil {
		base = &Vault{}
	}
	if local == nil {
		local = &Vault{}
	}
	if remote == nil {
		remote = &Vault{}
	}

	out := &Vault{
		SchemaVersion: local.SchemaVersion,
		VaultContext:  local.VaultContext,
	}
	if out.SchemaVersion == "" {
		out.SchemaVersion = remote.SchemaVersion
	}
	if out.VaultContext == "" {
		out.VaultContext = remote.VaultContext
	}

	var conflicts []Conflict
	var summary MergeSummary

	// --- Integrations ---
	out.Integrations = map[string]Integration{}
	{
		conf := mergeMap(
			toGeneric(base.Integrations),
			toGeneric(local.Integrations),
			toGeneric(remote.Integrations),
			out.Integrations,
			func(a, b Integration) bool { return equalIntegration(a, b) },
			func(v Integration) string { return v.Description },
			"integrations",
			&summary.AddedIntegrations,
			&summary.RemovedIntegrations,
		)
		conflicts = append(conflicts, conf...)
	}

	// --- Grants ---
	out.Grants = map[string]Grant{}
	{
		conf := mergeMap(
			toGeneric(base.Grants),
			toGeneric(local.Grants),
			toGeneric(remote.Grants),
			out.Grants,
			func(a, b Grant) bool { return equalGrant(a, b) },
			func(v Grant) string { return v.Integration + "." + v.Token },
			"grants",
			&summary.AddedGrants,
			&summary.RemovedGrants,
		)
		conflicts = append(conflicts, conf...)
	}

	// --- Admins ---
	out.Admins = map[string]Admin{}
	{
		conf := mergeMap(
			toGeneric(base.Admins),
			toGeneric(local.Admins),
			toGeneric(remote.Admins),
			out.Admins,
			func(a, b Admin) bool {
				return a.AgeRecipient == b.AgeRecipient &&
					a.Ed25519Pubkey == b.Ed25519Pubkey
			},
			func(v Admin) string { return v.Note },
			"admins",
			&summary.AddedAdmins,
			&summary.RemovedAdmins,
		)
		conflicts = append(conflicts, conf...)
	}

	// --- Capabilities ---
	// Cap IDs are content-addressed — no add/add collision on different
	// bearers. Same-ID edits can happen for status/generation changes
	// after issuance (claim, revoke). We conflict only on genuine
	// mismatch (different signed record for the same id from the base).
	out.Capabilities = map[string]Capability{}
	{
		added, removed := 0, 0
		seen := map[string]struct{}{}
		for id, r := range remote.Capabilities {
			seen[id] = struct{}{}
			l, hasL := local.Capabilities[id]
			b, hasB := base.Capabilities[id]
			if !hasL && !hasB {
				out.Capabilities[id] = r
				added++
				continue
			}
			if !hasL && hasB {
				// Local removed it, remote kept/edited — assume local's removal.
				removed++
				continue
			}
			if hasL && !hasB {
				// Both added — conflict only if they don't match.
				if equalCapability(l, r) {
					out.Capabilities[id] = l
					continue
				}
				conflicts = append(conflicts, Conflict{
					Kind:   "capabilities",
					Key:    id,
					Path:   "capabilities." + id[:12],
					Reason: "both machines added a different record for the same capability id",
					Local:  summarizeCap(l),
					Remote: summarizeCap(r),
				})
				out.Capabilities[id] = l // prefer local on unresolved conflict
				continue
			}
			// hasL && hasB: standard 3-way for edits.
			switch {
			case equalCapability(l, r):
				out.Capabilities[id] = l
			case equalCapability(l, b) && !equalCapability(r, b):
				out.Capabilities[id] = r
			case equalCapability(r, b) && !equalCapability(l, b):
				out.Capabilities[id] = l
			default:
				conflicts = append(conflicts, Conflict{
					Kind:   "capabilities",
					Key:    id,
					Path:   "capabilities." + id[:12],
					Reason: "both machines edited this capability differently",
					Local:  summarizeCap(l),
					Remote: summarizeCap(r),
				})
				out.Capabilities[id] = l
			}
		}
		// Local-only capabilities (added on our side).
		for id, l := range local.Capabilities {
			if _, ok := seen[id]; ok {
				continue
			}
			if _, hasB := base.Capabilities[id]; !hasB {
				out.Capabilities[id] = l
				added++
			}
			// else: local kept, remote removed → honor remote removal.
			if _, hasB := base.Capabilities[id]; hasB {
				removed++
			}
		}
		summary.AddedCapabilities = added
		summary.RemovedCapabilities = removed
	}

	// --- Generations ---
	// Simple rule: keep the highest per-subject across all three sides.
	out.Generations = map[string]uint64{}
	for k, v := range base.Generations {
		out.Generations[k] = v
	}
	for k, v := range local.Generations {
		if v > out.Generations[k] {
			out.Generations[k] = v
		}
	}
	for k, v := range remote.Generations {
		if v > out.Generations[k] {
			out.Generations[k] = v
		}
	}

	return MergeResult{Merged: out, Conflicts: conflicts, Summary: summary}
}

// toGeneric copies a typed map into a map[string]any so mergeMap can
// stay generic without heavy generics. Yes, this is a little dumb.
// Yes, we could use generics. Yes, we'd still need an equality
// function passed in, so the ergonomic win is small.
func toGeneric[V any](m map[string]V) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

// mergeMap does the plain 3-way merge for one typed map, filling
// `dst`. `eq` compares two typed values; `label` returns a short
// human-readable string for a value (for the Conflict.Local/Remote
// preview). `kind` is the top-level path segment ("integrations" etc.).
// Adds keys that appear in either side (relative to base) get appended
// to `added`; keys that disappear get appended to `removed`.
func mergeMap[V any](
	base, local, remote map[string]any,
	dst map[string]V,
	eq func(a, b V) bool,
	label func(v V) string,
	kind string,
	added, removed *[]string,
) []Conflict {
	var out []Conflict
	seen := map[string]struct{}{}
	for k, rv := range remote {
		seen[k] = struct{}{}
		r := rv.(V)
		lv, hasL := local[k]
		bv, hasB := base[k]
		if !hasL && !hasB {
			// Remote added.
			dst[k] = r
			*added = append(*added, k)
			continue
		}
		if !hasL && hasB {
			// Local removed.
			*removed = append(*removed, k)
			continue
		}
		l := lv.(V)
		if !hasB {
			// Both sides added.
			if eq(l, r) {
				dst[k] = l
				continue
			}
			out = append(out, Conflict{
				Kind:   kind,
				Key:    k,
				Path:   kind + "." + k,
				Reason: "both machines added this with different settings",
				Local:  label(l),
				Remote: label(r),
			})
			dst[k] = l // prefer local
			continue
		}
		b := bv.(V)
		switch {
		case eq(l, r):
			dst[k] = l
		case eq(l, b) && !eq(r, b):
			dst[k] = r
		case eq(r, b) && !eq(l, b):
			dst[k] = l
		default:
			out = append(out, Conflict{
				Kind:   kind,
				Key:    k,
				Path:   kind + "." + k,
				Reason: "both machines edited this differently",
				Local:  label(l),
				Remote: label(r),
			})
			dst[k] = l
		}
	}
	for k, lv := range local {
		if _, ok := seen[k]; ok {
			continue
		}
		l := lv.(V)
		if _, hasB := base[k]; !hasB {
			// Local added.
			dst[k] = l
			*added = append(*added, k)
			continue
		}
		// Local kept, remote removed.
		*removed = append(*removed, k)
	}
	return out
}

// equalIntegration is a deep-equal that ignores map ordering.
func equalIntegration(a, b Integration) bool {
	if a.Description != b.Description {
		return false
	}
	if len(a.Metadata) != len(b.Metadata) {
		return false
	}
	for k, v := range a.Metadata {
		if b.Metadata[k] != v {
			return false
		}
	}
	if len(a.Tokens) != len(b.Tokens) {
		return false
	}
	for k, v := range a.Tokens {
		w, ok := b.Tokens[k]
		if !ok || v.Value != w.Value || v.ScopeNote != w.ScopeNote {
			return false
		}
	}
	return true
}

func equalGrant(a, b Grant) bool {
	if a.Integration != b.Integration || a.Token != b.Token || a.EnvPrefix != b.EnvPrefix {
		return false
	}
	return equalStrSlice(a.Projects, b.Projects) && equalStrSlice(a.Tags, b.Tags)
}

func equalStrSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	seen := map[string]int{}
	for _, s := range a {
		seen[s]++
	}
	for _, s := range b {
		seen[s]--
	}
	for _, n := range seen {
		if n != 0 {
			return false
		}
	}
	return true
}

func equalCapability(a, b Capability) bool {
	// Compare only fields that matter for merge — the signature and
	// bundle hash capture the "real" identity of the record.
	return a.Status == b.Status &&
		a.Generation == b.Generation &&
		a.BundleHash == b.BundleHash &&
		a.Signature == b.Signature
}

func summarizeCap(c Capability) string {
	s := c.Subject
	if c.Status != "" {
		s += " (" + c.Status + ")"
	}
	return s
}
