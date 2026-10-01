// v1.13.0-rc8 — cascade logic shared between `dop grant remove`
// (removes one or more grants) and the TUI integration-removal
// drill-down flow (removes a service's tokens, which in turn removes
// every grant that referenced those tokens).
//
// Semantics for each affected active capability:
//
//   * Grants are dropped from c.Grants in-place.
//
//   * Generation is bumped.
//
//   * P-256-bound bearers: EnvWrapped is resealed (same code path as
//     `dop token reseal` / add-grant / remove-grant). Agent's next
//     `dop exec` sees the narrowed env automatically — the live-add
//     work from v1.12 symmetrically covers live-removal.
//
//   * Ed25519-bound bearers: the bundle env is bearer-encrypted and
//     can't be rewritten without the bearer, so the stale credential
//     stays visible to the agent until the next re-issue. By default
//     this surfaces as a warning per bearer; with
//     forceRevokeEd25519=true the record is marked revoked.
//
//   * A capability left with ZERO remaining grants is marked
//     revoked unconditionally — a bearer with no grants is useless
//     and would be confusing to leave hanging.
//
// The caller is responsible for actually deleting the grant from
// v.Grants and saving the vault.

package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/capability"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

// cascadeResult carries the per-bearer outcomes from a cascade so the
// caller can build an informative summary line (or a confirmation
// preview in the TUI).
type cascadeResult struct {
	Resealed       []string // capID — grants trimmed, EnvWrapped refreshed
	Ed25519Stale   []string // subject — bundle env stale, warn-only
	Ed25519Revoked []string // subject — bundle env stale, --force-revoke-ed25519 flipped to revoked
	FullyEmptied   []string // subject — zero grants left; marked revoked
}

// summary renders a human-readable trailer for the cascade result,
// to be appended after the main "removed X" message.
func (r cascadeResult) summary() string {
	parts := []string{}
	if n := len(r.Resealed); n > 0 {
		parts = append(parts, fmt.Sprintf("%d bearer(s) resealed", n))
	}
	if n := len(r.Ed25519Stale); n > 0 {
		parts = append(parts, fmt.Sprintf("%d ed25519 bearer(s) now stale (env still in bundle; use --force-revoke-ed25519 to revoke): %s",
			n, strings.Join(r.Ed25519Stale, ", ")))
	}
	if n := len(r.Ed25519Revoked); n > 0 {
		parts = append(parts, fmt.Sprintf("%d ed25519 bearer(s) revoked: %s",
			n, strings.Join(r.Ed25519Revoked, ", ")))
	}
	if n := len(r.FullyEmptied); n > 0 {
		parts = append(parts, fmt.Sprintf("%d bearer(s) left with no grants → revoked: %s",
			n, strings.Join(r.FullyEmptied, ", ")))
	}
	if len(parts) == 0 {
		return ""
	}
	return " · " + strings.Join(parts, " · ")
}

// isGrantInSet is a tiny helper that avoids pulling in a slice-set
// dep for a hot inner loop.
func isGrantInSet(s string, set map[string]bool) bool { return set[s] }

// cascadeGrantRemoval mutates every active capability in v so that
// grants in removedGrants are no longer referenced. For P-256 bearers
// it also updates each record's EnvWrapped payload and re-signs the
// record (via the daemon). Returns a cascadeResult describing what
// changed.
//
// The grant map entries are NOT deleted — caller does that after
// calling cascadeGrantRemoval, so the preview path can call this
// speculatively on a cloned vault without side effects on the real
// grant map.
func cascadeGrantRemoval(
	client *admin.Client,
	paths *config.Paths,
	v *vault.Vault,
	removedGrants []string,
	forceRevokeEd25519 bool,
) (cascadeResult, error) {
	removed := map[string]bool{}
	for _, g := range removedGrants {
		removed[g] = true
	}
	var out cascadeResult
	for capID, c := range v.Capabilities {
		if c.Status != capability.RecordStatusActive {
			continue
		}
		// Does this cap reference any of the removed grants?
		touched := false
		for _, g := range c.Grants {
			if isGrantInSet(g, removed) {
				touched = true
				break
			}
		}
		if !touched {
			continue
		}
		// Trim removed grants out of c.Grants.
		kept := c.Grants[:0]
		for _, g := range c.Grants {
			if !isGrantInSet(g, removed) {
				kept = append(kept, g)
			}
		}
		c.Grants = append([]string(nil), kept...) // defensive copy
		c.Generation = v.BumpGeneration(c.Subject)

		// Zero-grant bearer → revoke outright.
		if len(c.Grants) == 0 {
			c.Status = capability.RecordStatusRevoked
			out.FullyEmptied = append(out.FullyEmptied, c.Subject)
			rec := vaultCapability2Record(c, capID)
			if err := signRecordViaDaemon(client, &rec); err != nil {
				return out, fmt.Errorf("sign revoke %s: %w", c.LookupID, err)
			}
			v.Capabilities[capID] = capability2VaultCapability(rec)
			// Clean the on-disk sidecar + bundle.
			_ = os.Remove(paths.Vault + "/capabilities/" + c.LookupID + ".bundle")
			_ = os.Remove(paths.Vault + "/capabilities/" + c.LookupID + ".record")
			continue
		}

		// What kind of binding do we have?
		keyType := vault.KeyTypeEd25519
		if c.Binding != nil && c.Binding.KeyType != "" {
			keyType = c.Binding.KeyType
		}

		switch keyType {
		case vault.KeyTypeP256:
			// Reseal EnvWrapped from the narrowed grants.
			rec := vaultCapability2Record(c, capID)
			wrapped, err := sealEnvWrapped(v, &rec)
			if err != nil {
				return out, fmt.Errorf("reseal %s: %w", c.LookupID, err)
			}
			rec.EnvWrapped = wrapped
			if err := signRecordViaDaemon(client, &rec); err != nil {
				return out, fmt.Errorf("sign %s: %w", c.LookupID, err)
			}
			v.Capabilities[capID] = capability2VaultCapability(rec)
			if err := writeRecordSidecar(paths, rec); err != nil {
				return out, fmt.Errorf("write sidecar %s: %w", c.LookupID, err)
			}
			out.Resealed = append(out.Resealed, capID[:12])

		case vault.KeyTypeEd25519:
			if forceRevokeEd25519 {
				c.Status = capability.RecordStatusRevoked
				rec := vaultCapability2Record(c, capID)
				if err := signRecordViaDaemon(client, &rec); err != nil {
					return out, fmt.Errorf("sign ed25519 revoke %s: %w", c.LookupID, err)
				}
				v.Capabilities[capID] = capability2VaultCapability(rec)
				_ = os.Remove(paths.Vault + "/capabilities/" + c.LookupID + ".bundle")
				_ = os.Remove(paths.Vault + "/capabilities/" + c.LookupID + ".record")
				out.Ed25519Revoked = append(out.Ed25519Revoked, c.Subject)
			} else {
				// Still re-sign the record with the trimmed grants
				// list — exec will see the shorter grants on the
				// record, but the bundle env (which is bearer-
				// encrypted) still holds the stale credential.
				rec := vaultCapability2Record(c, capID)
				if err := signRecordViaDaemon(client, &rec); err != nil {
					return out, fmt.Errorf("sign %s: %w", c.LookupID, err)
				}
				v.Capabilities[capID] = capability2VaultCapability(rec)
				if err := writeRecordSidecar(paths, rec); err != nil {
					return out, fmt.Errorf("write sidecar %s: %w", c.LookupID, err)
				}
				out.Ed25519Stale = append(out.Ed25519Stale, c.Subject)
			}
		}
	}
	return out, nil
}

// cascadePreview is a non-mutating variant used by the TUI
// confirmation screen before the operator commits. It computes WHICH
// capabilities would be touched and groups them into the same four
// buckets as cascadeResult, without actually editing records.
func cascadePreview(v *vault.Vault, removedGrants []string) cascadeResult {
	removed := map[string]bool{}
	for _, g := range removedGrants {
		removed[g] = true
	}
	var out cascadeResult
	for capID, c := range v.Capabilities {
		if c.Status != capability.RecordStatusActive {
			continue
		}
		touched := false
		remaining := 0
		for _, g := range c.Grants {
			if isGrantInSet(g, removed) {
				touched = true
			} else {
				remaining++
			}
		}
		if !touched {
			continue
		}
		if remaining == 0 {
			out.FullyEmptied = append(out.FullyEmptied, c.Subject)
			continue
		}
		keyType := vault.KeyTypeEd25519
		if c.Binding != nil && c.Binding.KeyType != "" {
			keyType = c.Binding.KeyType
		}
		switch keyType {
		case vault.KeyTypeP256:
			out.Resealed = append(out.Resealed, capID[:12])
		case vault.KeyTypeEd25519:
			out.Ed25519Stale = append(out.Ed25519Stale, c.Subject)
		}
	}
	return out
}
