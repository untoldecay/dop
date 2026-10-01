// v1.13.0-rc12 — protected-credentials enforcement logic shared
// between CLI mutation commands and the daemon-side save guard.
//
// Design (Shape B + daemon revert): the Protected flag + Owner pubkey
// on vault.Integration and vault.Grant are CLI-enforced ("refuse the
// command if session != owner") AND vault-save-enforced ("if a
// non-owner slipped a protected mutation through `dop vault edit`,
// revert the change before writing and log the attempt").
//
// This isn't a cryptographic boundary — any admin can decrypt the
// SOPS vault and edit it outside DOP. It IS a loud, verifiable
// convention: all mutations go through the daemon, the daemon
// enforces + logs, operators get a predictable audit trail.

package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/approval"
	"github.com/fray/dop/internal/audit"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

// requireProtectionOwner refuses the current operation unless the
// active admin session owns the resource. Call this BEFORE any
// mutation that touches a protected integration or grant. Returns
// nil when the resource isn't protected (unrestricted) or when the
// session owns it (allowed).
func requireProtectionOwner(client *admin.Client, resource string, protected bool, owner string) error {
	if !protected {
		return nil
	}
	st, err := client.Status()
	if err != nil {
		return fmt.Errorf("read session: %w", err)
	}
	if !strings.EqualFold(st.AdminPubkey, owner) {
		return fmt.Errorf(
			"%s is protected and owned by another admin (owner=%s…) — only they can modify it",
			resource, short(owner))
	}
	return nil
}

// promptProtectionPassphrase runs the approval-passphrase gate used
// for any mutation on a protected resource. The passphrase is the
// SAME approval passphrase set by `dop admin set-approval` — reuses
// the existing argon2id + rate-limit primitive.
//
// readStdin: if true, read the passphrase from stdin (one line);
// used by the TUI which already handles typing. Else prompt
// interactively from the controlling terminal.
func promptProtectionPassphrase(paths *config.Paths, prompt string, readStdin bool) error {
	phrase, err := readPassphrase(prompt, readStdin)
	if err != nil {
		return fmt.Errorf("read passphrase: %w", err)
	}
	ok, err := approval.Verify(paths, phrase)
	if err != nil {
		return fmt.Errorf("verify passphrase: %w", err)
	}
	if !ok {
		return errors.New("approval passphrase incorrect")
	}
	return nil
}

// logProtectedCreate appends an audit event when an integration or
// grant is marked protected. Non-fatal; audit.Append is best-effort.
func logProtectedCreate(paths *config.Paths, kind, resource, owner string) {
	audit.Append(paths, audit.Event{
		Kind: audit.EventProtectedCreate,
		Extra: map[string]string{
			"resource_kind": kind, // "integration" | "grant"
			"resource":      resource,
			"owner":         owner,
		},
	})
}

// logProtectedTokenIssue tracks when a bearer gets issued containing
// a protected grant. Useful for later forensic correlation.
func logProtectedTokenIssue(paths *config.Paths, subject string, grants []string) {
	audit.Append(paths, audit.Event{
		Kind:    audit.EventProtectedTokenIssue,
		Subject: subject,
		Extra: map[string]string{
			"protected_grants": strings.Join(grants, ","),
		},
	})
}

// enforceProtectedOnSave is the daemon-side revert mechanism Cam
// specifically asked for. Diffs the proposed vault against the
// current on-disk vault — for every Integration or Grant whose
// Protected block (Protected flag OR Owner field OR any
// nested value) was mutated by a session that doesn't own it, the
// change is reverted to the original state and an audit event is
// emitted.
//
// Returns a non-nil error only if the reversion itself failed to
// write; otherwise returns (revertedList, nil) so the caller can
// surface a "N changes reverted" feedback to the operator.
//
// nil `old` means first save (nothing to diff against) — no reverts.
func enforceProtectedOnSave(client *admin.Client, paths *config.Paths, old, next *vault.Vault) ([]string, error) {
	if old == nil || next == nil {
		return nil, nil
	}
	st, err := client.Status()
	if err != nil {
		return nil, fmt.Errorf("session: %w", err)
	}
	actor := st.AdminPubkey
	var reverted []string

	// Pass 1 — integrations
	for key, oldInteg := range old.Integrations {
		newInteg, present := next.Integrations[key]
		// Resource was protected and session is not the owner.
		if oldInteg.Protected && !strings.EqualFold(oldInteg.Owner, actor) {
			if !present {
				// Non-owner tried to delete a protected integration → revert.
				next.Integrations[key] = oldInteg
				reverted = append(reverted, "integration:"+key+" (deletion)")
				audit.Append(paths, audit.Event{
					Kind:    audit.EventProtectedBypassAttempt,
					Subject: actor,
					Extra: map[string]string{
						"resource_kind": "integration",
						"resource":      key,
						"owner":         oldInteg.Owner,
						"operation":     "delete",
					},
				})
				continue
			}
			if !integrationEqual(oldInteg, newInteg) {
				// Non-owner edited a protected integration → revert.
				next.Integrations[key] = oldInteg
				reverted = append(reverted, "integration:"+key)
				audit.Append(paths, audit.Event{
					Kind:    audit.EventProtectedBypassAttempt,
					Subject: actor,
					Extra: map[string]string{
						"resource_kind": "integration",
						"resource":      key,
						"owner":         oldInteg.Owner,
						"operation":     "edit",
					},
				})
			}
		}
	}
	// Non-owner tried to CREATE a new integration under protected (impossible —
	// no owner existed before). But they MAY have flipped Protected=true on a
	// non-protected integration without being the intended owner. Detect: new
	// has Protected but old didn't — require that the session's pubkey equals
	// the newly-claimed Owner (operators must own what they protect).
	for key, newInteg := range next.Integrations {
		oldInteg, present := old.Integrations[key]
		if !newInteg.Protected {
			continue
		}
		if !present {
			// Brand-new protected integration — Owner must be the session.
			if !strings.EqualFold(newInteg.Owner, actor) {
				next.Integrations[key] = vault.Integration{} // reset
				delete(next.Integrations, key)
				reverted = append(reverted, "integration:"+key+" (claimed-owner mismatch)")
				audit.Append(paths, audit.Event{
					Kind:    audit.EventProtectedBypassAttempt,
					Subject: actor,
					Extra: map[string]string{
						"resource_kind": "integration",
						"resource":      key,
						"operation":     "claim-ownership",
					},
				})
			}
			continue
		}
		// Was it already protected? If so pass 1 handled it.
		if oldInteg.Protected {
			continue
		}
		// Became protected now. Owner must be the session.
		if !strings.EqualFold(newInteg.Owner, actor) {
			newInteg.Protected = false
			newInteg.Owner = ""
			next.Integrations[key] = newInteg
			reverted = append(reverted, "integration:"+key+" (protected-flip without owning it)")
			audit.Append(paths, audit.Event{
				Kind:    audit.EventProtectedBypassAttempt,
				Subject: actor,
				Extra: map[string]string{
					"resource_kind": "integration",
					"resource":      key,
					"operation":     "flip-protection",
				},
			})
		}
	}
	// Pass 2 — grants (same rules).
	for key, oldGrant := range old.Grants {
		newGrant, present := next.Grants[key]
		if oldGrant.Protected && !strings.EqualFold(oldGrant.Owner, actor) {
			if !present {
				next.Grants[key] = oldGrant
				reverted = append(reverted, "grant:"+key+" (deletion)")
				audit.Append(paths, audit.Event{
					Kind: audit.EventProtectedBypassAttempt,
					Extra: map[string]string{
						"actor":         actor,
						"resource_kind": "grant",
						"resource":      key,
						"owner":         oldGrant.Owner,
						"operation":     "delete",
					},
				})
				continue
			}
			if !grantEqual(oldGrant, newGrant) {
				next.Grants[key] = oldGrant
				reverted = append(reverted, "grant:"+key)
				audit.Append(paths, audit.Event{
					Kind: audit.EventProtectedBypassAttempt,
					Extra: map[string]string{
						"actor":         actor,
						"resource_kind": "grant",
						"resource":      key,
						"owner":         oldGrant.Owner,
						"operation":     "edit",
					},
				})
			}
		}
	}
	for key, newGrant := range next.Grants {
		oldGrant, present := old.Grants[key]
		if !newGrant.Protected {
			continue
		}
		if !present {
			if !strings.EqualFold(newGrant.Owner, actor) {
				delete(next.Grants, key)
				reverted = append(reverted, "grant:"+key+" (claimed-owner mismatch)")
				audit.Append(paths, audit.Event{
					Kind: audit.EventProtectedBypassAttempt,
					Extra: map[string]string{
						"actor":         actor,
						"resource_kind": "grant",
						"resource":      key,
						"operation":     "claim-ownership",
					},
				})
			}
			continue
		}
		if oldGrant.Protected {
			continue
		}
		if !strings.EqualFold(newGrant.Owner, actor) {
			newGrant.Protected = false
			newGrant.Owner = ""
			next.Grants[key] = newGrant
			reverted = append(reverted, "grant:"+key+" (protected-flip without owning it)")
			audit.Append(paths, audit.Event{
				Kind: audit.EventProtectedBypassAttempt,
				Extra: map[string]string{
					"actor":         actor,
					"resource_kind": "grant",
					"resource":      key,
					"operation":     "flip-protection",
				},
			})
		}
	}
	return reverted, nil
}

// integrationEqual is a value-level diff ignoring the Protected +
// Owner fields (those are checked separately by enforceProtectedOnSave).
func integrationEqual(a, b vault.Integration) bool {
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
		bt, ok := b.Tokens[k]
		if !ok || bt.Value != v.Value || bt.ScopeNote != v.ScopeNote {
			return false
		}
	}
	// Protected flag flip handled by the caller's pass-2 logic.
	if a.Protected != b.Protected {
		return false
	}
	if !strings.EqualFold(a.Owner, b.Owner) {
		return false
	}
	return true
}

func grantEqual(a, b vault.Grant) bool {
	if a.Integration != b.Integration || a.Token != b.Token || a.EnvPrefix != b.EnvPrefix {
		return false
	}
	if !stringSlicesEqual(a.Projects, b.Projects) {
		return false
	}
	if !stringSlicesEqual(a.Tags, b.Tags) {
		return false
	}
	if a.Protected != b.Protected {
		return false
	}
	if !strings.EqualFold(a.Owner, b.Owner) {
		return false
	}
	return true
}

// readPassphrase is defined in admincmd.go — reused here.
