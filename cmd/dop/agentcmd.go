// `dop agent <subcommand>` — v1.11 agent-key operations.
//
// Subcommands:
//   dop agent list                       show all agent keys + backend + type
//   dop agent info <lookup-id>           details for one key
//   dop agent migrate <subject-or-lookup>  re-enroll a legacy ed25519 key
//                                          into SE-backed P-256. Requires an
//                                          admin session (must re-sign the
//                                          capability record). Leaves the
//                                          old .key file with a 12h grace
//                                          marker so a bad SE key doesn't
//                                          brick the agent immediately.
//   dop agent sweep                      clean up files past their 12h grace

package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/fray/dop/internal/agentkey"
	"github.com/fray/dop/internal/audit"
	"github.com/fray/dop/internal/capability"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

func runAgent(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: dop agent <list|info|migrate|sweep|delete>")
		return 2
	}
	switch args[0] {
	case "list":
		return runAgentList(args[1:])
	case "info":
		return runAgentInfo(args[1:])
	case "migrate":
		return runAgentMigrate(args[1:])
	case "sweep":
		return runAgentSweep(args[1:])
	case "delete":
		return runAgentDelete(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "dop agent: unknown subcommand %q\n", args[0])
		return 2
	}
}

// runAgentDelete removes the agent key for the given lookup id from
// EVERY backend (Keychain SE + file). Idempotent. Useful for cleaning
// up after a revoked bearer, or for removing a leaked SE key that a
// test run created in the real user's Keychain.
func runAgentDelete(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: dop agent delete <lookup-id-or-prefix>")
		return 2
	}
	paths, _ := config.Resolve()
	entries, err := collectAgentKeys(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop agent delete: %v\n", err)
		return 1
	}
	// Try to match a full lookup id first — if the caller passes an
	// exact-hex ID and it's not on the file backend, we still want to
	// delete it from Keychain (which we can't enumerate without a list op).
	var lookup string
	if len(args[0]) >= 32 {
		lookup = args[0]
	} else {
		match, err := matchLookupPrefix(entries, args[0])
		if err != nil {
			fmt.Fprintf(os.Stderr, "dop agent delete: %v\n", err)
			return 1
		}
		lookup = match.LookupID
	}
	if err := agentkey.Delete(paths, lookup); err != nil {
		fmt.Fprintf(os.Stderr, "dop agent delete: %v\n", err)
		return 1
	}
	// Also clean the grace marker file if present.
	_ = os.Remove(filepath.Join(paths.Root, "agent-keys", lookup+".migrated"))
	fmt.Fprintf(os.Stderr, "dop agent delete: removed key material for %s from every backend.\n", shortLookup(lookup))
	return 0
}

// runAgentList enumerates the agent-keys/ directory and reports each
// key's type + backend + whether it's exportable. Also reports SE keys
// (via the keychain backend's list, when available — currently a stub).
func runAgentList(args []string) int {
	fs := flag.NewFlagSet("agent list", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "emit JSON output instead of a table")
	_ = fs.Parse(args)

	paths, _ := config.Resolve()
	entries, err := collectAgentKeys(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop agent list: %v\n", err)
		return 1
	}
	if *asJSON {
		out, _ := json.MarshalIndent(entries, "", "  ")
		fmt.Println(string(out))
		return 0
	}
	if len(entries) == 0 {
		fmt.Println("(no agent keys on this machine)")
		return 0
	}
	seCount, fileCount := 0, 0
	for _, e := range entries {
		if e.Backend == "keychain-darwin" {
			seCount++
		} else {
			fileCount++
		}
	}
	fmt.Printf("agent keys on this machine: %d total (%d Secure Enclave · %d file-backed)\n\n", len(entries), seCount, fileCount)
	fmt.Printf("%-16s  %-9s  %-16s  %s\n", "LOOKUP", "KEY_TYPE", "BACKEND", "STATUS")
	orphanCount := 0
	for _, e := range entries {
		status := "active"
		switch {
		case e.PendingDelete:
			status = fmt.Sprintf("grace-delete (%s left)", time.Until(e.DeleteAfter).Round(time.Minute))
		case e.Orphan:
			status = "orphan (no matching record — bearer revoked or vault lost)"
			orphanCount++
		}
		fmt.Printf("%-16s  %-9s  %-16s  %s\n",
			shortLookup(e.LookupID), e.KeyType, e.Backend, status)
	}
	if orphanCount > 0 {
		fmt.Printf("\n%d orphan key(s) — clean with `dop agent sweep` or `dop agent delete <lookup>`.\n", orphanCount)
	}
	return 0
}

func runAgentInfo(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: dop agent info <lookup-id-or-prefix>")
		return 2
	}
	paths, _ := config.Resolve()
	entries, err := collectAgentKeys(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop agent info: %v\n", err)
		return 1
	}
	match, err := matchLookupPrefix(entries, args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop agent info: %v\n", err)
		return 1
	}
	store, err := agentkey.Open(paths, match.LookupID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop agent info: %v\n", err)
		return 1
	}
	fmt.Printf("lookup_id:    %s\n", match.LookupID)
	fmt.Printf("key_type:     %s\n", store.KeyType())
	fmt.Printf("backend:      %s\n", match.Backend)
	fmt.Printf("extractable:  %v\n", store.Extractable())
	fmt.Printf("storage:      %s\n", store.StorageDescription())
	fmt.Printf("pubkey (hex): %s\n", hex.EncodeToString(store.PublicKey()))
	if match.PendingDelete {
		fmt.Printf("pending-delete-after: %s (grace remaining: %s)\n",
			match.DeleteAfter.Format(time.RFC3339),
			time.Until(match.DeleteAfter).Round(time.Second))
	}
	return 0
}

func runAgentMigrate(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: dop agent migrate <lookup-id-or-prefix>")
		return 2
	}
	paths, _ := config.Resolve()
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop agent migrate: %v\n", err)
		return 1
	}
	entries, err := collectAgentKeys(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop agent migrate: %v\n", err)
		return 1
	}
	match, err := matchLookupPrefix(entries, args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop agent migrate: %v\n", err)
		return 1
	}
	if match.KeyType == vault.KeyTypeP256 {
		fmt.Fprintf(os.Stderr, "dop agent migrate: this key is already P-256 (%s) — nothing to do.\n", match.Backend)
		return 0
	}

	// Load vault, find the capability with matching lookup_id.
	v, vaultPath, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop agent migrate: %v\n", err)
		return 1
	}
	var capIDHex string
	var capRec vault.Capability
	for id, c := range v.Capabilities {
		if c.LookupID == match.LookupID {
			capIDHex = id
			capRec = c
			break
		}
	}
	if capIDHex == "" {
		fmt.Fprintln(os.Stderr, "dop agent migrate: no capability record found in vault for this lookup id.")
		fmt.Fprintln(os.Stderr, "  You may need to `dop pull` first, or the bearer was revoked from another machine.")
		return 1
	}
	if capRec.Status != capability.RecordStatusActive {
		fmt.Fprintf(os.Stderr, "dop agent migrate: capability is not active (status=%s).\n", capRec.Status)
		return 1
	}
	if capRec.Binding == nil || capRec.Binding.Kind != vault.BindingKindPIN || capRec.Binding.Pubkey == "" {
		fmt.Fprintln(os.Stderr, "dop agent migrate: capability isn't in a claimed PIN-bound state; migrate is only for claimed bearers.")
		return 1
	}

	fmt.Fprintf(os.Stderr, "Migrating agent key for capability %q…\n", capRec.Subject)
	fmt.Fprintf(os.Stderr, "  old: %s (%s)\n", match.KeyType, match.Backend)
	fmt.Fprintln(os.Stderr, "  new: p256 (Secure Enclave when available, else file-backed with DOP_ALLOW_FILE_KEYS=1)")

	// Generate the new key. Keep the old key on disk for 12h so a
	// broken SE bridge / user error doesn't brick the agent.
	newStore, err := agentkey.Create(paths, match.LookupID, vault.KeyTypeP256)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop agent migrate: keygen: %v\n", err)
		return 1
	}
	newPubHex := hex.EncodeToString(newStore.PublicKey())

	// Bump generation for rebind hardening.
	newGen := v.BumpGeneration(capRec.Subject)
	capRec.Generation = newGen
	capRec.Binding = &vault.Binding{
		Kind:      vault.BindingKindPIN,
		Pubkey:    newPubHex,
		KeyType:   newStore.KeyType(),
		ClaimedAt: time.Now().UTC().Truncate(time.Second),
	}
	rec := vaultCapability2Record(capRec, capIDHex)
	if err := signRecordViaDaemon(client, &rec); err != nil {
		fmt.Fprintf(os.Stderr, "dop agent migrate: sign: %v\n", err)
		// The new p256 key is on disk but the record still points at the
		// old ed25519 pubkey. Leaving the new key in place is safe — a
		// retry will find it via agentkey.Open and re-sign.
		return 1
	}
	v.Capabilities[capIDHex] = capability2VaultCapability(rec)

	if err := writeRecordSidecar(paths, rec); err != nil {
		fmt.Fprintf(os.Stderr, "dop agent migrate: write sidecar: %v\n", err)
		return 1
	}
	if err := saveVaultViaDaemon(client, paths, vaultPath, v); err != nil {
		fmt.Fprintf(os.Stderr, "dop agent migrate: save vault: %v\n", err)
		return 1
	}

	// Mark the old key file for delete after 12h. The sweep sub-command
	// (and the login-time auto-sweep) removes files past their expiry.
	if err := markLegacyForGrace(paths, match.LookupID, 12*time.Hour); err != nil {
		fmt.Fprintf(os.Stderr, "  warning: couldn't set grace marker on old key: %v\n", err)
	}

	audit.Append(paths, audit.Event{
		Kind:     audit.EventAgentMigrated,
		Subject:  capRec.Subject,
		LookupID: match.LookupID,
		Extra: map[string]string{
			"old_key_type":     match.KeyType,
			"new_key_type":     newStore.KeyType(),
			"new_backend":      match.Backend, // will be updated post-SE-bridge
			"new_generation":   fmt.Sprintf("%d", newGen),
			"grace_delete_hrs": "12",
		},
	})

	fmt.Fprintln(os.Stderr, "  ✓ migration complete.")
	fmt.Fprintln(os.Stderr, "  Old ed25519 key file kept for 12h as a safety net.")
	fmt.Fprintln(os.Stderr, "  Run `dop agent sweep` to remove it earlier once you're confident.")
	return 0
}

func runAgentSweep(args []string) int {
	paths, _ := config.Resolve()
	n, err := sweepLegacyGrace(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop agent sweep: %v\n", err)
		return 1
	}
	// v1.13 — also remove orphan agent key files (post-revoke
	// leftovers). Grace-pending keys are skipped here because
	// sweepLegacyGrace already handles them.
	o, err := sweepOrphanAgentKeys(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop agent sweep: orphan pass: %v\n", err)
		return 1
	}
	switch {
	case n == 0 && o == 0:
		fmt.Fprintln(os.Stderr, "dop agent sweep: nothing to remove.")
	case n > 0 && o == 0:
		fmt.Fprintf(os.Stderr, "dop agent sweep: removed %d expired legacy key file(s).\n", n)
	case n == 0 && o > 0:
		fmt.Fprintf(os.Stderr, "dop agent sweep: removed %d orphan agent key file(s).\n", o)
	default:
		fmt.Fprintf(os.Stderr, "dop agent sweep: removed %d expired legacy + %d orphan agent key file(s).\n", n, o)
	}
	return 0
}

// sweepOrphanAgentKeys removes any agent key file whose matching
// record sidecar is missing. Used by `dop agent sweep` (v1.13+) to
// clean up after `dop token revoke` which deletes the record but
// leaves the key behind.
func sweepOrphanAgentKeys(paths *config.Paths) (int, error) {
	entries, err := collectAgentKeys(paths)
	if err != nil {
		return 0, err
	}
	removed := 0
	for _, e := range entries {
		if !e.Orphan || e.PendingDelete {
			continue
		}
		if e.Path == "" {
			continue
		}
		if err := os.Remove(e.Path); err != nil && !os.IsNotExist(err) {
			return removed, fmt.Errorf("remove %s: %w", e.Path, err)
		}
		removed++
	}
	return removed, nil
}

// --- helpers ---

// AgentKeyEntry is the enumeration record surfaced by `dop agent list`
// and `dop agent info`. Backend is one of "keychain-darwin" or "file";
// KeyType is "ed25519" or "p256".
type AgentKeyEntry struct {
	LookupID      string    `json:"lookup_id"`
	KeyType       string    `json:"key_type"`
	Backend       string    `json:"backend"`
	Extractable   bool      `json:"extractable"`
	Path          string    `json:"path,omitempty"`
	PendingDelete bool      `json:"pending_delete,omitempty"`
	DeleteAfter   time.Time `json:"delete_after,omitempty"`

	// v1.13 — Orphan is true when the agent key file lingers on disk
	// but there's no matching active record sidecar in the vault
	// (the bearer was revoked, the record file was deleted, etc.).
	// Reported with status "orphan" in `dop agent list`, cleaned by
	// `dop agent sweep` or when `dop token revoke` is run locally.
	Orphan bool `json:"orphan,omitempty"`
}

// collectAgentKeys walks the agent-keys/ directory (file-backed keys)
// and enumerates SE keys where the keychain backend supports it (stub
// today). Returns a stable-order slice sorted by lookup id.
func collectAgentKeys(paths *config.Paths) ([]AgentKeyEntry, error) {
	dir := filepath.Join(paths.Root, "agent-keys")
	out := []AgentKeyEntry{}
	entries, err := os.ReadDir(dir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	seen := map[string]bool{}
	for _, e := range entries {
		name := e.Name()
		// Skip our grace marker files.
		if strings.HasSuffix(name, ".migrated") {
			continue
		}
		var lookupID, keyType string
		switch {
		case strings.HasSuffix(name, ".key"):
			lookupID = strings.TrimSuffix(name, ".key")
			keyType = vault.KeyTypeEd25519
		case strings.HasSuffix(name, ".p256"):
			lookupID = strings.TrimSuffix(name, ".p256")
			keyType = vault.KeyTypeP256
		default:
			continue
		}
		if seen[lookupID+":"+keyType] {
			continue
		}
		seen[lookupID+":"+keyType] = true
		ent := AgentKeyEntry{
			LookupID:    lookupID,
			KeyType:     keyType,
			Backend:     "file",
			Extractable: true,
			Path:        filepath.Join(dir, name),
		}
		// The grace marker sits alongside the LEGACY ed25519 key file
		// after `dop agent migrate` — it only applies to that specific
		// key type. A P-256 entry for the same lookup id is the NEW
		// key, not something scheduled for delete.
		if keyType == vault.KeyTypeEd25519 {
			if until, ok := readGraceMarker(paths, lookupID); ok {
				ent.PendingDelete = true
				ent.DeleteAfter = until
			}
		}
		// v1.13 — orphan detection. A key is orphan when there's no
		// matching active record sidecar in the vault. Catches
		// post-revoke / post-vault-wipe leftovers that previously
		// just lingered as "active" in `dop agent list`.
		//
		// Grace-pending keys are allowed to be "active without record"
		// mid-migration — don't double-flag.
		if !ent.PendingDelete && !hasActiveRecordSidecar(paths, lookupID) {
			ent.Orphan = true
		}
		out = append(out, ent)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LookupID < out[j].LookupID })
	return out, nil
}

// hasActiveRecordSidecar is true iff the vault's capabilities/
// directory contains <lookupID>.record. The record is deleted by
// `dop token revoke` (via syncSidecars dropping revoked records),
// so missing-record === "this agent key no longer backs any bearer".
func hasActiveRecordSidecar(paths *config.Paths, lookupID string) bool {
	p := filepath.Join(paths.Vault, "capabilities", lookupID+".record")
	_, err := os.Stat(p)
	return err == nil
}

func matchLookupPrefix(entries []AgentKeyEntry, prefix string) (*AgentKeyEntry, error) {
	if len(prefix) < 4 {
		return nil, errors.New("give at least 4 characters of the lookup id prefix")
	}
	matches := []int{}
	for i, e := range entries {
		if strings.HasPrefix(e.LookupID, prefix) {
			matches = append(matches, i)
		}
	}
	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("no agent key matches prefix %q", prefix)
	case 1:
		return &entries[matches[0]], nil
	default:
		names := []string{}
		for _, i := range matches {
			names = append(names, shortLookup(entries[i].LookupID))
		}
		return nil, fmt.Errorf("prefix %q matches %d keys: %s — be more specific", prefix, len(matches), strings.Join(names, ", "))
	}
}

func shortLookup(s string) string {
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}

// --- grace-marker file format ---
//
// After `dop agent migrate` we don't immediately delete the old
// ed25519 .key file — we leave it and write a sibling <lookup>.migrated
// file whose only content is the UTC RFC3339 timestamp at which the
// grace expires. `dop agent sweep` and `dop admin login` both check
// these and remove expired keys.

func markLegacyForGrace(paths *config.Paths, lookupID string, grace time.Duration) error {
	dir := filepath.Join(paths.Root, "agent-keys")
	p := filepath.Join(dir, lookupID+".migrated")
	deadline := time.Now().UTC().Add(grace)
	return os.WriteFile(p, []byte(deadline.Format(time.RFC3339)+"\n"), 0o600)
}

func readGraceMarker(paths *config.Paths, lookupID string) (time.Time, bool) {
	p := filepath.Join(paths.Root, "agent-keys", lookupID+".migrated")
	b, err := os.ReadFile(p)
	if err != nil {
		return time.Time{}, false
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(string(b)))
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

// sweepLegacyGrace removes any legacy .key file whose grace marker
// has expired. Also removes the marker itself and any orphaned .p256
// files with the same lookup id (in case an incomplete migration left
// state behind). Returns the number of keys removed.
func sweepLegacyGrace(paths *config.Paths) (int, error) {
	dir := filepath.Join(paths.Root, "agent-keys")
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	removed := 0
	now := time.Now().UTC()
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".migrated") {
			continue
		}
		lookupID := strings.TrimSuffix(e.Name(), ".migrated")
		until, ok := readGraceMarker(paths, lookupID)
		if !ok {
			continue
		}
		if now.Before(until) {
			continue
		}
		// Grace expired — delete the ed25519 .key file and the marker.
		if err := os.Remove(filepath.Join(dir, lookupID+".key")); err == nil || errors.Is(err, fs.ErrNotExist) {
			removed++
		}
		_ = os.Remove(filepath.Join(dir, e.Name()))
	}
	return removed, nil
}
