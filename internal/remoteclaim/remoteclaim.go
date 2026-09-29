// Package remoteclaim models the "agent-driven" claim workflow used
// when the agent host has no admin daemon (CI runners, remote servers).
//
// Flow:
//   1. Agent (no daemon) verifies bearer + PIN locally, generates a
//      new keypair, prepares a new bundle with the pubkey binding, and
//      stores BOTH the new bundle bytes AND a signed metadata file
//      under `<Vault>/pending-remote-claims/`. Commits + pushes.
//   2. Admin (with daemon) pulls, runs `dop approve-remote`, verifies
//      the agent's signature over the request, prompts for the approval
//      passphrase, swaps the pending bundle into `capabilities/`,
//      writes the updated signed record sidecar, saves the vault, and
//      pushes.
//   3. Agent pulls; `dop exec` now succeeds.
//
// Wire artifacts (all inside the vault repo):
//   pending-remote-claims/<lookup_id>.bundle   the new bundle bytes
//   pending-remote-claims/<lookup_id>.json     signed metadata
package remoteclaim

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fray/dop/internal/config"
)

// Request is the JSON metadata the agent commits.
type Request struct {
	LookupID       string    `json:"lookup_id"`
	CapabilityID   string    `json:"capability_id"`
	Subject        string    `json:"subject"`
	Pubkey         string    `json:"pubkey"`     // hex ed25519
	Host           string    `json:"host"`       // agent's os.Hostname()
	RequestedAt    time.Time `json:"requested_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	NewGeneration  uint64    `json:"new_generation"`
	NewBundleHash  string    `json:"new_bundle_hash"`
	Signature      string    `json:"signature"` // hex ed25519 sig by Pubkey over signingPayload()
}

// TTL is how long a remote claim sits in the vault before an admin
// should treat it as stale.
const TTL = 24 * time.Hour

// Dir returns the pending-remote-claims directory under the vault.
func Dir(paths *config.Paths) string {
	return filepath.Join(paths.Vault, "pending-remote-claims")
}

// EnsureDir creates the directory mode 0755 (contents are committed).
func EnsureDir(paths *config.Paths) error {
	return os.MkdirAll(Dir(paths), 0o755)
}

// bundlePath / metaPath return the two per-request files.
func bundlePath(paths *config.Paths, lookupID string) string {
	return filepath.Join(Dir(paths), lookupID+".bundle")
}
func metaPath(paths *config.Paths, lookupID string) string {
	return filepath.Join(Dir(paths), lookupID+".json")
}

// signingPayload returns the deterministic byte sequence the agent
// signs with its NEW private key, proving it holds the pubkey. Signature
// covers everything but the Signature field itself.
func signingPayload(r Request) ([]byte, error) {
	r.Signature = ""
	blob, err := json.Marshal(struct {
		LookupID      string `json:"lookup_id"`
		CapabilityID  string `json:"capability_id"`
		Subject       string `json:"subject"`
		Pubkey        string `json:"pubkey"`
		Host          string `json:"host"`
		RequestedAt   string `json:"requested_at"`
		ExpiresAt     string `json:"expires_at"`
		NewGeneration uint64 `json:"new_generation"`
		NewBundleHash string `json:"new_bundle_hash"`
	}{
		LookupID:      r.LookupID,
		CapabilityID:  r.CapabilityID,
		Subject:       r.Subject,
		Pubkey:        r.Pubkey,
		Host:          r.Host,
		RequestedAt:   r.RequestedAt.UTC().Format(time.RFC3339Nano),
		ExpiresAt:     r.ExpiresAt.UTC().Format(time.RFC3339Nano),
		NewGeneration: r.NewGeneration,
		NewBundleHash: r.NewBundleHash,
	})
	if err != nil {
		return nil, err
	}
	return blob, nil
}

// Sign attaches an ed25519 signature over signingPayload.
func (r *Request) Sign(priv ed25519.PrivateKey) error {
	payload, err := signingPayload(*r)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, payload)
	r.Signature = hex.EncodeToString(sig)
	return nil
}

// Verify checks the request's signature against its own Pubkey (which
// itself must be validated out-of-band by the admin).
func (r Request) Verify() error {
	if r.Signature == "" {
		return errors.New("remote claim: no signature")
	}
	pubBytes, err := hex.DecodeString(r.Pubkey)
	if err != nil {
		return fmt.Errorf("remote claim: bad pubkey hex: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("remote claim: pubkey wrong size %d", len(pubBytes))
	}
	sig, err := hex.DecodeString(r.Signature)
	if err != nil {
		return fmt.Errorf("remote claim: bad sig hex: %w", err)
	}
	payload, err := signingPayload(r)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pubBytes, payload, sig) {
		return errors.New("remote claim: signature does not verify")
	}
	return nil
}

// Write writes the bundle bytes AND the metadata file atomically.
func Write(paths *config.Paths, r Request, bundleBytes []byte) error {
	if err := EnsureDir(paths); err != nil {
		return err
	}
	if err := os.WriteFile(bundlePath(paths, r.LookupID), bundleBytes, 0o644); err != nil {
		return err
	}
	blob, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	blob = append(blob, '\n')
	tmp := metaPath(paths, r.LookupID) + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, metaPath(paths, r.LookupID))
}

// ReadOne loads the metadata + bundle for one lookup_id.
func ReadOne(paths *config.Paths, lookupID string) (*Request, []byte, error) {
	blob, err := os.ReadFile(metaPath(paths, lookupID))
	if err != nil {
		return nil, nil, err
	}
	var r Request
	if err := json.Unmarshal(blob, &r); err != nil {
		return nil, nil, err
	}
	bundle, err := os.ReadFile(bundlePath(paths, r.LookupID))
	if err != nil {
		return nil, nil, err
	}
	return &r, bundle, nil
}

// List enumerates all metadata files. Bundle payloads are NOT loaded.
func List(paths *config.Paths) ([]*Request, error) {
	dir := Dir(paths)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := []*Request{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		blob, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			continue
		}
		var r Request
		if err := json.Unmarshal(blob, &r); err != nil {
			continue
		}
		out = append(out, &r)
	}
	return out, nil
}

// Delete removes both the .json + .bundle for one lookup_id.
func Delete(paths *config.Paths, lookupID string) error {
	e1 := os.Remove(metaPath(paths, lookupID))
	e2 := os.Remove(bundlePath(paths, lookupID))
	if e1 != nil && !os.IsNotExist(e1) {
		return e1
	}
	if e2 != nil && !os.IsNotExist(e2) {
		return e2
	}
	return nil
}
