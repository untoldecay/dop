// Package trust is the plain-text-committed "who is an admin" file for
// agent-side signature verification.
//
// Rationale: the vault (SOPS-encrypted) already carries the list of
// admins, but agent installs never have the age key to decrypt it.
// Without a plain-text way to enumerate trusted admin pubkeys, the
// exec plane cannot verify signed capability records, so the "signed
// records prevent tampering" claim collapses.
//
// We commit `admins.trust` alongside `vault-context.bin` (both public
// artifacts). The file is written by every `dop token issue/revoke`
// via the admin daemon (same path as vault.yaml re-encryption).
//
// Threat notes:
//   - We rely on the repo itself being authentic (SSH auth, GitHub org).
//     If an attacker can push to the vault repo, they can add a rogue
//     admin pubkey — but if they can push, they can already write raw
//     bundles too. Same trust anchor.
//   - The file is not itself signed. Signing it would introduce a
//     bootstrap chicken-and-egg (chain of trust). git history is the
//     out-of-band verification mechanism.
package trust

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

// Admin is the public info about one admin: pubkey + name.
type Admin struct {
	Name         string `json:"name"`
	Ed25519      string `json:"ed25519_pubkey"`
	AgeRecipient string `json:"age_recipient"`
	Note         string `json:"note,omitempty"`
}

// File is the marshaled trust list.
type File struct {
	Version int     `json:"version"`
	Admins  []Admin `json:"admins"`
}

// Path returns the on-disk location for the trust file.
func Path(paths *config.Paths) string {
	return filepath.Join(paths.Vault, "admins.trust")
}

// Write serializes the vault's Admins map to admins.trust (0644).
// Called from saveVaultViaDaemon so it stays in sync with the vault.
func Write(paths *config.Paths, v *vault.Vault) error {
	f := File{Version: 1}
	for name, a := range v.Admins {
		f.Admins = append(f.Admins, Admin{
			Name:         name,
			Ed25519:      a.Ed25519Pubkey,
			AgeRecipient: a.AgeRecipient,
			Note:         a.Note,
		})
	}
	blob, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	blob = append(blob, '\n')
	p := Path(paths)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Load reads admins.trust and returns the pubkey set. Returns an empty
// set + nil error if the file doesn't exist yet (fresh install).
func Load(paths *config.Paths) (map[string]bool, error) {
	blob, err := os.ReadFile(Path(paths))
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]bool{}, nil
		}
		return nil, err
	}
	var f File
	if err := json.Unmarshal(blob, &f); err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, a := range f.Admins {
		if a.Ed25519 != "" {
			out[a.Ed25519] = true
		}
	}
	return out, nil
}
