// Shared helpers for TUI views that need to read the vault.

package tui

import (
	"bytes"
	"os"

	"gopkg.in/yaml.v3"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

// loadVaultForListing reads the vault via the admin daemon if encrypted,
// or directly if plaintext. Returns the parsed vault + the file path.
func loadVaultForListing(client *admin.Client, paths *config.Paths) (*vault.Vault, string, error) {
	vp := paths.Vault + "/vault.yaml"
	raw, err := os.ReadFile(vp)
	if err != nil {
		return nil, vp, err
	}
	if bytes.Contains(raw, []byte("\nsops:")) || bytes.HasPrefix(raw, []byte("sops:")) {
		plain, err := client.DecryptVault(vp)
		if err != nil {
			return nil, vp, err
		}
		raw = plain
	}
	var vv vault.Vault
	if err := yaml.Unmarshal(raw, &vv); err != nil {
		return nil, vp, err
	}
	return &vv, vp, nil
}

// vaultAttached returns true iff the vault directory is a git clone.
// The signal is `.git/` — a successful clone always creates it, even for
// an empty remote. Waiting for vault.yaml or .sops.yaml would hide the
// mutation menu until the user's first save, which is exactly the moment
// they need those options.
func vaultAttached(paths *config.Paths) bool {
	if paths == nil {
		return false
	}
	if _, err := os.Stat(paths.Vault + "/.git"); err == nil {
		return true
	}
	// Belt + suspenders: also accept a file called `.git` (git worktree
	// pointer) — happens if the user manually converted their setup.
	if fi, err := os.Stat(paths.Vault + "/.git"); err == nil && !fi.IsDir() {
		return true
	}
	// And still accept vault.yaml alone — covers weird test setups.
	if _, err := os.Stat(paths.Vault + "/vault.yaml"); err == nil {
		return true
	}
	return false
}
