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

// vaultAttached returns true iff a vault.yaml exists at the standard location.
func vaultAttached(paths *config.Paths) bool {
	if paths == nil {
		return false
	}
	_, err := os.Stat(paths.Vault + "/vault.yaml")
	if err == nil {
		return true
	}
	// Also count "vault dir cloned but empty" as attached — the user's
	// intent is expressed by the presence of .sops.yaml.
	_, err = os.Stat(paths.Vault + "/.sops.yaml")
	return err == nil
}
