// Setup-phase state detection for the TUI. The root model consults this
// on startup to decide whether to route through the first-run flow before
// showing the main menu.

package tui

import (
	"os"
	"path/filepath"

	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

// SetupState describes the machine's setup readiness (cases A/B/C/D/E
// from the design doc).
type SetupState int

const (
	SetupReady           SetupState = iota // D — key + vault attached + decrypts
	SetupNoKey                             // A — no age key on this machine
	SetupNoVault                           // B — key present but no vault attached
	SetupVaultEmpty                        // C — vault attached, no vault.yaml yet
	SetupNotRecipient                      // E — vault.yaml exists but this key can't decrypt
	SetupUnknownError                      // fallback for stat errors
)

func (s SetupState) String() string {
	switch s {
	case SetupReady:
		return "ready"
	case SetupNoKey:
		return "no-key"
	case SetupNoVault:
		return "no-vault"
	case SetupVaultEmpty:
		return "vault-empty"
	case SetupNotRecipient:
		return "not-recipient"
	}
	return "unknown"
}

// DetectSetup inspects the on-disk state relative to `paths` and returns
// the resulting SetupState plus, if applicable, the vault path to use.
//
// Pure enough to unit-test: takes `paths` (not env), reads only files.
func DetectSetup(paths *config.Paths) (SetupState, string) {
	if paths == nil {
		return SetupUnknownError, ""
	}
	if !exists(paths.KeyFile) {
		return SetupNoKey, ""
	}
	sopsCfg := filepath.Join(paths.Vault, ".sops.yaml")
	if !exists(sopsCfg) {
		return SetupNoVault, ""
	}
	vaultFile := filepath.Join(paths.Vault, "vault.yaml")
	if !exists(vaultFile) {
		return SetupVaultEmpty, vaultFile
	}
	// Try to load — this triggers sops decrypt.
	if _, err := vault.Load(vaultFile); err != nil {
		return SetupNotRecipient, vaultFile
	}
	return SetupReady, vaultFile
}

func exists(p string) bool {
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}
