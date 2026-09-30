// Platform-selecting facade over the file + keychain backends. Callers
// use Open() to load an existing key and Create() to make a new one;
// the right backend gets picked based on OS + operator opt-ins.

package agentkey

import (
	"fmt"
	"os"
	"runtime"

	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

// Open loads the agent key for lookupID from the best-available
// backend. Preference order:
//   1. Keychain (macOS Secure Enclave), if Available()
//   2. File backend (looks for .key ed25519 then .p256)
// Returns ErrNotFound if no backend has a key for this lookup.
func Open(paths *config.Paths, lookupID string) (Store, error) {
	kc := NewKeychainBackend()
	if kc.Available() {
		if s, err := kc.Load(lookupID); err == nil {
			return s, nil
		} else if err != ErrNotFound {
			// Real error from the SE path — fall through to file
			// backend so a legacy key still works, but keep the
			// original error for surfacing if the file backend also
			// misses.
			if fs, ferr := NewFileBackend(paths.Root).Load(lookupID); ferr == nil {
				return fs, nil
			}
			return nil, err
		}
	}
	return NewFileBackend(paths.Root).Load(lookupID)
}

// Create generates a new agent key for lookupID. Policy:
//   - macOS desktop + Available(): SE-backed P-256
//   - macOS without SE (rare): refuse unless DOP_ALLOW_FILE_KEYS=1
//   - Linux/CI: file P-256 with DOP_ALLOW_FILE_KEYS=1, else refuse
//
// The keyType parameter is a hint; if the target backend can't honor
// it (e.g. SE only supports p256, file backend refuses p256 without
// opt-in), the error is surfaced rather than silently swapped.
func Create(paths *config.Paths, lookupID, keyType string) (Store, error) {
	if keyType == "" {
		// Default: prefer P-256 on macOS (SE-backed), keep Ed25519
		// on non-macOS so existing verifiers keep working. When the
		// file P-256 backend is opt-in only, this default sidesteps
		// the "you need DOP_ALLOW_FILE_KEYS to use dop on Linux at
		// all" trap.
		if runtime.GOOS == "darwin" {
			keyType = vault.KeyTypeP256
		} else {
			keyType = vault.KeyTypeEd25519
		}
	}
	kc := NewKeychainBackend()
	if kc.Available() && keyType == vault.KeyTypeP256 {
		return kc.Generate(lookupID, keyType)
	}
	// Fall-back path — file backend. Refuse macOS desktop file fallback
	// unless explicitly opted in, so nobody accidentally ships an
	// extractable key on a machine that has SE available.
	if runtime.GOOS == "darwin" && keyType == vault.KeyTypeP256 && os.Getenv("DOP_ALLOW_FILE_KEYS") != "1" {
		return nil, fmt.Errorf(
			"macOS Secure Enclave is required for P-256 agent keys on this platform.\n" +
				"  If SE is unavailable (rare) and you understand the risk of extractable keys,\n" +
				"  set DOP_ALLOW_FILE_KEYS=1 to allow the file backend as a fallback.")
	}
	return NewFileBackend(paths.Root).Generate(lookupID, keyType)
}

// Delete removes the key from wherever it lives. Idempotent.
func Delete(paths *config.Paths, lookupID string) error {
	kc := NewKeychainBackend()
	if kc.Available() {
		_ = kc.Delete(lookupID)
	}
	return NewFileBackend(paths.Root).Delete(lookupID)
}
