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
// backend. When multiple key types exist for the same lookup (e.g.
// mid-migration, an ed25519 file lingers alongside a fresh p256), the
// file backend's default preference is p256 → ed25519. If the caller
// knows which type it wants, use OpenByType — verifyBinding does that
// after reading the record's key_type.
func Open(paths *config.Paths, lookupID string) (Store, error) {
	return OpenByType(paths, lookupID, "")
}

// OpenByType loads the agent key for lookupID, preferring the store
// whose KeyType() matches expectedType. Falls back to any available
// key if expectedType is empty. Returns ErrNotFound if no backend has
// a key for this lookup.
func OpenByType(paths *config.Paths, lookupID, expectedType string) (Store, error) {
	kc := NewKeychainBackend()
	if kc.Available() {
		if s, err := kc.Load(lookupID); err == nil {
			if expectedType == "" || s.KeyType() == expectedType {
				return s, nil
			}
			// SE has a key but not the type we want; check file too.
		} else if err != ErrNotFound {
			if fs, ferr := NewFileBackend(paths.Root).Load(lookupID); ferr == nil {
				return fs, nil
			}
			return nil, err
		}
	}
	// File backend: prefer the exact type when the caller specified one.
	fb := NewFileBackend(paths.Root)
	if expectedType != "" {
		if s, err := fb.LoadByType(lookupID, expectedType); err == nil {
			return s, nil
		} else if err != ErrNotFound {
			return nil, err
		}
	}
	return fb.Load(lookupID)
}

// Create generates a new agent key for lookupID. Policy is layered:
//
//   Explicit keyType passed:
//     "p256"    → try Keychain first; if unavailable, refuse on macOS
//                 desktop unless DOP_ALLOW_FILE_KEYS=1 opts in to the
//                 extractable file backend. Non-macOS uses file backend
//                 (also gated by DOP_ALLOW_FILE_KEYS=1).
//     "ed25519" → file backend (legacy). Works on every platform, no
//                 opt-in required — this is the pre-v1.11 behavior.
//
//   No keyType (auto): pick the best available option that works right
//   now without prompting for opt-in. Preference:
//     1. Keychain SE P-256 (macOS, when the cgo bridge is live)
//     2. Ed25519 legacy file (universally works, unchanged v1.10 shape)
//
//   Note: the "auto" path deliberately does NOT default to P-256 file
//   storage — that would silently ship an extractable key with the
//   same threat profile as v1.10 while claiming a v1.11 label.
func Create(paths *config.Paths, lookupID, keyType string) (Store, error) {
	kc := NewKeychainBackend()

	// Auto: SE if available, else legacy ed25519.
	if keyType == "" {
		if kc.Available() {
			return kc.Generate(lookupID, vault.KeyTypeP256)
		}
		return NewFileBackend(paths.Root).Generate(lookupID, vault.KeyTypeEd25519)
	}

	// Explicit p256: try SE first; if unavailable, gate on opt-in.
	if keyType == vault.KeyTypeP256 {
		if kc.Available() {
			return kc.Generate(lookupID, keyType)
		}
		if runtime.GOOS == "darwin" && os.Getenv("DOP_ALLOW_FILE_KEYS") != "1" {
			return nil, fmt.Errorf(
				"macOS Secure Enclave is required for P-256 agent keys on this platform.\n" +
					"  If SE is unavailable and you understand the risk of extractable keys,\n" +
					"  set DOP_ALLOW_FILE_KEYS=1 to allow the file backend as a fallback.")
		}
		return NewFileBackend(paths.Root).Generate(lookupID, keyType)
	}

	// Explicit ed25519: always the file backend.
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
