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
	kc.Root = paths.Root
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

// Create generates a new agent key for lookupID.
//
//	"ed25519" (explicit) → legacy file key. No rotation, grant edits or
//	                       bearer-free exec (those need P-256 ECDH).
//	"" or "p256"         → Secure Enclave P-256 when this Mac has one
//	                       (SE handle, dop-ofn — every build); otherwise a
//	                       P-256 file key (Linux, CI, Macs without an SE),
//	                       so rotation / grant edits / bearer-free exec still
//	                       work (dop-7b7). Same extractability as an ed25519
//	                       file; on macOS the fallback is announced loudly.
func Create(paths *config.Paths, lookupID, keyType string) (Store, error) {
	fb := NewFileBackend(paths.Root)
	if keyType != "" && keyType != vault.KeyTypeP256 {
		return fb.Generate(lookupID, keyType)
	}
	kc := NewKeychainBackend()
	kc.Root = paths.Root
	if kc.Available() {
		s, err := kc.Generate(lookupID, vault.KeyTypeP256)
		if err == nil {
			return s, nil
		}
		if runtime.GOOS == "darwin" {
			warnSEUnavailable(err)
		}
	} else if runtime.GOOS == "darwin" && os.Getenv("DOP_NO_KEYCHAIN") != "1" {
		warnSEFileFallback()
	}
	return fb.Generate(lookupID, vault.KeyTypeP256)
}

var seWarnedOnce bool

func warnSEUnavailable(err error) {
	if seWarnedOnce || os.Getenv("DOP_ALLOW_FILE_KEYS") == "1" {
		return
	}
	seWarnedOnce = true
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "╭─ ⚠  SECURE ENCLAVE UNAVAILABLE ──────────────────────────────────────╮")
	fmt.Fprintln(os.Stderr, "│ The agent key will be a P-256 file (0600, readable by any process    │")
	fmt.Fprintln(os.Stderr, "│ running as this user) instead of living in the Secure Enclave.       │")
	fmt.Fprintln(os.Stderr, "│ Rotation, grant edits and bearer-free exec still work.               │")
	fmt.Fprintln(os.Stderr, "│ Check with: dop doctor                                               │")
	fmt.Fprintln(os.Stderr, "╰──────────────────────────────────────────────────────────────────────╯")
	fmt.Fprintln(os.Stderr, "   Details:", err)
	fmt.Fprintln(os.Stderr, "")
}

// warnSEFileFallback: macOS, but the SE backend is off (no cgo bridge).
var seFileFallbackWarnedOnce bool

func warnSEFileFallback() {
	if seFileFallbackWarnedOnce || os.Getenv("DOP_ALLOW_FILE_KEYS") == "1" {
		return
	}
	seFileFallbackWarnedOnce = true
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "⚠  This dop build has no Secure Enclave bridge (built without cgo): the agent")
	fmt.Fprintln(os.Stderr, "   key will be a P-256 file (0600, readable by any process running as this user).")
	fmt.Fprintln(os.Stderr, "")
}

// Delete removes the key from wherever it lives. Idempotent.
func Delete(paths *config.Paths, lookupID string) error {
	kc := NewKeychainBackend()
	kc.Root = paths.Root
	if kc.Available() {
		_ = kc.Delete(lookupID)
	}
	return NewFileBackend(paths.Root).Delete(lookupID)
}
