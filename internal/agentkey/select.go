// Platform-selecting facade over the file + keychain backends. Callers
// use Open() to load an existing key and Create() to make a new one;
// the right backend gets picked based on OS + operator opt-ins.

package agentkey

import (
	"fmt"
	"os"
	"runtime"
	"strings"

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
//     1. Keychain SE P-256 (macOS, when the cgo bridge is live AND
//        the binary is code-signed with the required entitlements)
//     2. Ed25519 legacy file (universally works, unchanged v1.10 shape)
//
//   v1.11.0-rc3 — if SE keygen fails at runtime (typically because the
//   binary isn't code-signed → OSStatus -34018 errSecMissingEntitlement),
//   the auto path falls back to legacy ed25519 file storage with a
//   loud stderr warning. This keeps unsigned developer builds usable
//   while making the security regression visible on every claim.
func Create(paths *config.Paths, lookupID, keyType string) (Store, error) {
	kc := NewKeychainBackend()

	// Auto: SE if available, else legacy ed25519.
	if keyType == "" {
		if kc.Available() {
			if s, err := kc.Generate(lookupID, vault.KeyTypeP256); err == nil {
				return s, nil
			} else if isEntitlementError(err) {
				warnSEUnavailable(err)
				// Fall through to legacy ed25519 file.
			} else {
				return nil, err
			}
		}
		return NewFileBackend(paths.Root).Generate(lookupID, vault.KeyTypeEd25519)
	}

	// Explicit p256: try SE first; if unavailable OR unsigned, gate on opt-in.
	if keyType == vault.KeyTypeP256 {
		seEntitlementErr := error(nil)
		if kc.Available() {
			if s, err := kc.Generate(lookupID, keyType); err == nil {
				return s, nil
			} else if !isEntitlementError(err) {
				return nil, err
			} else {
				seEntitlementErr = err
			}
			// Entitlement error — fall through to the file-backend
			// gating below (which requires DOP_ALLOW_FILE_KEYS=1 on
			// macOS desktop).
		}
		if runtime.GOOS == "darwin" && os.Getenv("DOP_ALLOW_FILE_KEYS") != "1" {
			return nil, fmt.Errorf(
				"macOS Secure Enclave is required for P-256 agent keys on this platform,\n" +
					"  but this dop binary can't reach the SE (usually because it's not code-signed\n" +
					"  with the keychain-access entitlement — OSStatus -34018).\n" +
					"  Fix by installing an officially-signed release, or accept extractable file storage\n" +
					"  by setting DOP_ALLOW_FILE_KEYS=1 for the current command.")
		}
		// v1.13.0-rc11 — ClaudeMini field report: on macOS without a
		// Developer ID cert, every explicit --key-type p256 claim quietly
		// landed in an extractable file. Make this noisy so operators
		// see the security downgrade at claim time, not later from
		// `dop doctor`.
		if seEntitlementErr != nil {
			warnSEUnavailable(seEntitlementErr)
		} else if runtime.GOOS == "darwin" {
			warnSEFileFallback()
		}
		return NewFileBackend(paths.Root).Generate(lookupID, keyType)
	}

	// Explicit ed25519: always the file backend.
	return NewFileBackend(paths.Root).Generate(lookupID, keyType)
}

// isEntitlementError detects the specific macOS Keychain error that
// means "this binary can't reach the Secure Enclave because it isn't
// code-signed with the right entitlements". Any other SE error (e.g.
// disk full, hardware fault) surfaces as a hard failure.
func isEntitlementError(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	// errSecMissingEntitlement == -34018
	return strings.Contains(s, "-34018") ||
		strings.Contains(s, "errSecMissingEntitlement") ||
		strings.Contains(s, "missing entitlement")
}

// warnSEUnavailable prints a one-off "this dop binary can't use SE"
// warning to stderr the first time we hit the entitlement gap in this
// process. Structured so an operator (or agent scraping the output)
// notices the security downgrade.
var seWarnedOnce bool

func warnSEUnavailable(err error) {
	if seWarnedOnce {
		return
	}
	seWarnedOnce = true
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "⚠  Secure Enclave unavailable — this dop binary isn't code-signed for SE access.")
	fmt.Fprintln(os.Stderr, "   Falling back to file-backed ed25519 (extractable to any process on this uid).")
	fmt.Fprintln(os.Stderr, "   To harden: install an officially-signed dop release.")
	fmt.Fprintln(os.Stderr, "   Details:", err)
	fmt.Fprintln(os.Stderr, "")
}

// v1.13.0-rc11 — warnSEFileFallback is the louder cousin fired when
// the operator explicitly chose --key-type p256 but the SE is not
// reachable (ClaudeMini field report). The private key WILL land in
// an extractable file. Different wording than warnSEUnavailable so
// scrapers/doctors can tell the paths apart.
var seFileFallbackWarnedOnce bool

func warnSEFileFallback() {
	if seFileFallbackWarnedOnce {
		return
	}
	seFileFallbackWarnedOnce = true
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "⚠  P-256 agent key will be EXTRACTABLE on this install.")
	fmt.Fprintln(os.Stderr, "   The Secure Enclave isn't reachable (binary not Developer-ID-signed), so")
	fmt.Fprintln(os.Stderr, "   the private key lands in a 0600 file on disk — readable by any process")
	fmt.Fprintln(os.Stderr, "   running as this uid.")
	fmt.Fprintln(os.Stderr, "   Live-grant features (reseal, add-grant, rotate) still work; the key is")
	fmt.Fprintln(os.Stderr, "   just not hardware-locked. Install an officially-signed release to upgrade.")
	fmt.Fprintln(os.Stderr, "")
}

// Delete removes the key from wherever it lives. Idempotent.
func Delete(paths *config.Paths, lookupID string) error {
	kc := NewKeychainBackend()
	if kc.Available() {
		_ = kc.Delete(lookupID)
	}
	return NewFileBackend(paths.Root).Delete(lookupID)
}
