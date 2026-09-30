//go:build darwin

// macOS Secure Enclave backend for agent keys. Stores an ECDSA P-256
// key in the SE via Security.framework so the private key material
// never leaves the hardware.
//
// STATUS (v1.11 branch checkpoint): the cgo bridge to Security.framework
// is NOT yet implemented. This file exists so the platform-selection
// code compiles and so tests targeting the interface can be written
// against a mock. Actual SE-backed signing lands in the next commit
// on this branch.
//
// Design notes for the impl (do not implement here yet):
//   - SecAccessControlCreateWithFlags with:
//       kSecAccessControlPrivateKeyUsage (required for SE keys)
//       No biometric flag (Mode 1: no Touch ID prompt)
//       kSecAttrAccessibleWhenUnlockedThisDeviceOnly
//   - SecKeyCreateRandomKey with:
//       kSecAttrKeyType     = kSecAttrKeyTypeECSECPrimeRandom
//       kSecAttrKeySizeInBits = 256
//       kSecAttrTokenID     = kSecAttrTokenIDSecureEnclave
//       kSecAttrIsPermanent = true
//       kSecAttrApplicationTag = "dop.agent.<lookup_id>" bytes
//       kSecAttrAccessControl = accessControl
//   - SecKeyCreateSignature with:
//       kSecKeyAlgorithmECDSASignatureMessageX962SHA256
//   - SecItemDelete via query with matching application tag on rotate/uninstall
//   - The daemon is the sole holder — CLI-side signing paths get an error
//     saying "run 'dop admin login' — signing goes through the daemon".

package agentkey

import (
	"errors"
	"os"
	"runtime"
)

// KeychainBackend will hold the SE-backed P-256 store implementation.
// For now, all methods return "not implemented" so callers fall through
// to the file backend during v1.11 branch development.
type KeychainBackend struct {
	// AppTagPrefix is the string prefixed to lookup ids when storing
	// keys under kSecAttrApplicationTag. Kept configurable so tests
	// can use a namespace that doesn't collide with a real install.
	AppTagPrefix string
}

// NewKeychainBackend returns a KeychainBackend. On non-darwin builds
// this file is excluded via the build tag; on darwin builds it exists
// but returns "not yet implemented" for every operation until the cgo
// bridge lands. Callers should combine it with a FileBackend fallback.
func NewKeychainBackend() *KeychainBackend {
	return &KeychainBackend{AppTagPrefix: "dop.agent."}
}

func (b *KeychainBackend) Name() string { return "keychain-darwin" }

// Available returns true when the SE-backed backend should be tried.
// v1.11-checkpoint: always returns false because the cgo bridge isn't
// there yet. Once implemented, this checks kSecAttrTokenIDSecureEnclave
// availability + macOS version + presence of a Keychain session.
func (b *KeychainBackend) Available() bool {
	// Guardrails while the bridge is a stub — never let this backend
	// silently claim to work.
	if runtime.GOOS != "darwin" {
		return false
	}
	if os.Getenv("DOP_KEYCHAIN_STUB") == "1" {
		// Tests can flip this to exercise the "backend prefers keychain
		// but falls back to file on error" path.
		return true
	}
	return false
}

func (b *KeychainBackend) Load(lookupID string) (Store, error) {
	return nil, errors.New("keychain-darwin: Load not yet implemented (v1.11 branch checkpoint)")
}

func (b *KeychainBackend) Generate(lookupID, keyType string) (Store, error) {
	return nil, errors.New("keychain-darwin: Generate not yet implemented (v1.11 branch checkpoint)")
}

func (b *KeychainBackend) Delete(lookupID string) error {
	return errors.New("keychain-darwin: Delete not yet implemented (v1.11 branch checkpoint)")
}
