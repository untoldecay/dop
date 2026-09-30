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
)

// KeychainBackend holds the SE-backed P-256 store implementation.
// When cgo is enabled (keychain_darwin_cgo.go build tag), init()
// there rewires seLoad/seGenerate/seDelete/seAvailable to real
// Security.framework calls. Without cgo, this file's stub versions
// stand in — Available() returns false so callers fall through to
// the file backend.
type KeychainBackend struct {
	// AppTagPrefix is the string prefixed to lookup ids when storing
	// keys under kSecAttrApplicationTag. Kept configurable so tests
	// can use a namespace that doesn't collide with a real install.
	AppTagPrefix string
}

// NewKeychainBackend returns a KeychainBackend. Actual availability
// is decided at call time by Available() — which uses seAvailable
// (wired by the cgo file when built with cgo).
func NewKeychainBackend() *KeychainBackend {
	return &KeychainBackend{AppTagPrefix: "dop.agent."}
}

func (b *KeychainBackend) Name() string { return "keychain-darwin" }

// The following four package-level function vars are the seam between
// the "stub, always fails" build (no cgo) and the "real, calls into
// Security.framework" build (cgo). The cgo file's init() overwrites
// them at process start when the tag is set.

var (
	seAvailable = func() bool {
		// Escape hatch for headless CI runs where the SE bridge exists
		// but the test wants to exercise the file backend path.
		return os.Getenv("DOP_KEYCHAIN_STUB") == "1"
	}
	seLoad = func(_ *KeychainBackend, _ string) (Store, error) {
		return nil, errors.New("keychain-darwin: cgo bridge not built (build with CGO_ENABLED=1)")
	}
	seGenerate = func(_ *KeychainBackend, _, _ string) (Store, error) {
		return nil, errors.New("keychain-darwin: cgo bridge not built (build with CGO_ENABLED=1)")
	}
	seDelete = func(_ *KeychainBackend, _ string) error {
		return errors.New("keychain-darwin: cgo bridge not built")
	}
)

// Available reports whether the SE-backed backend can be used right
// now. The cgo build overrides seAvailable with a real probe.
func (b *KeychainBackend) Available() bool {
	if os.Getenv("DOP_NO_KEYCHAIN") == "1" {
		return false
	}
	return seAvailable()
}

func (b *KeychainBackend) Load(lookupID string) (Store, error) {
	return seLoad(b, lookupID)
}

func (b *KeychainBackend) Generate(lookupID, keyType string) (Store, error) {
	return seGenerate(b, lookupID, keyType)
}

func (b *KeychainBackend) Delete(lookupID string) error {
	return seDelete(b, lookupID)
}
