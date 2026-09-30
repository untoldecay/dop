// Package agentkey abstracts the storage + signing of the ed25519 or
// P-256 key an agent generates during `dop claim`. Prior to v1.11 the
// key was always a raw 64-byte ed25519 file at
// <paths.Root>/agent-keys/<lookup_id>.key.
//
// v1.11 introduces a Store interface so we can:
//   1. Keep the file-backed ed25519 path working for legacy records
//      (verifiers still support "ed25519" key_type indefinitely).
//   2. Add a file-backed P-256 path for Linux / CI where Secure Enclave
//      isn't available and DOP_ALLOW_FILE_KEYS=1 is set.
//   3. Add a Secure-Enclave-backed P-256 path (macOS keychain_darwin.go)
//      so key material never leaves the hardware, killing the "copy
//      the .key file to another machine" attack class.
//
// The daemon owns the SE key on macOS — direct CLI access is a fallback
// only, gated on DOP_ALLOW_FILE_KEYS=1.
package agentkey

import (
	"crypto/ed25519"
	"errors"
)

// Store is the abstract handle for one agent key. A Store references a
// specific key (by LookupID) — it doesn't manage the set. Implementations
// are single-key stateless facades over the backing storage.
type Store interface {
	// LookupID is the vault lookup id this key was created for.
	LookupID() string

	// KeyType returns one of vault.KeyType* constants. Callers use
	// this to pick the right verifier.
	KeyType() string

	// PublicKey returns the raw public key bytes. For ed25519 that's
	// 32 bytes; for P-256 that's the uncompressed X9.63 65-byte form
	// (0x04 || X || Y).
	PublicKey() []byte

	// Sign signs the challenge and returns the signature bytes.
	// For ed25519, output is 64 bytes (raw EdDSA).
	// For P-256, output is X9.62/DER-encoded ECDSA (variable length,
	// typically 70-72 bytes).
	Sign(challenge []byte) ([]byte, error)

	// Extractable reports whether the private key material is
	// exportable from this Store. Hardware-backed keys (SE) return
	// false. File-backed keys return true. Surfaced via `dop doctor`
	// so operators can see which agents are hardened.
	Extractable() bool

	// StorageDescription returns a short human-readable string
	// describing where + how the key is stored, e.g.
	//   "file: /Users/cam/Library/…/agent-keys/abc.key (ed25519)"
	//   "macOS Secure Enclave (p256)"
	//   "file: /home/ci/.config/dop/…/abc.p256 (p256, explicit opt-in)"
	// Used by dop doctor and dop admin status.
	StorageDescription() string
}

// ErrNotFound is returned by Backend.Load when no key exists for
// the given lookup id.
var ErrNotFound = errors.New("agent key not found for this bearer")

// Backend is the platform-specific factory that opens/creates Store
// instances. Backends live behind build tags:
//   file_backend.go       — always available
//   keychain_backend_darwin.go — macOS-only, SE-backed P-256
type Backend interface {
	// Load opens the key for lookupID. Returns ErrNotFound if the
	// backend has no key for it (caller may then try another backend
	// or fail).
	Load(lookupID string) (Store, error)

	// Generate creates a fresh key for lookupID and returns its Store.
	// keyType is one of vault.KeyType* — implementations may refuse
	// unsupported types (e.g. file backend refuses p256 without the
	// explicit opt-in env var).
	Generate(lookupID, keyType string) (Store, error)

	// Delete removes the key. Idempotent.
	Delete(lookupID string) error

	// Name returns a short identifier for logs and doctor output
	// ("file", "keychain-darwin").
	Name() string
}

// EnsurePermsMode is the required permission mode on file-backed key
// files. Enforced on load: any laxer perms are refused rather than
// silently accepted (a mis-chmod could otherwise expose the key).
const EnsurePermsMode = 0o600

// Ed25519PublicKeyFrom extracts the public half of a raw 64-byte
// ed25519 private key. Kept here so the file backend's implementation
// details stay next to the interface.
func Ed25519PublicKeyFrom(priv ed25519.PrivateKey) []byte {
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil
	}
	return append([]byte(nil), pub...)
}
