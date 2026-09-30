// Signature verification, branching on key type. Used by exec/env to
// confirm that a challenge signed by an agent-side Store matches the
// pubkey recorded in the capability binding.

package agentkey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"errors"
	"fmt"

	"github.com/fray/dop/internal/vault"
)

// Verify checks that sig is a valid signature over challenge by
// pubkeyBytes under keyType. pubkeyBytes format:
//   ed25519: 32-byte raw pubkey
//   p256:    uncompressed X9.63 (65 bytes: 0x04 || X || Y)
// sig format:
//   ed25519: 64-byte raw EdDSA
//   p256:    X9.62/DER ECDSA
func Verify(keyType string, pubkeyBytes, challenge, sig []byte) error {
	switch keyType {
	case "", vault.KeyTypeEd25519:
		if len(pubkeyBytes) != ed25519.PublicKeySize {
			return errors.New("verify: ed25519 pubkey wrong size")
		}
		if !ed25519.Verify(ed25519.PublicKey(pubkeyBytes), challenge, sig) {
			return errors.New("verify: ed25519 signature failed")
		}
		return nil
	case vault.KeyTypeP256:
		x, y := elliptic.Unmarshal(elliptic.P256(), pubkeyBytes)
		if x == nil {
			return errors.New("verify: p256 pubkey unmarshal failed")
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
		digest := sha256Sum(challenge)
		if !ecdsa.VerifyASN1(pub, digest[:], sig) {
			return errors.New("verify: p256 signature failed")
		}
		return nil
	default:
		return fmt.Errorf("verify: unknown key_type %q", keyType)
	}
}

// PubkeyEqual returns true if two pubkey byte slices represent the
// same public key. Length mismatches short-circuit. Values aren't
// secrets — this is a public-identifier equality check.
func PubkeyEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
