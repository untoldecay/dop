// Package envseal implements the v1.12 admin-to-agent secure channel
// used to ship freshly-resolved env (and eventually replacement bearers)
// through the vault without ever exposing them in plaintext.
//
// Handshake shape:
//
//	admin_ephem  = fresh P-256 keypair
//	shared       = ECDH(admin_ephem_priv, agent_p256_pub)
//	              = ECDH(agent_p256_priv, admin_ephem_pub)         [agent side]
//	key          = HKDF-SHA256(shared, salt, "dop-envseal-v1")     [both sides]
//	ct           = XChaCha20-Poly1305-Seal(key, nonce, plaintext, aad)
//
// The output package the admin writes to the record is (ephem_pub, salt,
// nonce, ct). Agent's side, once they have `shared`, applies HKDF with
// the exact same salt/info and opens.
//
// Cipher choice mirrors the bundle codec (`internal/capability` uses the
// same XChaCha20-Poly1305). Nonce is 24 bytes — safe under random
// generation.
//
// This package does NOT know how to compute `shared` on the agent side
// when the agent's private key lives in the Secure Enclave. That path
// goes through `internal/agentkey` (its Store interface will grow a
// `SharedSecret(peerPub)` method in M1c). This package's `Open` variant
// takes the shared secret directly, so it works with any source of that
// secret.
package envseal

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// HKDF context string. Bumping this rotates key derivation domain
// (e.g., "dop-envseal-v2" would make v1 sealed payloads un-openable
// by a v2 codebase). Keep in sync with what agents run.
const hkdfInfo = "dop-envseal-v1"

// Sealed holds the wire-format output of Seal — everything the record
// needs to reproduce the shared secret + open the ciphertext.
//
// All byte slices are stored as hex strings on the record for
// diff-friendliness in git.
type Sealed struct {
	AdminEphemPub []byte // uncompressed X9.62 P-256 point (65B: 0x04 || X || Y)
	Salt          []byte // 32B random per seal — HKDF salt
	Nonce         []byte // 24B random per seal — XChaCha20 nonce
	Ciphertext    []byte // AEAD ciphertext + 16B tag
}

// ToHex serializes a Sealed for record storage. Every field is
// hex-encoded (no base64 — matches the rest of the codebase).
func (s Sealed) ToHex() map[string]string {
	return map[string]string{
		"admin_ephem_pub": hex.EncodeToString(s.AdminEphemPub),
		"salt":            hex.EncodeToString(s.Salt),
		"nonce":           hex.EncodeToString(s.Nonce),
		"ciphertext":      hex.EncodeToString(s.Ciphertext),
	}
}

// FromHex inflates a hex-encoded Sealed. Any decode error is fatal —
// the record has been tampered with or corrupted.
func FromHex(m map[string]string) (Sealed, error) {
	var s Sealed
	var err error
	if s.AdminEphemPub, err = hex.DecodeString(m["admin_ephem_pub"]); err != nil {
		return s, fmt.Errorf("admin_ephem_pub: %w", err)
	}
	if s.Salt, err = hex.DecodeString(m["salt"]); err != nil {
		return s, fmt.Errorf("salt: %w", err)
	}
	if s.Nonce, err = hex.DecodeString(m["nonce"]); err != nil {
		return s, fmt.Errorf("nonce: %w", err)
	}
	if s.Ciphertext, err = hex.DecodeString(m["ciphertext"]); err != nil {
		return s, fmt.Errorf("ciphertext: %w", err)
	}
	return s, nil
}

// Seal encrypts plaintext to the agent identified by their P-256
// public key (uncompressed X9.62 encoding, 65 bytes starting with
// 0x04). aad is authenticated but not encrypted — typically a hash
// of the record fields the sealed payload commits to (generation,
// lookup_id) so a mismatched record can't be paired with a stale
// ciphertext.
//
// A fresh admin ephemeral keypair is generated for each call and the
// private half is discarded before return. Do not attempt to reuse.
func Seal(agentP256Pub []byte, plaintext []byte, aad []byte) (Sealed, error) {
	curve := ecdh.P256()
	agentPub, err := curve.NewPublicKey(agentP256Pub)
	if err != nil {
		return Sealed{}, fmt.Errorf("agent pubkey: %w", err)
	}
	ephemPriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return Sealed{}, fmt.Errorf("ephem keygen: %w", err)
	}
	shared, err := ephemPriv.ECDH(agentPub)
	if err != nil {
		return Sealed{}, fmt.Errorf("ecdh: %w", err)
	}

	salt := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return Sealed{}, fmt.Errorf("salt: %w", err)
	}
	key, err := deriveKey(shared, salt)
	if err != nil {
		return Sealed{}, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return Sealed{}, fmt.Errorf("aead init: %w", err)
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return Sealed{}, fmt.Errorf("nonce: %w", err)
	}
	ct := aead.Seal(nil, nonce, plaintext, aad)

	return Sealed{
		AdminEphemPub: ephemPriv.PublicKey().Bytes(),
		Salt:          salt,
		Nonce:         nonce,
		Ciphertext:    ct,
	}, nil
}

// OpenWithShared decrypts a Sealed given the pre-computed shared
// secret. Callers responsible for computing `shared` — from a Go
// crypto/ecdh key (via OpenWithPriv) or from the Secure Enclave (via
// agentkey.Store.SharedSecret in a later milestone).
//
// aad MUST match the aad used at Seal time byte-for-byte, otherwise
// AEAD auth fails and this returns an error.
func OpenWithShared(shared []byte, s Sealed, aad []byte) ([]byte, error) {
	if len(shared) == 0 {
		return nil, errors.New("envseal: empty shared secret")
	}
	key, err := deriveKey(shared, s.Salt)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("aead init: %w", err)
	}
	if len(s.Nonce) != aead.NonceSize() {
		return nil, fmt.Errorf("envseal: nonce length %d, want %d", len(s.Nonce), aead.NonceSize())
	}
	pt, err := aead.Open(nil, s.Nonce, s.Ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("envseal: open: %w", err)
	}
	return pt, nil
}

// OpenWithPriv decrypts a Sealed using a Go-native P-256 private key.
// Convenience wrapper around OpenWithShared for the file-backend
// path; SE-backed callers should compute the shared secret themselves
// (via agentkey.Store.SharedSecret) and call OpenWithShared directly.
func OpenWithPriv(agentPriv *ecdh.PrivateKey, s Sealed, aad []byte) ([]byte, error) {
	curve := ecdh.P256()
	ephemPub, err := curve.NewPublicKey(s.AdminEphemPub)
	if err != nil {
		return nil, fmt.Errorf("ephem pubkey: %w", err)
	}
	shared, err := agentPriv.ECDH(ephemPub)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}
	return OpenWithShared(shared, s, aad)
}

// deriveKey runs HKDF-SHA256 over the shared secret + salt with our
// domain-separating info string. Returns a 32-byte key suitable for
// XChaCha20-Poly1305.
func deriveKey(shared, salt []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, shared, salt, []byte(hkdfInfo))
	key := make([]byte, chacha20poly1305.KeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("hkdf: %w", err)
	}
	return key, nil
}
