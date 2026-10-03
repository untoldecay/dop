// Admin-use bearer stash helpers (v1.14.0-rc1).
//
// `dop token issue --for-admin-use` wraps the fresh bearer value with
// the issuing admin's age recipient and stores the ciphertext on the
// capability record (vault.Capability.AdminUseWrapped). Only the
// admin that owns the matching age identity can later unwrap it —
// typically via the admin session daemon, which holds the identity
// in memory while unlocked.
//
// This is a public-key encryption: wrapping needs only the recipient
// (ok to run from the client). Unwrapping needs the identity (daemon).
// Kept distinct from the scrypt-based Wrap/Unwrap in keys.go which
// are for the admin keyfile itself.

package admin

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"

	"filippo.io/age"
)

// WrapToRecipient encrypts plaintext for the given age recipient (an
// `age1...` string) and returns the base64-encoded ciphertext. Safe
// to call from any process; needs only the public recipient.
func WrapToRecipient(plaintext []byte, ageRecipient string) (string, error) {
	rcpt, err := age.ParseX25519Recipient(ageRecipient)
	if err != nil {
		return "", fmt.Errorf("parse age recipient: %w", err)
	}
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, rcpt)
	if err != nil {
		return "", err
	}
	if _, err := w.Write(plaintext); err != nil {
		return "", err
	}
	if err := w.Close(); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

// UnwrapWithIdentity decrypts a base64-encoded ciphertext produced by
// WrapToRecipient, using the given age identity. Returns the raw
// plaintext bytes.
func UnwrapWithIdentity(ciphertextB64 string, id *age.X25519Identity) ([]byte, error) {
	ct, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	r, err := age.Decrypt(bytes.NewReader(ct), id)
	if err != nil {
		return nil, fmt.Errorf("age decrypt: %w", err)
	}
	return io.ReadAll(r)
}
