// Package admin holds passphrase-wrapped admin keys and the local
// session daemon that unlocks them for the duration of an admin login.
//
// See ARCHITECTURE.md — two-plane model. This package covers the
// administrative plane.
package admin

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"filippo.io/age"
)

// Keys holds both admin private keys in memory. Only ever exists inside
// the daemon process (and briefly in the CLI during `dop admin init`).
type Keys struct {
	Age     *age.X25519Identity
	Ed25519 ed25519.PrivateKey
}

// keyBundle is the on-disk-encrypted JSON representation.
type keyBundle struct {
	Version       int    `json:"version"`
	AgeSecret     string `json:"age_secret"`     // "AGE-SECRET-KEY-..."
	Ed25519Secret string `json:"ed25519_secret"` // 64-byte hex (seed+pub)
}

// Generate creates a fresh admin key set: one X25519 identity (for SOPS
// decryption of vault.yaml) and one ed25519 keypair (for signing
// capability records).
func Generate() (*Keys, error) {
	ageID, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("generate age: %w", err)
	}
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ed25519: %w", err)
	}
	return &Keys{Age: ageID, Ed25519: edPriv}, nil
}

// Wrap encrypts the key bundle with an age scrypt-based passphrase
// recipient. The resulting bytes are safe to write to disk.
//
// Work factor 18 is ~1s on modern hardware — appropriate cost for an
// interactive admin login prompt.
func Wrap(k *Keys, passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, fmt.Errorf("wrap: passphrase must not be empty")
	}
	payload := keyBundle{
		Version:       1,
		AgeSecret:     k.Age.String(),
		Ed25519Secret: hex.EncodeToString(k.Ed25519),
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	recipient, err := age.NewScryptRecipient(passphrase)
	if err != nil {
		return nil, err
	}
	recipient.SetWorkFactor(18)
	var buf bytes.Buffer
	w, err := age.Encrypt(&buf, recipient)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(plaintext); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// Unwrap decrypts wrapped bytes with the passphrase. Returns a clean
// distinct error when the passphrase is wrong so callers can prompt
// again.
func Unwrap(wrapped []byte, passphrase string) (*Keys, error) {
	identity, err := age.NewScryptIdentity(passphrase)
	if err != nil {
		return nil, err
	}
	r, err := age.Decrypt(bytes.NewReader(wrapped), identity)
	if err != nil {
		return nil, ErrWrongPassphrase
	}
	plaintext, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	var kb keyBundle
	if err := json.Unmarshal(plaintext, &kb); err != nil {
		return nil, fmt.Errorf("decoded key bundle: %w", err)
	}
	if kb.Version != 1 {
		return nil, fmt.Errorf("unsupported wrapped key version %d", kb.Version)
	}
	ageID, err := age.ParseX25519Identity(kb.AgeSecret)
	if err != nil {
		return nil, fmt.Errorf("parse age secret: %w", err)
	}
	edBytes, err := hex.DecodeString(kb.Ed25519Secret)
	if err != nil {
		return nil, fmt.Errorf("decode ed25519: %w", err)
	}
	if len(edBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("bad ed25519 size %d", len(edBytes))
	}
	return &Keys{Age: ageID, Ed25519: ed25519.PrivateKey(edBytes)}, nil
}

// ErrWrongPassphrase is returned by Unwrap when the passphrase doesn't
// decrypt the file. Distinguished so callers can prompt again.
var ErrWrongPassphrase = fmt.Errorf("wrong passphrase")

// WriteFile atomically writes wrapped keys to path (mode 0600).
// Parent dir is created 0700 if missing.
func WriteFile(path string, wrapped []byte) error {
	dir := parentDir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, wrapped, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func parentDir(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' {
			return p[:i]
		}
	}
	return "."
}

// AdminPubkey returns the ed25519 public key as hex — this is what gets
// embedded in signed capability records under `issued_by`.
func (k *Keys) AdminPubkey() string {
	pub, ok := k.Ed25519.Public().(ed25519.PublicKey)
	if !ok {
		return ""
	}
	return hex.EncodeToString(pub)
}
