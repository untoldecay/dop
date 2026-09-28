package admin

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"

	"filippo.io/age"
)

// KeysFromComponents rebuilds a Keys struct from its constituent
// serialized parts. Used by the daemon to accept keys from the login
// parent via stdin.
func KeysFromComponents(ageSecret, ed25519HexSecret string) (*Keys, error) {
	ageID, err := age.ParseX25519Identity(ageSecret)
	if err != nil {
		return nil, fmt.Errorf("parse age secret: %w", err)
	}
	edBytes, err := hex.DecodeString(ed25519HexSecret)
	if err != nil {
		return nil, fmt.Errorf("decode ed25519 hex: %w", err)
	}
	if len(edBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("bad ed25519 size %d", len(edBytes))
	}
	return &Keys{Age: ageID, Ed25519: ed25519.PrivateKey(edBytes)}, nil
}
