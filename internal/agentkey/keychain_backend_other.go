//go:build !darwin

// Non-darwin stub for the keychain backend. Present so callers can
// unconditionally reference KeychainBackend in platform-agnostic code
// paths; Available() returns false so file backend takes over.

package agentkey

// KeychainBackend on non-darwin is a no-op — SE isn't available.
type KeychainBackend struct{}

// NewKeychainBackend returns a stub that always reports unavailable.
func NewKeychainBackend() *KeychainBackend { return &KeychainBackend{} }

// Available always returns false on non-darwin.
func (b *KeychainBackend) Available() bool { return false }

// Name returns the backend identifier for logs.
func (b *KeychainBackend) Name() string { return "keychain-darwin (unavailable — non-darwin)" }

// Load fails — non-darwin has no SE.
func (b *KeychainBackend) Load(_ string) (Store, error) {
	return nil, ErrNotFound
}

// Generate fails — non-darwin has no SE.
func (b *KeychainBackend) Generate(_, _ string) (Store, error) {
	return nil, ErrNotFound
}

// Delete is a no-op on non-darwin.
func (b *KeychainBackend) Delete(_ string) error { return nil }
