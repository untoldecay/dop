// File-backed agent-key implementation. Always available; the only
// option on Linux / CI and the legacy path on macOS. For P-256 keys
// on non-macOS, callers must set DOP_ALLOW_FILE_KEYS=1 to opt in.
//
// File layout under <paths.Root>/agent-keys/ :
//   <lookup>.key    — raw 64-byte ed25519 private key (legacy, pre-v1.11)
//   <lookup>.p256   — PEM-encoded P-256 private key (v1.11+ file-backed
//                      P-256, gated on DOP_ALLOW_FILE_KEYS=1)
//
// The daemon owns SE-backed keys (keychain_backend_darwin.go). The file
// backend is used for lookup+load fallback when a SE key doesn't exist
// for a given lookup id, and for the legacy Ed25519 code path that
// must keep working until every capability has been re-enrolled.

package agentkey

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/fray/dop/internal/vault"
)

// FileBackend stores keys as files under root/agent-keys/.
type FileBackend struct {
	Root string // paths.Root
}

// NewFileBackend constructs a FileBackend rooted at the given directory.
func NewFileBackend(root string) *FileBackend { return &FileBackend{Root: root} }

func (b *FileBackend) Name() string { return "file" }

func (b *FileBackend) dir() string { return filepath.Join(b.Root, "agent-keys") }

func (b *FileBackend) edPath(lookupID string) string {
	return filepath.Join(b.dir(), lookupID+".key")
}

func (b *FileBackend) p256Path(lookupID string) string {
	return filepath.Join(b.dir(), lookupID+".p256")
}

// Load tries P-256 first (newer, harder to steal even in file form)
// then ed25519. When a caller knows the target type, LoadByType is
// deterministic — used by verifyBinding after reading the record's
// key_type.
func (b *FileBackend) Load(lookupID string) (Store, error) {
	if s, err := b.loadP256(lookupID); err == nil {
		return s, nil
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	if s, err := b.loadEd25519(lookupID); err == nil {
		return s, nil
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return nil, ErrNotFound
}

// LoadByType returns the store matching keyType exactly, or ErrNotFound.
func (b *FileBackend) LoadByType(lookupID, keyType string) (Store, error) {
	switch keyType {
	case "", "ed25519":
		return b.loadEd25519(lookupID)
	case "p256":
		return b.loadP256(lookupID)
	default:
		return nil, ErrNotFound
	}
}

func (b *FileBackend) loadEd25519(lookupID string) (Store, error) {
	p := b.edPath(lookupID)
	fi, err := os.Stat(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s: permissions %o are too permissive (want 0600)", p, fi.Mode().Perm())
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("agent key: wrong ed25519 size")
	}
	return &fileEd25519Store{
		lookupID: lookupID,
		path:     p,
		priv:     ed25519.PrivateKey(raw),
	}, nil
}

func (b *FileBackend) loadP256(lookupID string) (Store, error) {
	p := b.p256Path(lookupID)
	fi, err := os.Stat(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("%s: permissions %o are too permissive (want 0600)", p, fi.Mode().Perm())
	}
	pemBytes, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("agent key p256: no PEM block found")
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("agent key p256: parse: %w", err)
	}
	if key.Curve != elliptic.P256() {
		return nil, errors.New("agent key p256: wrong curve")
	}
	return &fileP256Store{
		lookupID: lookupID,
		path:     p,
		priv:     key,
	}, nil
}

// Generate creates a new key of the requested type.
func (b *FileBackend) Generate(lookupID, keyType string) (Store, error) {
	if err := os.MkdirAll(b.dir(), 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(b.dir(), 0o700); err != nil {
		return nil, err
	}
	switch keyType {
	case vault.KeyTypeEd25519:
		return b.generateEd25519(lookupID)
	case vault.KeyTypeP256:
		// Gate on the explicit opt-in for file-backed P-256. Callers
		// on macOS should use the keychain backend; callers on
		// Linux/CI need to acknowledge that this is exportable.
		if os.Getenv("DOP_ALLOW_FILE_KEYS") != "1" {
			return nil, errors.New(
				"file-backed P-256 keys require DOP_ALLOW_FILE_KEYS=1.\n" +
					"  On macOS, use the Secure Enclave backend (the default).\n" +
					"  On Linux/CI, set the env var explicitly to acknowledge that\n" +
					"  the key file will be extractable to any process on this uid.")
		}
		return b.generateP256(lookupID)
	default:
		return nil, fmt.Errorf("file backend: unsupported key type %q", keyType)
	}
}

func (b *FileBackend) generateEd25519(lookupID string) (Store, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	p := b.edPath(lookupID)
	if err := os.WriteFile(p, priv, EnsurePermsMode); err != nil {
		return nil, err
	}
	return &fileEd25519Store{lookupID: lookupID, path: p, priv: priv}, nil
}

func (b *FileBackend) generateP256(lookupID string) (Store, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	p := b.p256Path(lookupID)
	if err := os.WriteFile(p, pemBytes, EnsurePermsMode); err != nil {
		return nil, err
	}
	return &fileP256Store{lookupID: lookupID, path: p, priv: key}, nil
}

// Delete removes both the ed25519 and the P-256 file for a lookup id.
// Idempotent.
func (b *FileBackend) Delete(lookupID string) error {
	for _, p := range []string{b.edPath(lookupID), b.p256Path(lookupID)} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

// --- Ed25519 file store ---

type fileEd25519Store struct {
	lookupID string
	path     string
	priv     ed25519.PrivateKey
}

func (s *fileEd25519Store) LookupID() string { return s.lookupID }
func (s *fileEd25519Store) KeyType() string  { return vault.KeyTypeEd25519 }
func (s *fileEd25519Store) PublicKey() []byte {
	return Ed25519PublicKeyFrom(s.priv)
}
func (s *fileEd25519Store) Sign(challenge []byte) ([]byte, error) {
	return ed25519.Sign(s.priv, challenge), nil
}
func (s *fileEd25519Store) Extractable() bool { return true }
func (s *fileEd25519Store) StorageDescription() string {
	return fmt.Sprintf("file: %s (ed25519, LEGACY — extractable to any process on this uid)", s.path)
}
func (s *fileEd25519Store) SharedSecret(peerPub []byte) ([]byte, error) {
	return nil, ErrECDHUnsupported
}

// --- P-256 file store ---

type fileP256Store struct {
	lookupID string
	path     string
	priv     *ecdsa.PrivateKey
}

func (s *fileP256Store) LookupID() string { return s.lookupID }
func (s *fileP256Store) KeyType() string  { return vault.KeyTypeP256 }
func (s *fileP256Store) PublicKey() []byte {
	// Uncompressed X9.63 encoding: 0x04 || X (32) || Y (32) = 65 bytes.
	return elliptic.Marshal(elliptic.P256(), s.priv.PublicKey.X, s.priv.PublicKey.Y)
}
func (s *fileP256Store) Sign(challenge []byte) ([]byte, error) {
	// SHA-256 hash of the challenge, then ECDSA sign — the verifier
	// side (keychain sign path on macOS also produces this) hashes
	// with SHA-256. Signature bytes are X9.62/DER encoded.
	digest := sha256sum(challenge)
	return ecdsa.SignASN1(rand.Reader, s.priv, digest)
}
func (s *fileP256Store) Extractable() bool { return true }
func (s *fileP256Store) StorageDescription() string {
	return fmt.Sprintf("file: %s (p256, EXPLICIT OPT-IN — extractable)", s.path)
}
func (s *fileP256Store) SharedSecret(peerPub []byte) ([]byte, error) {
	// Move the ecdsa.PrivateKey into an ecdh.PrivateKey and let
	// crypto/ecdh do the curve arithmetic + point-on-curve checks.
	// crypto/ecdh's P256().NewPrivateKey takes the scalar as
	// big-endian 32B; ecdsa.PrivateKey.D is a *big.Int we can format.
	scalar := s.priv.D.FillBytes(make([]byte, 32))
	ecdhPriv, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		return nil, fmt.Errorf("agentkey/file: ecdh priv from ecdsa: %w", err)
	}
	ecdhPub, err := ecdh.P256().NewPublicKey(peerPub)
	if err != nil {
		return nil, fmt.Errorf("agentkey/file: peer pubkey: %w", err)
	}
	return ecdhPriv.ECDH(ecdhPub)
}

// sha256sum returns the SHA-256 digest of b. Kept unexported so the
// Sign implementation is self-contained.
func sha256sum(b []byte) []byte {
	sum := sha256Sum(b)
	return sum[:]
}
