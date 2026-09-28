// Package capability implements the v1 credential-delivery envelope.
//
// The design goal: agent machines never decrypt the vault. Admins produce
// small "capability" bundles — one per issued bearer — that carry only the
// specific env vars that bearer's grants unlock. Agents consume bundles
// with their bearer; the vault stays sealed.
//
// See ARCHITECTURE.md for the two-plane model and the honest threat model.
//
// Envelope format (binary, all little-endian):
//
//	[0..4)     magic         = "DOPB"
//	[4..8)     version       = uint32 1
//	[8..40)    capability_id = 32 bytes (raw id, the "cap_XXX" without the prefix)
//	[40..48)   generation    = uint64
//	[48..56)   expires_at    = int64 unix seconds
//	[56..80)   nonce         = 24 bytes (random per encryption)
//	[80..128)  wrapped_key   = 48 bytes (AEAD-wrapped K_bundle: 32B key + 16B tag)
//	[128..)    ciphertext    = AEAD(K_bundle, env-bundle JSON) + tag
//
// Cryptographic details:
//   K_wrap   = HKDF-SHA256(IKM=bearer, salt="dop-v1-wrap", info="cap:"||capability_id)
//   K_bundle = 32 random bytes (fresh per issuance)
//   AEAD     = ChaCha20-Poly1305
//   AAD      = capability_id (32B) || generation (8B LE) || expires_at (8B LE)
//
// The bearer is never stored in the bundle. Recovering the env requires
// possession of the bearer at read time.
package capability

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

// Version is the current envelope version. Bumps require a versioned
// migration path.
const Version uint32 = 1

// Magic is the four-byte header identifying a DOP bundle file.
var Magic = [4]byte{'D', 'O', 'P', 'B'}

// Sizes — fixed offsets keep envelope parsing constant-time and portable.
const (
	CapabilityIDBytes = 32
	NonceBytes        = 24
	KeyBytes          = 32
	TagBytes          = 16
	WrappedKeyBytes   = KeyBytes + TagBytes // 48
	MinBundleBytes    = 4 + 4 + CapabilityIDBytes + 8 + 8 + NonceBytes + WrappedKeyBytes
	// = 128 fixed header + at least one AEAD block of ciphertext
)

// BundleHeader is the fixed prefix of every capability bundle.
type BundleHeader struct {
	Magic         [4]byte
	Version       uint32
	CapabilityID  [CapabilityIDBytes]byte
	Generation    uint64
	ExpiresAtUnix int64
	Nonce         [NonceBytes]byte
	WrappedKey    [WrappedKeyBytes]byte
}

// EnvBundle is the payload — a map of env-var name → value. Marshaled as
// JSON before encryption. Callers reading with ReadBundle receive this
// after successful decryption.
type EnvBundle struct {
	Env map[string]string `json:"env"`
	// Additional metadata carried inside the ciphertext for
	// defense-in-depth. The outer header carries the same generation and
	// expires_at, which must match on decrypt.
	Generation    uint64 `json:"generation"`
	ExpiresAtUnix int64  `json:"expires_at_unix"`
}

// WriteOpts configures Write.
type WriteOpts struct {
	CapabilityID [CapabilityIDBytes]byte
	Bearer       string    // bearer, will not be stored
	Generation   uint64
	ExpiresAt    time.Time // written as unix seconds
	Env          map[string]string
	// Rand is the entropy source. nil → crypto/rand.
	Rand io.Reader
}

// Write serializes and encrypts an EnvBundle to `w`. Returns the raw
// bytes it wrote for callers that also want to compute a bundle hash.
func Write(w io.Writer, opts WriteOpts) ([]byte, error) {
	if opts.Bearer == "" {
		return nil, errors.New("capability.Write: bearer is required")
	}
	if len(opts.Env) == 0 {
		return nil, errors.New("capability.Write: env is empty")
	}
	if opts.ExpiresAt.IsZero() {
		return nil, errors.New("capability.Write: expires_at is required")
	}
	randSrc := opts.Rand
	if randSrc == nil {
		randSrc = rand.Reader
	}

	var nonce [NonceBytes]byte
	if _, err := io.ReadFull(randSrc, nonce[:]); err != nil {
		return nil, fmt.Errorf("nonce: %w", err)
	}
	var kBundle [KeyBytes]byte
	if _, err := io.ReadFull(randSrc, kBundle[:]); err != nil {
		return nil, fmt.Errorf("bundle key: %w", err)
	}

	kWrap, err := deriveWrapKey(opts.Bearer, opts.CapabilityID)
	if err != nil {
		return nil, err
	}

	aad := associatedData(opts.CapabilityID, opts.Generation, opts.ExpiresAt.Unix())

	// Wrap K_bundle. AEAD requires a nonce; we reuse the outer nonce.
	// K_wrap is only used once per issuance (fresh capability id) so nonce
	// reuse across capabilities is not a concern.
	wrapCipher, err := chacha20poly1305.NewX(kWrap[:])
	if err != nil {
		return nil, err
	}
	wrappedKey := wrapCipher.Seal(nil, nonce[:], kBundle[:], aad)
	if len(wrappedKey) != WrappedKeyBytes {
		return nil, fmt.Errorf("wrapped key size %d, want %d", len(wrappedKey), WrappedKeyBytes)
	}

	// Encrypt env payload.
	payload := EnvBundle{
		Env:           opts.Env,
		Generation:    opts.Generation,
		ExpiresAtUnix: opts.ExpiresAt.Unix(),
	}
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	envCipher, err := chacha20poly1305.NewX(kBundle[:])
	if err != nil {
		return nil, err
	}
	// Separate nonce for env encryption (bump the wrap nonce by one byte;
	// still deterministic per issuance because opts.CapabilityID is unique).
	var envNonce [NonceBytes]byte
	copy(envNonce[:], nonce[:])
	envNonce[0] ^= 0x01
	ciphertext := envCipher.Seal(nil, envNonce[:], plaintext, aad)

	hdr := BundleHeader{
		Magic:         Magic,
		Version:       Version,
		CapabilityID:  opts.CapabilityID,
		Generation:    opts.Generation,
		ExpiresAtUnix: opts.ExpiresAt.Unix(),
		Nonce:         nonce,
	}
	copy(hdr.WrappedKey[:], wrappedKey)

	buf, err := marshalHeader(hdr)
	if err != nil {
		return nil, err
	}
	buf = append(buf, ciphertext...)
	if _, err := w.Write(buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// ReadOpts configures Read.
type ReadOpts struct {
	Bearer string    // bearer, needed to unwrap K_bundle
	Now    time.Time // clock, defaults to time.Now()
	// MinGeneration lets callers reject rollback replays. Bundles with
	// Generation < MinGeneration are rejected as "superseded".
	MinGeneration uint64
}

// Read parses and decrypts a bundle from `data`. Returns the plaintext env
// bundle plus the header (so callers can access expiry, generation, etc).
func Read(data []byte, opts ReadOpts) (*EnvBundle, *BundleHeader, error) {
	if opts.Bearer == "" {
		return nil, nil, errors.New("capability.Read: bearer is required")
	}
	if len(data) < MinBundleBytes {
		return nil, nil, fmt.Errorf("bundle too short: %d < %d", len(data), MinBundleBytes)
	}

	hdr, err := unmarshalHeader(data[:headerSize()])
	if err != nil {
		return nil, nil, err
	}
	if hdr.Magic != Magic {
		return nil, nil, errors.New("bad magic (not a DOP bundle)")
	}
	if hdr.Version != Version {
		return nil, nil, fmt.Errorf("unsupported bundle version %d (this build handles %d)", hdr.Version, Version)
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	expiresAt := time.Unix(hdr.ExpiresAtUnix, 0)
	if now.After(expiresAt) {
		return nil, hdr, fmt.Errorf("bundle expired at %s", expiresAt.UTC().Format(time.RFC3339))
	}
	if hdr.Generation < opts.MinGeneration {
		return nil, hdr, fmt.Errorf("bundle superseded (gen %d < min %d)", hdr.Generation, opts.MinGeneration)
	}

	aad := associatedData(hdr.CapabilityID, hdr.Generation, hdr.ExpiresAtUnix)

	kWrap, err := deriveWrapKey(opts.Bearer, hdr.CapabilityID)
	if err != nil {
		return nil, hdr, err
	}
	wrapCipher, err := chacha20poly1305.NewX(kWrap[:])
	if err != nil {
		return nil, hdr, err
	}
	kBundle, err := wrapCipher.Open(nil, hdr.Nonce[:], hdr.WrappedKey[:], aad)
	if err != nil {
		return nil, hdr, fmt.Errorf("unwrap key: %w (wrong bearer, or bundle tampered)", err)
	}
	if len(kBundle) != KeyBytes {
		return nil, hdr, fmt.Errorf("unwrapped key size %d, want %d", len(kBundle), KeyBytes)
	}
	envCipher, err := chacha20poly1305.NewX(kBundle)
	if err != nil {
		return nil, hdr, err
	}
	var envNonce [NonceBytes]byte
	copy(envNonce[:], hdr.Nonce[:])
	envNonce[0] ^= 0x01
	ciphertext := data[headerSize():]
	plaintext, err := envCipher.Open(nil, envNonce[:], ciphertext, aad)
	if err != nil {
		return nil, hdr, fmt.Errorf("decrypt env: %w (bundle tampered)", err)
	}

	var payload EnvBundle
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, hdr, fmt.Errorf("payload json: %w", err)
	}
	// Defense in depth: inner metadata must match outer header.
	if payload.Generation != hdr.Generation || payload.ExpiresAtUnix != hdr.ExpiresAtUnix {
		return nil, hdr, errors.New("inner/outer metadata mismatch (bundle rewritten)")
	}
	return &payload, hdr, nil
}

// --- internal helpers ---

func headerSize() int {
	return 4 + 4 + CapabilityIDBytes + 8 + 8 + NonceBytes + WrappedKeyBytes
}

func marshalHeader(h BundleHeader) ([]byte, error) {
	buf := make([]byte, 0, headerSize())
	buf = append(buf, h.Magic[:]...)
	buf = binary.LittleEndian.AppendUint32(buf, h.Version)
	buf = append(buf, h.CapabilityID[:]...)
	buf = binary.LittleEndian.AppendUint64(buf, h.Generation)
	buf = binary.LittleEndian.AppendUint64(buf, uint64(h.ExpiresAtUnix))
	buf = append(buf, h.Nonce[:]...)
	buf = append(buf, h.WrappedKey[:]...)
	return buf, nil
}

func unmarshalHeader(b []byte) (*BundleHeader, error) {
	if len(b) < headerSize() {
		return nil, fmt.Errorf("header too short: %d", len(b))
	}
	var h BundleHeader
	copy(h.Magic[:], b[0:4])
	h.Version = binary.LittleEndian.Uint32(b[4:8])
	copy(h.CapabilityID[:], b[8:8+CapabilityIDBytes])
	off := 8 + CapabilityIDBytes
	h.Generation = binary.LittleEndian.Uint64(b[off : off+8])
	off += 8
	h.ExpiresAtUnix = int64(binary.LittleEndian.Uint64(b[off : off+8]))
	off += 8
	copy(h.Nonce[:], b[off:off+NonceBytes])
	off += NonceBytes
	copy(h.WrappedKey[:], b[off:off+WrappedKeyBytes])
	return &h, nil
}

// deriveWrapKey derives K_wrap from the bearer + capability id using HKDF.
// Domain-separation constants avoid accidental key reuse across contexts.
func deriveWrapKey(bearer string, capID [CapabilityIDBytes]byte) ([KeyBytes]byte, error) {
	var out [KeyBytes]byte
	salt := []byte("dop-v1-wrap")
	info := append([]byte("cap:"), capID[:]...)
	r := hkdf.New(sha256.New, []byte(bearer), salt, info)
	if _, err := io.ReadFull(r, out[:]); err != nil {
		return out, err
	}
	return out, nil
}

// associatedData is the AEAD AAD for both the wrap and the payload encryption.
// Binding metadata into AEAD ensures an attacker can't swap a bundle's
// expires_at or generation and re-use the ciphertext.
func associatedData(capID [CapabilityIDBytes]byte, gen uint64, expUnix int64) []byte {
	aad := make([]byte, 0, CapabilityIDBytes+16)
	aad = append(aad, capID[:]...)
	aad = binary.LittleEndian.AppendUint64(aad, gen)
	aad = binary.LittleEndian.AppendUint64(aad, uint64(expUnix))
	return aad
}

// --- bearer + capability id helpers ---

// NewBearer generates a v1 bearer: `tok_1<32-hex>` = 128 bits of entropy.
func NewBearer() (string, error) {
	var b [16]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", err
	}
	return "tok_1" + hex.EncodeToString(b[:]), nil
}

// NewCapabilityID generates a random 32-byte capability identifier.
func NewCapabilityID() ([CapabilityIDBytes]byte, error) {
	var id [CapabilityIDBytes]byte
	if _, err := io.ReadFull(rand.Reader, id[:]); err != nil {
		return id, err
	}
	return id, nil
}

// LookupID computes the sync-safe identifier used as the bundle filename.
// vaultContext is a per-vault random salt stored (unencrypted) in the vault
// repo. Knowing lookup_id does not reveal the bearer.
func LookupID(vaultContext []byte, bearer string) string {
	mac := hmac.New(sha256.New, vaultContext)
	mac.Write([]byte(bearer))
	sum := mac.Sum(nil)
	return hex.EncodeToString(sum[:20]) // 40-char filename
}
