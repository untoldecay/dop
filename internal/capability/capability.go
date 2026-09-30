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

// EnvBundle is the payload — a map of env-var name → value plus enough
// metadata for the bearer-holder to identify what they hold.
type EnvBundle struct {
	Env     map[string]string `json:"env"`
	Subject string            `json:"subject,omitempty"`
	// Duplicate of the outer header for defense-in-depth. The outer
	// carries the same generation and expires_at; decryption checks
	// they match.
	Generation    uint64 `json:"generation"`
	ExpiresAtUnix int64  `json:"expires_at_unix"`
	// Binding — v1.3.0. Present when the capability is bound to an
	// agent identity (PIN-claim or admin-supplied pubkey).
	Binding *EnvelopeBinding `json:"binding,omitempty"`
}

// EnvelopeBinding is the binding view inside a bundle envelope. It's
// bearer-locked (only the bearer holder can read it), which is exactly
// who should be able to see the PIN hash to verify a claim attempt.
//
// PinHash is HMAC-SHA256(bearer, pin_normalized), hex-encoded. Binding
// the PIN hash to the bearer means a stolen bundle without a bearer is
// useless AND the hash can't be pre-computed by rainbow tables.
type EnvelopeBinding struct {
	Kind      string `json:"kind"`
	PinHash   string `json:"pin_hash,omitempty"`
	PinExpiry int64  `json:"pin_expiry,omitempty"`
	Pubkey    string `json:"pubkey,omitempty"`
	// v1.11 — KeyType mirrors vault.Binding.KeyType so exec-time
	// verification can pick the right signature scheme without loading
	// the vault. Absent field → "ed25519" for legacy records.
	KeyType string `json:"key_type,omitempty"`
}

// WriteOpts configures Write.
type WriteOpts struct {
	CapabilityID [CapabilityIDBytes]byte
	Bearer       string    // bearer, will not be stored
	Generation   uint64
	ExpiresAt    time.Time // written as unix seconds
	Subject      string    // human label for whoami — encrypted inside
	Env          map[string]string
	// Binding, if set, is written into the envelope so the bearer holder
	// can verify PIN claims and/or authenticated exec.
	Binding *EnvelopeBinding
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
		Subject:       opts.Subject,
		Generation:    opts.Generation,
		ExpiresAtUnix: opts.ExpiresAt.Unix(),
		Binding:       opts.Binding,
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

// pinAlphabet is 24 uppercase letters with confusables removed (I, L, O
// dropped). Numbers are excluded so PINs are unambiguously letters when
// spoken. 24^6 ≈ 191M possibilities — plenty for a 5-min claim window
// under rate limiting.
const pinAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ"

// NewPIN returns a fresh 6-letter PIN formatted as `XX-XX-XX`.
func NewPIN() (string, error) {
	buf := make([]byte, 6)
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", err
	}
	out := make([]byte, 8)
	for i, b := range buf {
		c := pinAlphabet[int(b)%len(pinAlphabet)]
		switch i {
		case 0, 1:
			out[i] = c
		case 2, 3:
			out[i+1] = c
		case 4, 5:
			out[i+2] = c
		}
	}
	out[2] = '-'
	out[5] = '-'
	return string(out), nil
}

// NormalizePIN uppercases and strips non-alphabet chars, letting users
// re-enter a PIN with lowercase or different separators.
func NormalizePIN(pin string) string {
	buf := make([]byte, 0, len(pin))
	for i := 0; i < len(pin); i++ {
		c := pin[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		if c >= 'A' && c <= 'Z' {
			buf = append(buf, c)
		}
	}
	return string(buf)
}

// HashPIN returns HMAC-SHA256(bearer, normalized(pin)) hex-encoded.
// The bearer-keyed HMAC prevents rainbow-table precomputation and ties
// verifiability to bundle possession.
func HashPIN(bearer, pin string) string {
	norm := NormalizePIN(pin)
	mac := hmac.New(sha256.New, []byte(bearer))
	mac.Write([]byte(norm))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyPIN is a constant-time compare of HashPIN against the stored hash.
func VerifyPIN(bearer, pin, storedHex string) bool {
	got := HashPIN(bearer, pin)
	return hmac.Equal([]byte(got), []byte(storedHex))
}
