// Signing / verification of capability records with ed25519.
//
// Every capability record in the vault carries a signature over its
// canonical form (JSON with sorted keys). The admin's private ed25519 key
// signs at issuance; every consumer verifies before trusting the record.
//
// This is what stops:
//   - A malicious re-encryption of the vault by a non-admin who somehow
//     obtained a decrypt key (edge case — shouldn't happen in v1 since
//     only admins have age keys, but defense in depth).
//   - Git rollback: an old capability record replayed after a revoke has
//     the same admin signature, but its generation is stale — detected
//     by the generation cache in the consumer.
//   - Bundle-file swap: if someone replaces `<lookup_id>.bundle` with a
//     valid-but-different bundle, the bundle_hash in the (signed) record
//     no longer matches.

package capability

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"
)

// Record is the vault-side metadata for one issued capability.
// Fields with `json:"-"` are computed / injected at load time.
type Record struct {
	CapabilityID string         `json:"capability_id"` // hex of the raw 32-byte id
	Subject      string         `json:"subject"`       // human label
	Grants       []string       `json:"grants"`        // grant ids
	CreatedAt    time.Time      `json:"created_at"`
	ExpiresAt    time.Time      `json:"expires_at"`
	RevokedAt    time.Time      `json:"revoked_at,omitempty"` // set when status becomes revoked; zero on older records
	Generation   uint64         `json:"generation"`
	LookupID     string         `json:"lookup_id"`   // 40-hex bundle filename
	BundleHash   string         `json:"bundle_hash"` // sha256 hex of bundle file
	IssuedBy     string         `json:"issued_by"`   // ed25519 pubkey hex
	Status       string         `json:"status"`      // "active" | "revoked"
	Binding      *RecordBinding `json:"binding,omitempty"`

	// v1.12 — env resolved from Grants, sealed to the agent's P-256
	// pubkey via ECDH. Present ⇒ dop exec MUST prefer this over the
	// bundle env (loud failure if it can't open — no silent
	// downgrade). Absent ⇒ legacy bundle-env path (used by ed25519
	// bearers and by P-256 bearers issued before v1.12).
	EnvWrapped *WrappedEnv `json:"env_wrapped,omitempty"`

	// v1.12 — replacement bearer sealed to the agent's P-256 pubkey.
	// Written when admin runs `dop token rotate <tok>`. Agent's next
	// dop exec decrypts, atomically replaces the on-disk bearer, and
	// proceeds with the new one. Absent ⇒ no rotation pending.
	BearerWrapped *WrappedBearer `json:"bearer_wrapped,omitempty"`

	// Signature over the canonical form of every other field. Excluded
	// from that canonical form during signing/verification.
	Signature string `json:"signature"`
}

// WrappedEnv is the envseal.Sealed output plus the generation it
// commits to. Fields are hex-encoded to match the rest of the
// codebase's on-disk format (bundle_hash, signature, ...).
//
// Generation is the record.Generation at the time this envelope was
// sealed. On open, the agent's dop exec MUST verify Generation
// matches record.Generation; a mismatch means someone glued a stale
// envelope to a fresher record (git rollback attack). Also included
// under the AEAD's AAD so a bit-flip in either place fails auth.
type WrappedEnv struct {
	AdminEphemPub string    `json:"admin_ephem_pub"` // hex, 65B uncompressed X9.62
	Salt          string    `json:"salt"`            // hex, 32B
	Nonce         string    `json:"nonce"`           // hex, 24B (XChaCha20)
	Ciphertext    string    `json:"ciphertext"`      // hex, encrypts JSON({"env": {..}})
	SealedAt      time.Time `json:"sealed_at"`
	Generation    uint64    `json:"generation"`
}

// WrappedBearer wraps a rotation payload sealed to the agent's
// P-256 pubkey. The AEAD-encrypted ciphertext holds JSON of the
// form:
//
//	{"bearer": "tok_1...", "lookup_id": "<hex>"}
//
// so the agent, after opening, has everything it needs to switch:
// the new bearer to auth with, and the new lookup id to find the
// fresh record + bundle. NewGeneration is the record.Generation
// bumped at rotation time — used in AAD to prevent envelope
// splicing across generations.
type WrappedBearer struct {
	AdminEphemPub string    `json:"admin_ephem_pub"`
	Salt          string    `json:"salt"`
	Nonce         string    `json:"nonce"`
	Ciphertext    string    `json:"ciphertext"`
	SealedAt      time.Time `json:"sealed_at"`
	NewGeneration uint64    `json:"new_generation"`
}

// RecordBinding is the vault-side view. Mirrors vault.Binding but lives
// in the capability package to avoid cyclic imports.
type RecordBinding struct {
	Kind      string    `json:"kind"`
	PinExpiry time.Time `json:"pin_expiry,omitempty"`
	Pubkey    string    `json:"pubkey,omitempty"`
	KeyType   string    `json:"key_type,omitempty"` // v1.11 — ed25519 (default) or p256
	ClaimedAt time.Time `json:"claimed_at,omitempty"`
}

const RecordStatusActive = "active"
const RecordStatusRevoked = "revoked"

// RecordStatusRotated marks a record whose bearer has been rotated
// via `dop token rotate`. Its BearerWrapped field carries the new
// bearer (sealed to the agent's P-256 pubkey) plus the new lookup
// id where the fresh record lives. An agent exec against a
// rotated bearer decrypts BearerWrapped, migrates its SE tag, and
// switches to the new bearer.
const RecordStatusRotated = "rotated"

// SigningPayload returns the deterministic byte sequence that a signer
// signs and a verifier verifies. It's a JSON serialization of the record
// with the Signature field omitted and keys in a fixed order.
func (r Record) SigningPayload() ([]byte, error) {
	// Build a plain map so we can control field ordering + exclusion.
	m := map[string]any{
		"capability_id": r.CapabilityID,
		"subject":       r.Subject,
		"grants":        r.Grants,
		"created_at":    r.CreatedAt.UTC().Format(time.RFC3339Nano),
		"expires_at":    r.ExpiresAt.UTC().Format(time.RFC3339Nano),
		"generation":    r.Generation,
		"lookup_id":     r.LookupID,
		"bundle_hash":   r.BundleHash,
		"issued_by":     r.IssuedBy,
		"status":        r.Status,
	}
	// Only when set, so records signed before revoked_at existed verify.
	if !r.RevokedAt.IsZero() {
		m["revoked_at"] = r.RevokedAt.UTC().Format(time.RFC3339Nano)
	}
	// Include binding only when set — pre-v1.3 records signed without it
	// still verify.
	if r.Binding != nil {
		bindingMap := map[string]any{
			"kind": r.Binding.Kind,
		}
		if !r.Binding.PinExpiry.IsZero() {
			bindingMap["pin_expiry"] = r.Binding.PinExpiry.UTC().Format(time.RFC3339Nano)
		}
		if r.Binding.Pubkey != "" {
			bindingMap["pubkey"] = r.Binding.Pubkey
		}
		// NOTE: r.Binding.KeyType is intentionally excluded from the
		// signing payload for backward compatibility with v1.11
		// records. Adding it here would invalidate every P-256 record
		// signed pre-v1.12. Key type is protected instead by the
		// signature over IssuedBy + BundleHash — the agent's pubkey is
		// what gets attacked in a type-confusion scenario, and that
		// pubkey IS covered indirectly via the bundle hash's
		// dependency on binding fields at issue time.
		if !r.Binding.ClaimedAt.IsZero() {
			bindingMap["claimed_at"] = r.Binding.ClaimedAt.UTC().Format(time.RFC3339Nano)
		}
		m["binding"] = bindingMap
	}
	// v1.12 — the wrapped envelopes are covered by the record signature
	// so tampering with them (or splicing them onto a different record)
	// breaks verification.
	if r.EnvWrapped != nil {
		m["env_wrapped"] = map[string]any{
			"admin_ephem_pub": r.EnvWrapped.AdminEphemPub,
			"salt":            r.EnvWrapped.Salt,
			"nonce":           r.EnvWrapped.Nonce,
			"ciphertext":      r.EnvWrapped.Ciphertext,
			"sealed_at":       r.EnvWrapped.SealedAt.UTC().Format(time.RFC3339Nano),
			"generation":      r.EnvWrapped.Generation,
		}
	}
	if r.BearerWrapped != nil {
		m["bearer_wrapped"] = map[string]any{
			"admin_ephem_pub": r.BearerWrapped.AdminEphemPub,
			"salt":            r.BearerWrapped.Salt,
			"nonce":           r.BearerWrapped.Nonce,
			"ciphertext":      r.BearerWrapped.Ciphertext,
			"sealed_at":       r.BearerWrapped.SealedAt.UTC().Format(time.RFC3339Nano),
			"new_generation":  r.BearerWrapped.NewGeneration,
		}
	}
	// Deterministic key order.
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	// Manual JSON to control ordering. encoding/json sorts map keys
	// alphabetically since Go 1.12, so this is somewhat redundant, but
	// explicit is better than implicit here.
	buf := []byte{'{'}
	for i, k := range keys {
		if i > 0 {
			buf = append(buf, ',')
		}
		kb, _ := json.Marshal(k)
		buf = append(buf, kb...)
		buf = append(buf, ':')
		vb, err := json.Marshal(m[k])
		if err != nil {
			return nil, err
		}
		buf = append(buf, vb...)
	}
	buf = append(buf, '}')
	return buf, nil
}

// Sign signs the record with the given ed25519 private key. Mutates
// r.Signature and r.IssuedBy.
func (r *Record) Sign(priv ed25519.PrivateKey) error {
	if len(priv) != ed25519.PrivateKeySize {
		return errors.New("bad ed25519 private key size")
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("ed25519 private key has no public")
	}
	r.IssuedBy = hex.EncodeToString(pub)
	r.Signature = "" // exclude old sig from payload
	payload, err := r.SigningPayload()
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, payload)
	r.Signature = hex.EncodeToString(sig)
	return nil
}

// Verify checks the record's signature against the pubkey embedded in
// IssuedBy. The caller MUST separately confirm IssuedBy is a trusted
// admin (via a stored admins list in the vault) — Verify only proves
// the record wasn't tampered since it was signed by whoever holds
// IssuedBy's private key.
func (r Record) Verify() error {
	if r.Signature == "" {
		return errors.New("record has no signature")
	}
	if r.IssuedBy == "" {
		return errors.New("record has no issued_by pubkey")
	}
	pubBytes, err := hex.DecodeString(r.IssuedBy)
	if err != nil {
		return fmt.Errorf("issued_by not hex: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("issued_by pubkey size %d != %d", len(pubBytes), ed25519.PublicKeySize)
	}
	sig, err := hex.DecodeString(r.Signature)
	if err != nil {
		return fmt.Errorf("signature not hex: %w", err)
	}
	// Rebuild the payload from the record with Signature blanked.
	blanked := r
	blanked.Signature = ""
	payload, err := blanked.SigningPayload()
	if err != nil {
		return err
	}
	if !ed25519.Verify(pubBytes, payload, sig) {
		return errors.New("signature verify failed")
	}
	return nil
}

// HashBundle returns the sha256 hex of raw bundle bytes. The record's
// BundleHash MUST equal this at verification time.
func HashBundle(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
