// Package admininvite implements the git-mediated admin bootstrap
// flow. Symmetric to internal/remoteclaim but for adding a NEW admin
// device to the vault rather than binding an agent bearer.
//
// Flow:
//  1. Existing admin M1 runs `dop team invite --name <label>`.
//     Generates a PIN + invite record, commits + pushes to
//     <Vault>/pending-admin-invites/<invite_id>.invite.json, then
//     polls the vault waiting for a matching response.
//  2. New machine M2 runs `dop admin join <URL> <PIN>`. Runs
//     `admin init` inline if no key exists, clones the vault, verifies
//     the PIN, signs a response with its fresh ed25519 key, writes
//     <invite_id>.response.json + pushes. Then polls waiting for the
//     vault to be re-encrypted for its recipient.
//  3. M1's poll loop notices the response, verifies the signature
//     (proves M2 holds the private key), prompts M1 admin for the
//     approval passphrase, and — on correct passphrase — runs the
//     existing `team add-key` path to register M2 as an admin.
//     Deletes both files, commits + pushes.
//  4. M2's poll loop sees itself in admins.trust, exits success.
//
// Wire artifacts (all in the vault repo, committed to `main`):
//   pending-admin-invites/<invite_id>.invite.json    (M1 writes)
//   pending-admin-invites/<invite_id>.response.json  (M2 writes)
package admininvite

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"

	"github.com/fray/dop/internal/config"
)

// TTL is how long an invite sits open before it's considered abandoned.
const TTL = 30 * time.Minute

// Invite is what M1 writes when it opens an invitation.
type Invite struct {
	InviteID     string    `json:"invite_id"`     // 16-hex, filename anchor
	Name         string    `json:"name"`          // human label for the new admin
	PinHash      string    `json:"pin_hash"`      // HMAC-SHA256(invite_id, normalize(PIN)) hex
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedByPub string    `json:"created_by_pub"` // M1's ed25519 pubkey (audit)
	Kind         string    `json:"kind,omitempty"` // "device" or "team_member" (cosmetic)
	// ShareIdentity (v1.9.3 — Flavor Y): when true, M1 also stages a
	// PIN-encrypted blob (see IdentityBlobPath) carrying its wrapped
	// admin key + approval hash. M2 installs those instead of generating
	// its own → SAME admin, one entry, one revocation surface across
	// devices. Only sensible for "another of MY devices"; NOT for
	// teammates.
	ShareIdentity bool `json:"share_identity,omitempty"`
}

// IdentityBlobPath is where M1 stages the encrypted admin-identity
// bundle when ShareIdentity=true. Empty when the invite is per-device.
func IdentityBlobPath(paths *config.Paths, id string) string {
	return filepath.Join(dirPath(paths), id+".identity-blob")
}

// EncryptIdentityBlob wraps (adminKeyBytes, approvalHashBytes) with
// XChaCha20-Poly1305 using a key derived from (PIN, invite_id) via
// argon2id. Format: nonce(24) || ciphertext.
func EncryptIdentityBlob(pin, inviteID string, adminKey, approvalHash []byte) ([]byte, error) {
	blob := struct {
		AdminKey     []byte `json:"admin_key"`
		ApprovalHash []byte `json:"approval_hash"`
	}{AdminKey: adminKey, ApprovalHash: approvalHash}
	plain, err := json.Marshal(blob)
	if err != nil {
		return nil, err
	}
	key := deriveBlobKey(pin, inviteID)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, nonce, plain, []byte(inviteID))
	return append(nonce, ct...), nil
}

// DecryptIdentityBlob is the reverse — M2 runs this after fetching the
// blob and reading the PIN from the caller.
func DecryptIdentityBlob(pin, inviteID string, blob []byte) (adminKey, approvalHash []byte, err error) {
	if len(blob) < 24 {
		return nil, nil, errors.New("identity blob: too short")
	}
	key := deriveBlobKey(pin, inviteID)
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, nil, err
	}
	nonce := blob[:aead.NonceSize()]
	ct := blob[aead.NonceSize():]
	plain, err := aead.Open(nil, nonce, ct, []byte(inviteID))
	if err != nil {
		return nil, nil, fmt.Errorf("identity blob: decrypt (wrong PIN?): %w", err)
	}
	var out struct {
		AdminKey     []byte `json:"admin_key"`
		ApprovalHash []byte `json:"approval_hash"`
	}
	if err := json.Unmarshal(plain, &out); err != nil {
		return nil, nil, err
	}
	return out.AdminKey, out.ApprovalHash, nil
}

// deriveBlobKey — argon2id(pin, salt=invite_id, t=3, m=64MiB, p=4, len=32).
// Same cost profile as the approval passphrase gate.
func deriveBlobKey(pin, inviteID string) []byte {
	return argon2.IDKey([]byte(normalizePIN(pin)), []byte(inviteID), 3, 64*1024, 4, 32)
}

// Response is what M2 writes to complete the handshake.
type Response struct {
	InviteID      string    `json:"invite_id"`
	Ed25519Pubkey string    `json:"ed25519_pubkey"` // hex
	AgeRecipient  string    `json:"age_recipient"`  // age1...
	Host          string    `json:"host"`
	RespondedAt   time.Time `json:"responded_at"`
	Signature     string    `json:"signature"`      // hex ed25519 sig by Ed25519Pubkey
}

// dirPath returns the pending-admin-invites directory (committed).
func dirPath(paths *config.Paths) string {
	return filepath.Join(paths.Vault, "pending-admin-invites")
}

// EnsureDir creates it mode 0755 (files are committed).
func EnsureDir(paths *config.Paths) error {
	return os.MkdirAll(dirPath(paths), 0o755)
}

// InvitePath / ResponsePath resolve the two files for one invite_id.
func InvitePath(paths *config.Paths, id string) string {
	return filepath.Join(dirPath(paths), id+".invite.json")
}
func ResponsePath(paths *config.Paths, id string) string {
	return filepath.Join(dirPath(paths), id+".response.json")
}

// NewInviteID returns a fresh 16-hex random identifier.
func NewInviteID() (string, error) {
	var b [8]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// HashPIN returns HMAC-SHA256(invite_id, normalize(pin)) hex. Using
// the invite_id as the HMAC key means the same PIN in two different
// invites produces different hashes, preventing cross-invite matching.
func HashPIN(inviteID, pin string) string {
	mac := hmac.New(sha256.New, []byte(inviteID))
	mac.Write([]byte(normalizePIN(pin)))
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyPIN is constant-time.
func VerifyPIN(inviteID, pin, storedHex string) bool {
	got := HashPIN(inviteID, pin)
	return hmac.Equal([]byte(got), []byte(storedHex))
}

// normalizePIN uppercases and strips separators — same rules as the
// capability PIN so users can type either format interchangeably.
func normalizePIN(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'a' && c <= 'z' {
			c -= 32
		}
		if c >= 'A' && c <= 'Z' {
			out = append(out, c)
		}
	}
	return string(out)
}

// --- Response signing ---

// signingPayload returns the deterministic byte sequence M2 signs.
func signingPayload(r Response) ([]byte, error) {
	r.Signature = ""
	return json.Marshal(struct {
		InviteID      string `json:"invite_id"`
		Ed25519Pubkey string `json:"ed25519_pubkey"`
		AgeRecipient  string `json:"age_recipient"`
		Host          string `json:"host"`
		RespondedAt   string `json:"responded_at"`
	}{
		InviteID:      r.InviteID,
		Ed25519Pubkey: r.Ed25519Pubkey,
		AgeRecipient:  r.AgeRecipient,
		Host:          r.Host,
		RespondedAt:   r.RespondedAt.UTC().Format(time.RFC3339Nano),
	})
}

// Sign attaches an ed25519 signature to the response using priv.
func (r *Response) Sign(priv ed25519.PrivateKey) error {
	payload, err := signingPayload(*r)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(priv, payload)
	r.Signature = hex.EncodeToString(sig)
	return nil
}

// Verify checks the signature against the embedded Ed25519Pubkey.
// The caller must ALSO verify that this pubkey is the one the operator
// actually wants to admit — that's the passphrase-gated approval step.
func (r Response) Verify() error {
	if r.Signature == "" {
		return errors.New("admin invite: response has no signature")
	}
	pubBytes, err := hex.DecodeString(r.Ed25519Pubkey)
	if err != nil {
		return fmt.Errorf("admin invite: bad pubkey hex: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("admin invite: pubkey wrong size %d", len(pubBytes))
	}
	sig, err := hex.DecodeString(r.Signature)
	if err != nil {
		return fmt.Errorf("admin invite: bad sig hex: %w", err)
	}
	payload, err := signingPayload(r)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pubBytes, payload, sig) {
		return errors.New("admin invite: signature does not verify")
	}
	return nil
}

// --- IO ---

// WriteInvite serializes an Invite atomically.
func WriteInvite(paths *config.Paths, inv Invite) error {
	if err := EnsureDir(paths); err != nil {
		return err
	}
	return writeJSON(InvitePath(paths, inv.InviteID), inv)
}

// WriteResponse serializes a Response atomically.
func WriteResponse(paths *config.Paths, r Response) error {
	if err := EnsureDir(paths); err != nil {
		return err
	}
	return writeJSON(ResponsePath(paths, r.InviteID), r)
}

// ReadInvite loads one invite by ID.
func ReadInvite(paths *config.Paths, id string) (*Invite, error) {
	var inv Invite
	if err := readJSON(InvitePath(paths, id), &inv); err != nil {
		return nil, err
	}
	return &inv, nil
}

// ReadResponse loads one response by invite ID.
func ReadResponse(paths *config.Paths, id string) (*Response, error) {
	var r Response
	if err := readJSON(ResponsePath(paths, id), &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// FindByPIN scans all invites, returns the first whose PIN matches.
// Runs on the joining machine (M2) after cloning the vault.
func FindByPIN(paths *config.Paths, pin string) (*Invite, error) {
	all, err := ListInvites(paths)
	if err != nil {
		return nil, err
	}
	for _, inv := range all {
		if VerifyPIN(inv.InviteID, pin, inv.PinHash) {
			return inv, nil
		}
	}
	return nil, nil
}

// ListInvites returns every invite metadata file, whether or not the
// response file exists yet.
func ListInvites(paths *config.Paths) ([]*Invite, error) {
	d := dirPath(paths)
	entries, err := os.ReadDir(d)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := []*Invite{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".invite.json") {
			continue
		}
		p := filepath.Join(d, e.Name())
		var inv Invite
		if err := readJSON(p, &inv); err != nil {
			continue
		}
		out = append(out, &inv)
	}
	return out, nil
}

// Delete removes both the invite and response files.
func Delete(paths *config.Paths, id string) error {
	if err := os.Remove(InvitePath(paths, id)); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Remove(ResponsePath(paths, id)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Expired reports whether the invite's ExpiresAt has passed.
func (inv Invite) Expired(now time.Time) bool {
	return now.After(inv.ExpiresAt)
}

// --- small helpers ---

func writeJSON(path string, v any) error {
	blob, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	blob = append(blob, '\n')
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func readJSON(path string, v any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
