// Package remoteuse models the "lease a portable bearer to an agent on a
// server" workflow (dop-1dd). The server has no admin key, so it cannot
// unwrap a portable bearer itself; it asks, and an admin machine answers
// with a fresh short-lived bearer sealed to a one-shot key.
//
// Flow:
//  1. Server: `dop use <subject> --remote` makes a one-shot age identity,
//     writes pending-use/<id>.json (this Request), pushes, polls.
//  2. Admin: TUI or `dop approve-remote --use <id> --lease 10m` picks a
//     duration (never the agent), verifies, mints an unbound bearer with
//     the same grants and that expiry, seals it to the request's recipient,
//     writes pending-use/<id>.lease.json (this Lease) signed by the admin
//     key, pushes.
//  3. Server: verifies the admin signature against admins.trust, opens the
//     lease, exports DOP_TOKEN, deletes both files. The bearer dies at its
//     expiry; the next exec after that says "lease expired, ask again".
package remoteuse

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fray/dop/internal/agentkey"
	"github.com/fray/dop/internal/config"
)

// TTL is how long a request waits for an answer before the server gives up.
const TTL = 15 * time.Minute

// Request is what the server stages. Signer* are optional: when a claimed
// agent key exists on the host the request is signed with it so the admin
// can see who asks; otherwise the admin trusts host + nonce shown in the TUI.
type Request struct {
	RequestID   string    `json:"request_id"`
	Subject     string    `json:"subject"` // the portable bearer asked for
	Host        string    `json:"host"`
	AgentName   string    `json:"agent_name,omitempty"`
	Recipient   string    `json:"recipient"` // one-shot age recipient (age1…)
	RequestedAt time.Time `json:"requested_at"`
	ExpiresAt   time.Time `json:"expires_at"`
	Nonce       string    `json:"nonce"`

	SignerLookupID string `json:"signer_lookup_id,omitempty"`
	SignerKeyType  string `json:"signer_key_type,omitempty"`
	SignerPubkey   string `json:"signer_pubkey,omitempty"`
	Signature      string `json:"signature,omitempty"`
}

// Lease is the admin's answer: a fresh bearer sealed to the request's
// recipient, signed by the approving admin's ed25519 key.
type Lease struct {
	RequestID    string    `json:"request_id"`
	Subject      string    `json:"subject"`
	LeaseSubject string    `json:"lease_subject"` // the minted bearer's subject
	ExpiresAt    time.Time `json:"expires_at"`
	Ciphertext   string    `json:"ciphertext"` // base64 age ciphertext of the bearer
	ApprovedAt   time.Time `json:"approved_at"`
	Approver     string    `json:"approver"` // admin ed25519 pubkey hex
	Signature    string    `json:"signature"`
}

func Dir(paths *config.Paths) string { return filepath.Join(paths.Vault, "pending-use") }

func requestPath(paths *config.Paths, id string) string { return filepath.Join(Dir(paths), id+".json") }
func leasePath(paths *config.Paths, id string) string {
	return filepath.Join(Dir(paths), id+".lease.json")
}

// RelPaths are the two repo-relative files of one request, for git add.
func RelPaths(id string) []string {
	return []string{filepath.Join("pending-use", id+".json"), filepath.Join("pending-use", id+".lease.json")}
}

// NewID is a random 160-bit hex id.
func NewID() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (r Request) signingPayload() ([]byte, error) {
	r.Signature = ""
	return json.Marshal(r)
}

// Sign attaches the agent store's signature and identity.
func (r *Request) Sign(store agentkey.Store) error {
	r.SignerLookupID, r.SignerKeyType = store.LookupID(), store.KeyType()
	r.SignerPubkey = hex.EncodeToString(store.PublicKey())
	payload, err := r.signingPayload()
	if err != nil {
		return err
	}
	sig, err := store.Sign(payload)
	if err != nil {
		return err
	}
	r.Signature = hex.EncodeToString(sig)
	return nil
}

// Verify checks the optional signature. Unsigned requests verify as
// unsigned (the caller decides whether to accept them); a bad signature
// is an error.
func (r Request) Verify() (signed bool, err error) {
	if r.Signature == "" && r.SignerPubkey == "" {
		return false, nil
	}
	pub, err := hex.DecodeString(r.SignerPubkey)
	if err != nil {
		return true, fmt.Errorf("remote use: bad signer pubkey: %w", err)
	}
	sig, err := hex.DecodeString(r.Signature)
	if err != nil {
		return true, fmt.Errorf("remote use: bad signature hex: %w", err)
	}
	payload, err := r.signingPayload()
	if err != nil {
		return true, err
	}
	if err := agentkey.Verify(r.SignerKeyType, pub, payload, sig); err != nil {
		return true, fmt.Errorf("remote use: %w", err)
	}
	return true, nil
}

// SigningPayload is what the admin signs (everything but Signature).
func (l Lease) SigningPayload() ([]byte, error) {
	l.Signature = ""
	return json.Marshal(l)
}

// Verify checks the admin signature against the trusted admin pubkeys.
func (l Lease) Verify(trusted map[string]bool) error {
	if l.Signature == "" || l.Approver == "" {
		return errors.New("lease: not signed")
	}
	if !trusted[strings.ToLower(l.Approver)] && !trusted[l.Approver] {
		return fmt.Errorf("lease: approver %s… is not a trusted admin", short(l.Approver))
	}
	pub, err := hex.DecodeString(l.Approver)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("lease: bad approver pubkey")
	}
	sig, err := hex.DecodeString(l.Signature)
	if err != nil {
		return errors.New("lease: bad signature hex")
	}
	payload, err := l.SigningPayload()
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), payload, sig) {
		return errors.New("lease: signature does not verify")
	}
	return nil
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	blob, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, append(blob, '\n'), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func WriteRequest(paths *config.Paths, r Request) error {
	return writeJSON(requestPath(paths, r.RequestID), r)
}
func WriteLease(paths *config.Paths, l Lease) error {
	return writeJSON(leasePath(paths, l.RequestID), l)
}

func ReadRequest(paths *config.Paths, id string) (*Request, error) {
	blob, err := os.ReadFile(requestPath(paths, id))
	if err != nil {
		return nil, err
	}
	var r Request
	if err := json.Unmarshal(blob, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func ReadLease(paths *config.Paths, id string) (*Lease, error) {
	blob, err := os.ReadFile(leasePath(paths, id))
	if err != nil {
		return nil, err
	}
	var l Lease
	if err := json.Unmarshal(blob, &l); err != nil {
		return nil, err
	}
	return &l, nil
}

// ListRequests enumerates staged requests (answered ones included while
// their lease file is still there).
func ListRequests(paths *config.Paths) ([]*Request, error) {
	entries, err := os.ReadDir(Dir(paths))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := []*Request{}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".json") || strings.HasSuffix(n, ".lease.json") {
			continue
		}
		r, err := ReadRequest(paths, strings.TrimSuffix(n, ".json"))
		if err != nil {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// Delete removes a request and its lease, if any.
func Delete(paths *config.Paths, id string) error {
	for _, p := range []string{requestPath(paths, id), leasePath(paths, id)} {
		if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func short(s string) string {
	if len(s) > 8 {
		return s[:8]
	}
	return s
}
