// Package pendingclaim tracks in-flight PIN claims waiting for admin
// approval. v1.5.
//
// Model:
//
//   - Agent runs `dop claim <PIN>`: PIN verifies, agent generates a
//     keypair, then WRITES a pending-claim file to disk and blocks
//     waiting for approval.
//   - Admin runs `dop approve <SAS>`: writes an approval marker into
//     the file.
//   - Agent's claim loop notices, applies the vault mutation, and
//     completes.
//
// Storage: one JSON file per pending claim at
// $CFG/pending-claims/<lookup_id>.json (mode 0600, dir 0700). Filename
// is lookup_id so a claim per capability is deduped naturally; SAS is
// stored inside and used for the `dop approve` lookup.
package pendingclaim

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/fray/dop/internal/config"
)

// TTL is how long a pending claim survives before the agent considers
// it abandoned. Chat-handoff flows need enough room to scan a QR,
// unlock a phone, type a passphrase — 5 min is comfortable without
// leaving a huge attacker window.
const TTL = 5 * time.Minute

// State enum for the approval decision.
const (
	StatePending  = "pending"
	StateApproved = "approved"
	StateRejected = "rejected"
)

// Record is what lives on disk.
type Record struct {
	SAS          string    `json:"sas"`
	LookupID     string    `json:"lookup_id"`
	CapabilityID string    `json:"capability_id"`
	Subject      string    `json:"subject"`
	Pubkey       string    `json:"pubkey"`
	StartedAt    time.Time `json:"started_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	State        string    `json:"state"`
	DecidedAt    time.Time `json:"decided_at,omitempty"`
}

// NewSAS returns a 6-digit numeric code formatted as `XXX-XXX`.
// 000000-999999 = 20 bits of entropy; scoped to a 2-minute window with
// a single active pending claim per capability, this is enough — an
// attacker racing the admin has ~50s to guess ~1M combinations while
// the human reads the code.
func NewSAS() (string, error) {
	var b [3]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		return "", err
	}
	n := int(b[0])<<16 | int(b[1])<<8 | int(b[2])
	n %= 1_000_000
	return fmt.Sprintf("%03d-%03d", n/1000, n%1000), nil
}

// NormalizeSAS strips separators and non-digits so users can type
// `472913` or `472-913` or `472 913` interchangeably.
func NormalizeSAS(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= '0' && c <= '9' {
			out = append(out, c)
		}
	}
	if len(out) != 6 {
		return string(out)
	}
	return string(out[:3]) + "-" + string(out[3:])
}

// dir returns the pending-claims directory, creating it on demand.
func dir(paths *config.Paths) (string, error) {
	d := filepath.Join(paths.Root, "pending-claims")
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", err
	}
	return d, nil
}

// Write creates a new pending-claim file. Fails if one already exists
// for the same lookup_id.
func Write(paths *config.Paths, r Record) error {
	if r.LookupID == "" || r.SAS == "" {
		return errors.New("pendingclaim.Write: missing lookup_id or SAS")
	}
	d, err := dir(paths)
	if err != nil {
		return err
	}
	p := filepath.Join(d, r.LookupID+".json")
	if _, err := os.Stat(p); err == nil {
		return fmt.Errorf("a pending claim already exists for this capability (%s) — reject it first", p)
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	return json.NewEncoder(f).Encode(r)
}

// Read loads a pending claim by lookup_id.
func Read(paths *config.Paths, lookupID string) (*Record, error) {
	d, err := dir(paths)
	if err != nil {
		return nil, err
	}
	return readFile(filepath.Join(d, lookupID+".json"))
}

func readFile(p string) (*Record, error) {
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var r Record
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// Delete removes a pending-claim file by lookup_id.
func Delete(paths *config.Paths, lookupID string) error {
	d, err := dir(paths)
	if err != nil {
		return err
	}
	err = os.Remove(filepath.Join(d, lookupID+".json"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// List returns all currently on-disk pending claims (including expired
// ones — the caller filters).
func List(paths *config.Paths) ([]*Record, error) {
	d, err := dir(paths)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(d)
	if err != nil {
		return nil, err
	}
	out := []*Record{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		r, err := readFile(filepath.Join(d, e.Name()))
		if err != nil {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

// FindBySAS scans all pending files for one whose SAS matches (after
// normalization). Returns nil if none match.
func FindBySAS(paths *config.Paths, sas string) (*Record, error) {
	target := NormalizeSAS(sas)
	all, err := List(paths)
	if err != nil {
		return nil, err
	}
	for _, r := range all {
		if NormalizeSAS(r.SAS) == target {
			return r, nil
		}
	}
	return nil, nil
}

// SetState atomically updates the on-disk record's state (approved or
// rejected). Writes via a tempfile + rename to prevent partial reads
// by a concurrent agent poll.
func SetState(paths *config.Paths, lookupID, state string) error {
	d, err := dir(paths)
	if err != nil {
		return err
	}
	p := filepath.Join(d, lookupID+".json")
	r, err := readFile(p)
	if err != nil {
		return err
	}
	r.State = state
	r.DecidedAt = time.Now().UTC().Truncate(time.Second)
	tmp, err := os.CreateTemp(d, ".dop-pending-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if err := json.NewEncoder(tmp).Encode(r); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	tmp.Close()
	if err := os.Chmod(tmpPath, 0o600); err != nil {
		os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, p)
}

// Expired returns true if the pending claim's ExpiresAt has passed.
func (r *Record) Expired(now time.Time) bool {
	return now.After(r.ExpiresAt)
}
