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

	"golang.org/x/sys/unix"

	"github.com/fray/dop/internal/config"
)

// ownerAlive reports whether the process that wrote a pending-claim
// record is still running. signal(0) probes for existence without
// side-effects. Used by Write to auto-clean records left behind by a
// SIGKILL / panic / power-loss (SIGINT is caught + cleaned via defer,
// but SIGKILL can't be trapped, so the file leaks).
//
// Only meaningful on the same host as the writer — a Record with a
// non-empty Host different from ours conservatively reports alive so
// we don't step on a peer's in-flight claim.
func ownerAlive(r *Record) bool {
	if r.PID <= 0 {
		return true // legacy record, no PID — conservative
	}
	if r.Host != "" && r.Host != currentHost() {
		return true // written by another machine
	}
	err := unix.Kill(r.PID, 0)
	if err == nil {
		return true
	}
	if errors.Is(err, unix.ESRCH) {
		return false
	}
	// EPERM means the process exists but we can't signal it — still alive.
	return true
}

func currentHost() string {
	h, _ := os.Hostname()
	return h
}

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
	// FailureCount — v1.6.3. Every failed passphrase attempt bumps
	// this, whether from the web endpoint OR the `dop approve` CLI.
	// The two paths share a limiter so an attacker can't burn attempts
	// from the CLI to bypass a web-page counter.
	FailureCount int `json:"failure_count,omitempty"`
	// PID + Host — v1.9.4. Set by Write to the process that owns the
	// claim. Enables next-run staleness detection: if the process is
	// gone (SIGKILL, panic, power-loss), Write silently reclaims the
	// slot instead of demanding "reject it first".
	PID  int    `json:"pid,omitempty"`
	Host string `json:"host,omitempty"`
}

// MaxFailures is the shared limit — approve/reject paths must call
// BumpFailure and refuse when the count reaches this. Matches
// approveRateMax in the approvalserver package.
const MaxFailures = 8

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

// Write creates a new pending-claim file. If one already exists for
// the same lookup_id, checks whether the owner process is still alive:
// dead → reclaim silently (v1.9.4 stale-lock fix), alive → refuse.
func Write(paths *config.Paths, r Record) error {
	if r.LookupID == "" || r.SAS == "" {
		return errors.New("pendingclaim.Write: missing lookup_id or SAS")
	}
	d, err := dir(paths)
	if err != nil {
		return err
	}
	if r.PID == 0 {
		r.PID = os.Getpid()
	}
	if r.Host == "" {
		r.Host = currentHost()
	}
	p := filepath.Join(d, r.LookupID+".json")
	if existing, rerr := readFile(p); rerr == nil {
		if !ownerAlive(existing) {
			_ = os.Remove(p)
			_ = os.Remove(filepath.Join(d, r.LookupID+".lock"))
		} else {
			return fmt.Errorf(
				"a claim for this token is already in-flight on this machine.\n"+
					"  To see its status:  dop claim --status\n"+
					"  To cancel it:       dop claim --cancel\n"+
					"  (Then retry your claim.)")
		}
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

// Delete removes a pending-claim file (and its lockfile + QR PNG) by lookup_id.
func Delete(paths *config.Paths, lookupID string) error {
	d, err := dir(paths)
	if err != nil {
		return err
	}
	err = os.Remove(filepath.Join(d, lookupID+".json"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	// Best-effort: sweep the lockfile + QR PNG so nothing lingers.
	_ = os.Remove(filepath.Join(d, lookupID+".lock"))
	_ = os.Remove(filepath.Join(d, lookupID+".qr.png"))
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
		if strings.HasPrefix(e.Name(), ".dop-pending-") {
			continue // in-flight tempfile
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
// rejected). Wraps read-modify-write in an flock so it composes safely
// with BumpFailure and with itself under concurrent web+CLI approve.
func SetState(paths *config.Paths, lookupID, state string) error {
	d, err := dir(paths)
	if err != nil {
		return err
	}
	return withLock(d, lookupID, func() error {
		p := filepath.Join(d, lookupID+".json")
		r, err := readFile(p)
		if err != nil {
			return err
		}
		r.State = state
		r.DecidedAt = time.Now().UTC().Truncate(time.Second)
		return writeRecord(d, p, r)
	})
}

// withLock takes an advisory exclusive lock on a per-claim lockfile
// and runs fn while holding it. Two racers on the same claim serialize;
// racers on different claims don't contend. Uses BSD-flock (LOCK_EX)
// which is honored by Linux and macOS. Lockfile lives next to the
// pending-claim json so cleanup happens naturally when the pending
// dir gets nuked.
func withLock(dir, lookupID string, fn func() error) error {
	lockPath := filepath.Join(dir, lookupID+".lock")
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("flock: %w", err)
	}
	defer unix.Flock(int(f.Fd()), unix.LOCK_UN)
	return fn()
}

// writeRecord serializes r to path via a temp-file + rename, mode 0600.
func writeRecord(dir, path string, r *Record) error {
	tmp, err := os.CreateTemp(dir, ".dop-pending-*")
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
	return os.Rename(tmpPath, path)
}

// Expired returns true if the pending claim's ExpiresAt has passed.
func (r *Record) Expired(now time.Time) bool {
	return now.After(r.ExpiresAt)
}

// BumpFailure atomically increments the on-disk failure counter for
// the pending claim with this lookup_id. Returns the new count and
// whether the pending claim has been auto-rejected (count >= Max).
//
// Locking: flock-wrapped so two racers (web + CLI, or two CLI) can't
// each read count=6 and each write count=7. Under argon2id parallelism
// on a warm system this race was small in practice (~40 vs 8), but
// still shipped as a soft cap in v1.6.3.
func BumpFailure(paths *config.Paths, lookupID string) (count int, autoRejected bool, err error) {
	d, dErr := dir(paths)
	if dErr != nil {
		return 0, false, dErr
	}
	p := filepath.Join(d, lookupID+".json")
	err = withLock(d, lookupID, func() error {
		r, err := readFile(p)
		if err != nil {
			return err
		}
		r.FailureCount++
		count = r.FailureCount
		if r.FailureCount >= MaxFailures {
			r.State = StateRejected
			r.DecidedAt = time.Now().UTC().Truncate(time.Second)
			autoRejected = true
		}
		return writeRecord(d, p, r)
	})
	return count, autoRejected, err
}
