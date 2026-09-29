// Package approval stores and verifies the DOP "approval passphrase"
// — a separate secret from the admin passphrase, used to gate
// out-of-band claim approvals (v1.6+).
//
// Why not reuse the admin passphrase? The admin passphrase unlocks
// the whole vault; typing it into a web form on a phone is a bigger
// exposure surface than typing an approval-only secret is worth.
//
// Storage: keys/approval.hash under the DOP root, a small JSON with
// argon2id parameters + salt + hash, mode 0600.
package approval

import (
	"crypto/hmac"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"

	"github.com/fray/dop/internal/config"
)

// Argon2id parameters (RFC-9106 second recommended set). t=3 with
// m=64MiB and p=4 keeps a phone-side login under a second while
// costing an offline attacker meaningfully more per guess.
const (
	argonTime    = 3
	argonMemKiB  = 64 * 1024
	argonThreads = 4
	argonKeyLen  = 32
	saltLen      = 16
)

// stored is the on-disk JSON layout — versioned so we can rev
// parameters later without breaking existing installs.
type stored struct {
	Version int    `json:"version"`
	Salt    string `json:"salt"`   // base64
	Hash    string `json:"hash"`   // base64
	Time    uint32 `json:"t"`
	Mem     uint32 `json:"m"`      // KiB
	Threads uint8  `json:"p"`
	KeyLen  uint32 `json:"k"`
}

// ErrNotSet is returned by Verify when no approval passphrase has been
// configured yet.
var ErrNotSet = errors.New("approval passphrase not configured (rerun `dop admin init` or `dop admin set-approval`)")

// path returns keys/approval.hash under the DOP root.
func path(paths *config.Paths) string {
	return filepath.Join(paths.KeysDir, "approval.hash")
}

// Configured reports whether an approval passphrase is set.
func Configured(paths *config.Paths) bool {
	_, err := os.Stat(path(paths))
	return err == nil
}

// Set hashes the passphrase with a fresh salt and writes it atomically.
func Set(paths *config.Paths, passphrase string) error {
	if len(passphrase) < 10 {
		return errors.New("approval passphrase must be at least 10 characters")
	}
	if err := paths.EnsureDirs(); err != nil {
		return err
	}
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return err
	}
	hash := argon2.IDKey([]byte(passphrase), salt, argonTime, argonMemKiB, argonThreads, argonKeyLen)
	blob, err := json.Marshal(stored{
		Version: 1,
		Salt:    base64.StdEncoding.EncodeToString(salt),
		Hash:    base64.StdEncoding.EncodeToString(hash),
		Time:    argonTime,
		Mem:     argonMemKiB,
		Threads: argonThreads,
		KeyLen:  argonKeyLen,
	})
	if err != nil {
		return err
	}
	p := path(paths)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Verify checks the candidate against the stored hash. Returns true
// only on a constant-time match. Returns ErrNotSet if no file exists.
func Verify(paths *config.Paths, candidate string) (bool, error) {
	blob, err := os.ReadFile(path(paths))
	if err != nil {
		if os.IsNotExist(err) {
			return false, ErrNotSet
		}
		return false, err
	}
	var s stored
	if err := json.Unmarshal(blob, &s); err != nil {
		return false, fmt.Errorf("approval.hash malformed: %w", err)
	}
	if s.Version != 1 {
		return false, fmt.Errorf("unsupported approval.hash version %d", s.Version)
	}
	salt, err := base64.StdEncoding.DecodeString(s.Salt)
	if err != nil {
		return false, err
	}
	want, err := base64.StdEncoding.DecodeString(s.Hash)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(candidate), salt, s.Time, s.Mem, s.Threads, s.KeyLen)
	return hmac.Equal(want, got), nil
}
