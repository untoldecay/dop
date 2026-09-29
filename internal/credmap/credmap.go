// Package credmap holds the host → (grant, username) mapping used by
// credential-helper shims (`dop-credential-git` today; docker/npm/etc.
// later).
//
// File layout: `<Root>/credential-map.yaml` (mode 0600). Format:
//
//   version: 1
//   entries:
//     - host: github.com
//       grant: github.readonly
//       username: oauth
//     - host: ssh.dev.azure.com
//       grant: azure.devops
//       username: dop
//
// The shim reads this file, matches the incoming host, resolves the
// specified grant against the local bearer's env bundle, and returns
// the injected upstream token as the credential-helper password.
//
// If no entry matches, the shim MUST return NOTHING (git will fall
// back to its next helper). Never invent a credential.
package credmap

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/fray/dop/internal/config"
)

// Entry maps one target host to a grant and desired username. Username
// defaults to "dop" when unset.
type Entry struct {
	Host     string `yaml:"host"`
	Grant    string `yaml:"grant"`
	Username string `yaml:"username,omitempty"`
	// EnvPrefix, if set, overrides the auto-derived prefix. In the
	// common case, grants already declare their prefix in the vault, so
	// this is rarely needed here.
	EnvPrefix string `yaml:"env_prefix,omitempty"`
}

// File is the on-disk shape.
type File struct {
	Version int     `yaml:"version"`
	Entries []Entry `yaml:"entries"`
}

// Path returns `<Root>/credential-map.yaml`.
func Path(paths *config.Paths) string {
	return filepath.Join(paths.Root, "credential-map.yaml")
}

// Load reads the file, returning empty entries when absent. Missing
// file is not an error — the shim should just quietly fall through.
func Load(paths *config.Paths) (*File, error) {
	blob, err := os.ReadFile(Path(paths))
	if err != nil {
		if os.IsNotExist(err) {
			return &File{Version: 1}, nil
		}
		return nil, err
	}
	var f File
	if err := yaml.Unmarshal(blob, &f); err != nil {
		return nil, fmt.Errorf("credential-map: %w", err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("credential-map: unsupported version %d", f.Version)
	}
	return &f, nil
}

// Save writes the file mode 0600.
func Save(paths *config.Paths, f *File) error {
	if err := paths.EnsureDirs(); err != nil {
		return err
	}
	if f.Version == 0 {
		f.Version = 1
	}
	blob, err := yaml.Marshal(f)
	if err != nil {
		return err
	}
	p := Path(paths)
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Match returns the first entry whose Host matches the given host.
// Matching is case-insensitive; empty host never matches.
func (f *File) Match(host string) *Entry {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return nil
	}
	for i := range f.Entries {
		if strings.EqualFold(f.Entries[i].Host, host) {
			return &f.Entries[i]
		}
	}
	return nil
}

// Add inserts or replaces an entry by host. Returns true if it replaced.
func (f *File) Add(e Entry) bool {
	if e.Host == "" || e.Grant == "" {
		return false
	}
	for i := range f.Entries {
		if strings.EqualFold(f.Entries[i].Host, e.Host) {
			f.Entries[i] = e
			return true
		}
	}
	f.Entries = append(f.Entries, e)
	return false
}

// Remove deletes any entry matching host. Returns true if it removed
// something.
func (f *File) Remove(host string) bool {
	host = strings.ToLower(host)
	out := f.Entries[:0]
	removed := false
	for _, e := range f.Entries {
		if strings.EqualFold(e.Host, host) {
			removed = true
			continue
		}
		out = append(out, e)
	}
	f.Entries = out
	return removed
}

// ErrEmpty is returned when the file is present but has no entries —
// distinct from ErrNotExist for UX.
var ErrEmpty = errors.New("credential-map: no entries")
