// Package userprefs persists non-vault UX choices to a small YAML file
// under the config dir. Promoted from `internal/tui/prefs.go` in rc5b
// so both the TUI and non-TUI code (`internal/cli/printguard`, etc.)
// can read the same values without crossing package boundaries.
//
// On-disk shape stays unchanged — the YAML file is the same path and
// the same keys, so existing installs round-trip without migration.
package userprefs

import (
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/fray/dop/internal/config"
)

// Prefs is the on-disk shape. All fields are `omitempty` so a freshly
// written file carries only what the operator actually touched.
type Prefs struct {
	// AllowFileKeys: when true, agent keys are generated as
	// file-backed P-256 (extractable) instead of SE-backed. Explicit
	// opt-in because the file is extractable to any same-uid process.
	AllowFileKeys bool `yaml:"allow_file_keys,omitempty"`
	// ApprovalPopupTimeoutSeconds — how long the native popup waits
	// for the operator to type their approval passphrase before the
	// flow upgrades to the tunnel+phone fallback. Default 60s;
	// supported choices in the TUI settings view: 15 / 30 / 60.
	// 0 (unset in YAML) → use default.
	ApprovalPopupTimeoutSeconds int `yaml:"approval_popup_timeout_seconds,omitempty"`
}

// Supported timeout choices (also what the TUI settings cycler offers).
const (
	ApprovalTimeoutDefaultSeconds = 60
)

var ApprovalTimeoutChoices = []int{15, 30, 60}

// Path returns the preferences file path (same as the old tui-prefs.yaml).
func Path(paths *config.Paths) string {
	return filepath.Join(paths.Root, "tui-prefs.yaml")
}

// Load reads the prefs file; missing file ⇒ zero-value Prefs.
func Load(paths *config.Paths) Prefs {
	b, err := os.ReadFile(Path(paths))
	if err != nil {
		return Prefs{}
	}
	var p Prefs
	_ = yaml.Unmarshal(b, &p)
	return p
}

// Save persists the Prefs struct to disk. Idempotent; creates parent
// dirs as needed.
func Save(paths *config.Paths, p Prefs) error {
	if err := os.MkdirAll(paths.Root, 0o700); err != nil {
		return err
	}
	b, err := yaml.Marshal(p)
	if err != nil {
		return err
	}
	return os.WriteFile(Path(paths), b, 0o600)
}

// ApprovalTimeout returns the operator's configured dialog timeout
// (or the default when unset / invalid). Clamps to the supported
// choices so a bad on-disk value doesn't produce a 1-second dialog
// or an infinite wait.
func (p Prefs) ApprovalTimeout() time.Duration {
	s := p.ApprovalPopupTimeoutSeconds
	if s <= 0 {
		s = ApprovalTimeoutDefaultSeconds
	}
	for _, c := range ApprovalTimeoutChoices {
		if s == c {
			return time.Duration(s) * time.Second
		}
	}
	return time.Duration(ApprovalTimeoutDefaultSeconds) * time.Second
}

// CycleApprovalTimeout returns the next supported timeout, wrapping
// around. Used by the TUI settings view's cycler.
func CycleApprovalTimeout(current int) int {
	for i, c := range ApprovalTimeoutChoices {
		if current == c {
			return ApprovalTimeoutChoices[(i+1)%len(ApprovalTimeoutChoices)]
		}
	}
	return ApprovalTimeoutDefaultSeconds
}
