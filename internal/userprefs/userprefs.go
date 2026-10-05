// Package userprefs persists non-vault UX choices to a small YAML file
// under the config dir. Promoted from `internal/tui/prefs.go` in rc5b
// so both the TUI and non-TUI code (`internal/cli/printguard`, etc.)
// can read the same values without crossing package boundaries.
//
// On-disk shape stays unchanged — the YAML file is the same path and
// the same keys, so existing installs round-trip without migration.
package userprefs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	// Harness — rc7i. Which AI coding harness the operator primarily
	// uses, so DOP's trust-context cache can consult the right session
	// env var without an explicit DOP_INFER_HARNESS_SESSION=1 opt-in.
	// Supported choices: HarnessNone / HarnessClaudeCode / HarnessCodex /
	// HarnessOpencode / HarnessManual / HarnessAny. See HarnessChoices.
	Harness string `yaml:"harness,omitempty"`
	// AdminIdleTTLSeconds — rc7l. How long the admin session stays
	// unlocked without activity before locking (idle timeout). Default
	// 15min matches admin.DefaultIdleTTL. 0 (unset) → use default.
	// -1 → never time out (operator must manually `dop admin logout`).
	AdminIdleTTLSeconds int `yaml:"admin_idle_ttl_seconds,omitempty"`
}

// Admin-idle-TTL presets. "never" is encoded as the sentinel
// AdminIdleTTLNever; "custom" opens a text-input picker in the TUI.
const (
	AdminIdleTTLDefault = 15 * 60    // 15 min (matches admin.DefaultIdleTTL)
	AdminIdleTTLNever   = -1
)

// AdminIdleTTLChoices is the preset list the TUI picker offers. Order
// is "shorter → longer → never" so operators scanning top-down see
// safer defaults first.
var AdminIdleTTLChoices = []int{
	15 * 60,       // 15 min
	30 * 60,       // 30 min
	60 * 60,       // 1 hour
	4 * 60 * 60,   // 4 hours
	24 * 60 * 60,  // 24 hours
	AdminIdleTTLNever,
}

// AdminIdleTTLLabel returns an operator-friendly short label.
func AdminIdleTTLLabel(secs int) string {
	switch {
	case secs == 0:
		return "default (15 min)"
	case secs == AdminIdleTTLNever:
		return "never (manual logout only)"
	case secs < 60:
		return fmt.Sprintf("%ds", secs)
	case secs < 3600:
		return fmt.Sprintf("%d min", secs/60)
	case secs%3600 == 0:
		return fmt.Sprintf("%d h", secs/3600)
	default:
		return (time.Duration(secs) * time.Second).String()
	}
}

// EffectiveAdminIdleTTL returns the duration the daemon should use —
// the operator pick when set, else the default. Returns a sentinel
// "very long" duration when the pref is AdminIdleTTLNever (300 years;
// no real session can outlast absolute TTL anyway).
func (p Prefs) EffectiveAdminIdleTTL() time.Duration {
	switch p.AdminIdleTTLSeconds {
	case 0:
		return time.Duration(AdminIdleTTLDefault) * time.Second
	case AdminIdleTTLNever:
		// 100 years. Enough to outlast any real session; small enough
		// to fit in int64 nanoseconds.
		return 100 * 365 * 24 * time.Hour
	default:
		return time.Duration(p.AdminIdleTTLSeconds) * time.Second
	}
}

// ParseAdminIdleTTL parses a free-text duration ("2h", "90m", "never")
// into the seconds representation used by Prefs.AdminIdleTTLSeconds.
// Returns an error on garbage input.
func ParseAdminIdleTTL(input string) (int, error) {
	s := strings.ToLower(strings.TrimSpace(input))
	if s == "" {
		return 0, errors.New("empty")
	}
	if s == "never" || s == "none" || s == "0" {
		return AdminIdleTTLNever, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("not a duration (try 15m / 2h / 24h / never): %w", err)
	}
	if d < 60*time.Second {
		return 0, errors.New("too short — minimum 1 minute (use `never` for no timeout)")
	}
	return int(d / time.Second), nil
}

// Harness choices. HarnessManual means "my harness doesn't expose a
// session id env var — I'll export DOP_SESSION_ID myself" (Cursor,
// Zed, aider, custom shells). HarnessAny tries all recognized adapters
// in Claude → Codex → opencode order.
const (
	HarnessNone       = ""
	HarnessClaudeCode = "claude-code"
	HarnessCodex      = "codex"
	HarnessOpencode   = "opencode"
	HarnessManual     = "manual"
	HarnessAny        = "any"
)

// HarnessChoices lists the values the TUI settings cycler offers.
// Order mirrors adoption: Claude Code first since it's the most
// common; "none" last as the opt-out.
var HarnessChoices = []string{
	HarnessClaudeCode,
	HarnessCodex,
	HarnessOpencode,
	HarnessManual,
	HarnessAny,
	HarnessNone,
}

// HarnessLabel returns the operator-facing short label for a harness
// choice (used by the TUI settings view).
func HarnessLabel(h string) string {
	switch h {
	case HarnessClaudeCode:
		return "Claude Code"
	case HarnessCodex:
		return "Codex CLI"
	case HarnessOpencode:
		return "opencode"
	case HarnessManual:
		return "manual (set DOP_SESSION_ID yourself)"
	case HarnessAny:
		return "any (try all recognized adapters)"
	case HarnessNone:
		return "none / skip"
	default:
		return "unknown"
	}
}

// CycleHarness returns the next supported choice, wrapping around.
// Unknown current → HarnessClaudeCode (sensible default for new picks).
func CycleHarness(current string) string {
	for i, c := range HarnessChoices {
		if current == c {
			return HarnessChoices[(i+1)%len(HarnessChoices)]
		}
	}
	return HarnessClaudeCode
}

// DOPHarnessEnvValue returns the DOP_HARNESS value that corresponds
// to this pref — the thing to pass to the sessiontrust resolver via
// os.Setenv. For HarnessManual and HarnessNone this returns "none"
// since the resolver should not auto-consult any harness var.
func DOPHarnessEnvValue(h string) string {
	switch h {
	case HarnessClaudeCode, HarnessCodex, HarnessOpencode, HarnessAny:
		return h
	default:
		return "none"
	}
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
