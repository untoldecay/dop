// TUI preferences — small on-disk YAML blob under the config dir that
// stores non-vault-related UX choices. Keeps the vault schema clean.
//
// Right now only one preference: AllowFileKeys. When true, the TUI
// passes DOP_ALLOW_FILE_KEYS=1 to any dop subcommand that generates
// agent keys, and recommends --key-type p256 in the agent-handoff
// clipboard payload. This unlocks v1.12 direct availability
// (add-grant / remove-grant / rotate) on hosts where the dop binary
// can't reach the Secure Enclave — typically unsigned/Apple-Dev
// macOS builds or Linux/CI runners.

package tui

import (
	"os"
	"path/filepath"

	"github.com/fray/dop/internal/config"
	"gopkg.in/yaml.v3"
)

type Prefs struct {
	// AllowFileKeys: when true, agent keys are generated as
	// file-backed P-256 (extractable) instead of SE-backed. Chosen
	// explicitly by the operator — never defaults to true, because
	// the file is extractable to any process on the same uid.
	AllowFileKeys bool `yaml:"allow_file_keys,omitempty"`
}

// prefsPath returns <config.Root>/tui-prefs.yaml.
func prefsPath(paths *config.Paths) string {
	return filepath.Join(paths.Root, "tui-prefs.yaml")
}

// LoadPrefs reads tui-prefs.yaml; missing file ⇒ zero-value Prefs
// (AllowFileKeys=false — the safe default).
func LoadPrefs(paths *config.Paths) Prefs {
	b, err := os.ReadFile(prefsPath(paths))
	if err != nil {
		return Prefs{}
	}
	var p Prefs
	_ = yaml.Unmarshal(b, &p)
	return p
}

// SavePrefs persists the Prefs struct to disk. Idempotent; create
// parent dirs as needed.
func SavePrefs(paths *config.Paths, p Prefs) error {
	if err := os.MkdirAll(paths.Root, 0o700); err != nil {
		return err
	}
	b, err := yaml.Marshal(p)
	if err != nil {
		return err
	}
	return os.WriteFile(prefsPath(paths), b, 0o600)
}
