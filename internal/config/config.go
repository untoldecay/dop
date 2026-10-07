// Package config resolves DOP's on-disk paths.
//
// Layout under $XDG_CONFIG_HOME/dop (default ~/.config/dop; on macOS
// ~/Library/Application Support/dop), or under $DOP_HOME when set:
//
//	config.yaml         optional overrides
//	keys/age.txt        age private key (mode 0600) — the single decryption root
//	vault/              git clone of the vault repo
//	logs/               local audit log (populated in P4)
package config

import (
	"fmt"
	"os"
	"path/filepath"
)

const (
	dirName     = "dop"
	keyFileName = "age.txt"
)

// Paths bundles the resolved on-disk locations for a DOP install.
type Paths struct {
	Root    string // ~/.config/dop
	KeyFile string // Root/keys/age.txt
	KeysDir string // Root/keys
	Vault   string // Root/vault  (git clone of vault repo)
	Logs    string // Root/logs
	Config  string // Root/config.yaml (may not exist)
}

// Resolve returns the standard DOP paths for the current user. It does NOT
// create anything on disk — callers use EnsureDirs when they need the tree.
//
// DOP_HOME replaces the whole root — a separate install (own keys, vault,
// session daemon, settings) that never reads or touches the default one.
// Used for throwaway demo/recording installs and tests.
func Resolve() (*Paths, error) {
	root, err := resolveRoot()
	if err != nil {
		return nil, err
	}
	return &Paths{
		Root:    root,
		KeysDir: filepath.Join(root, "keys"),
		KeyFile: filepath.Join(root, "keys", keyFileName),
		Vault:   filepath.Join(root, "vault"),
		Logs:    filepath.Join(root, "logs"),
		Config:  filepath.Join(root, "config.yaml"),
	}, nil
}

func resolveRoot() (string, error) {
	if h := HomeOverride(); h != "" {
		return h, nil
	}
	return DefaultRoot()
}

// DefaultRoot is the root DOP uses when DOP_HOME is not set.
func DefaultRoot() (string, error) {
	base, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config dir: %w", err)
	}
	return filepath.Join(base, dirName), nil
}

// HomeOverride returns DOP_HOME as an absolute path, or "" when unset.
// Callers that show the active install (TUI header, doctor) use it.
func HomeOverride() string {
	h := os.Getenv("DOP_HOME")
	if h == "" {
		return ""
	}
	if abs, err := filepath.Abs(h); err == nil {
		return abs
	}
	return h
}

// EnsureDirs creates the root/keys/logs directories with restrictive
// permissions. Vault dir is intentionally NOT created here — `dop init --vault`
// creates it via `git clone` or `git init`.
func (p *Paths) EnsureDirs() error {
	for _, d := range []struct {
		path string
		mode os.FileMode
	}{
		{p.Root, 0o700},
		{p.KeysDir, 0o700},
		{p.Logs, 0o700},
	} {
		if err := os.MkdirAll(d.path, d.mode); err != nil {
			return fmt.Errorf("mkdir %s: %w", d.path, err)
		}
	}
	return nil
}
