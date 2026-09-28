// Path helpers used by both the CLI dispatcher and the session daemon.

package admin

import (
	"errors"
	"os"

	"github.com/fray/dop/internal/config"
)

// KeyFile returns the absolute path to the passphrase-wrapped admin key
// file. Located under config paths (XDG-aware).
func KeyFile(paths *config.Paths) string {
	if paths == nil {
		return ""
	}
	return paths.KeysDir + "/admin.age.enc"
}

// SockPath returns the admin session unix socket path.
func SockPath(paths *config.Paths) string {
	if paths == nil {
		return ""
	}
	return paths.Root + "/admin.sock"
}

// KeyFileExists reports whether the passphrase-wrapped admin key is
// present on disk.
func KeyFileExists(paths *config.Paths) bool {
	p := KeyFile(paths)
	if p == "" {
		return false
	}
	_, err := os.Stat(p)
	return err == nil
}

// LoadAndUnwrap reads the wrapped key file and decrypts it with the
// given passphrase.
func LoadAndUnwrap(paths *config.Paths, passphrase string) (*Keys, error) {
	if !KeyFileExists(paths) {
		return nil, errors.New("no admin key on this machine — run `dop admin init` first")
	}
	data, err := os.ReadFile(KeyFile(paths))
	if err != nil {
		return nil, err
	}
	return Unwrap(data, passphrase)
}
