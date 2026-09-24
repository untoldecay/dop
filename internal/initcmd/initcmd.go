// Package initcmd implements `dop init` — first-run setup on a machine.
//
// Scope in P1: keygen + config directory scaffold. `dop init --vault <url>` is
// layered on top (see vaultgit package) and adds the git clone + SOPS merge
// driver install.
package initcmd

import (
	"fmt"
	"io"
	"os"

	"github.com/fray/dop/internal/agekeys"
	"github.com/fray/dop/internal/config"
)

// Init runs the base init flow: ensure directories exist, generate an age
// key if none present, and print the public key + next-step hints to `out`.
//
// Idempotent: if an age key already exists, prints its pubkey and exits ok.
func Init(out io.Writer) (*config.Paths, error) {
	paths, err := config.Resolve()
	if err != nil {
		return nil, err
	}
	if err := paths.EnsureDirs(); err != nil {
		return nil, err
	}

	if _, err := os.Stat(paths.KeyFile); err == nil {
		// Key exists — read it to surface the pubkey.
		id, err := agekeys.LoadPrivateKey(paths.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("existing key at %s unreadable: %w", paths.KeyFile, err)
		}
		fmt.Fprintf(out, "dop init: key already present at %s\n", paths.KeyFile)
		fmt.Fprintf(out, "  public key: %s\n", id.Recipient())
		return paths, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("stat key file: %w", err)
	}

	id, err := agekeys.Generate()
	if err != nil {
		return nil, err
	}
	if err := agekeys.WritePrivateKey(id, paths.KeyFile); err != nil {
		return nil, err
	}
	fmt.Fprintf(out, "dop init: generated new age key\n")
	fmt.Fprintf(out, "  private key: %s (mode 0600)\n", paths.KeyFile)
	fmt.Fprintf(out, "  public key:  %s\n", id.Recipient())
	fmt.Fprintf(out, "\n")
	fmt.Fprintf(out, "next steps:\n")
	fmt.Fprintf(out, "  1. keep the private key safe — losing it = losing every credential in the vault\n")
	fmt.Fprintf(out, "  2. attach a vault repo:   dop init --vault <local-path-or-git-url>\n")
	return paths, nil
}
