// `dop vault edit` — open the decrypted vault in $EDITOR and re-encrypt
// on save. Requires an active admin session.
//
// The plaintext lives in a `chmod 600` tempfile that's shredded on close.

package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

// runVault dispatches `dop vault <edit|...>`.
func runVault(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: dop vault <edit>")
		return 2
	}
	switch args[0] {
	case "edit":
		return runVaultEdit(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "dop vault: unknown subcommand %q\n", args[0])
		return 2
	}
}

func runVaultEdit(args []string) int {
	fs := flag.NewFlagSet("vault edit", flag.ExitOnError)
	editor := fs.String("editor", "", "override $EDITOR")
	_ = fs.Parse(args)

	paths, _ := config.Resolve()
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop vault edit: %v\n", err)
		return 1
	}
	v, vp, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop vault edit: %v\n", err)
		return 1
	}
	plaintext, err := vault.EmitPlain(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop vault edit: %v\n", err)
		return 1
	}
	// Write to a 0600 tempfile under the config dir so it's on the same
	// mount as the vault (no cross-device juggling).
	tmpDir := paths.Root
	if err := os.MkdirAll(tmpDir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "dop vault edit: %v\n", err)
		return 1
	}
	tmp := filepath.Join(tmpDir, ".vault-edit.yaml")
	if err := os.WriteFile(tmp, plaintext, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "dop vault edit: %v\n", err)
		return 1
	}
	// Best-effort scrub: overwrite before delete so recovery is harder.
	defer func() {
		if fi, err := os.Stat(tmp); err == nil {
			zero := make([]byte, fi.Size())
			_, _ = rand.Read(zero)
			os.WriteFile(tmp, zero, 0o600)
		}
		os.Remove(tmp)
	}()

	ed := *editor
	if ed == "" {
		ed = os.Getenv("EDITOR")
	}
	if ed == "" {
		ed = "vi"
	}
	cmd := exec.Command(ed, tmp)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "dop vault edit: editor exited with error: %v\n", err)
		return 1
	}
	// Read + parse edited content.
	edited, err := os.ReadFile(tmp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop vault edit: %v\n", err)
		return 1
	}
	newV, err := vault.ParsePlain(edited)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop vault edit: parse: %v\n", err)
		fmt.Fprintln(os.Stderr, "  (your edits were NOT saved. Re-run to try again.)")
		return 1
	}
	if err := saveVaultViaDaemon(client, paths, vp, newV); err != nil {
		fmt.Fprintf(os.Stderr, "dop vault edit: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "dop vault edit: saved")
	return 0
}
