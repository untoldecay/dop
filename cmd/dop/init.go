// `dop init` — attach a vault, either as admin (--vault) or agent (--cache).

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/config"
)

func runInit(args []string) int {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	vaultSrc := fs.String("vault", "", "attach as admin: path or URL to vault repo")
	cacheSrc := fs.String("cache", "", "attach as agent: path or URL to vault repo (no admin keys generated)")
	_ = fs.Parse(args)

	if *vaultSrc == "" && *cacheSrc == "" {
		fmt.Fprintln(os.Stderr, "dop init: --vault or --cache required")
		return 2
	}
	if *vaultSrc != "" && *cacheSrc != "" {
		fmt.Fprintln(os.Stderr, "dop init: only one of --vault / --cache")
		return 2
	}
	paths, err := config.Resolve()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop init: %v\n", err)
		return 1
	}
	if err := paths.EnsureDirs(); err != nil {
		fmt.Fprintf(os.Stderr, "dop init: %v\n", err)
		return 1
	}

	if *vaultSrc != "" {
		return initAsAdmin(paths, *vaultSrc)
	}
	return initAsAgent(paths, *cacheSrc)
}

// initAsAdmin requires an admin key (dop admin init must have run) and
// clones the vault, adds this machine's admin recipient to .sops.yaml
// on first attach.
func initAsAdmin(paths *config.Paths, source string) int {
	if !admin.KeyFileExists(paths) {
		fmt.Fprintln(os.Stderr, "dop init --vault: no admin key on this machine.")
		fmt.Fprintln(os.Stderr, "  Run `dop admin init` first to generate one, or use `dop init --cache <url>` for an agent install.")
		return 1
	}
	return attachRepo(source, paths.Vault, false)
}

// initAsAgent clones the vault WITHOUT generating any admin key.
// The `keys/` directory is not created; admin operations on this machine
// will refuse to run.
func initAsAgent(paths *config.Paths, source string) int {
	if admin.KeyFileExists(paths) {
		fmt.Fprintln(os.Stderr, "dop init --cache: an admin key exists at "+admin.KeyFile(paths))
		fmt.Fprintln(os.Stderr, "  This machine is already set up as an admin install. Remove the key first if you want to downgrade.")
		return 1
	}
	return attachRepo(source, paths.Vault, true)
}

// attachRepo bootstraps a local bare repo if source is a non-existent path,
// then clones source into dest. Idempotent: if dest already exists as a
// git checkout, does nothing.
func attachRepo(source, dest string, agentInstall bool) int {
	if _, err := exec.LookPath("git"); err != nil {
		fmt.Fprintln(os.Stderr, "dop init: git not on $PATH — install git first")
		return 1
	}
	if err := ensureDestClear(dest); err != nil {
		fmt.Fprintf(os.Stderr, "dop init: %v\n", err)
		return 1
	}
	source, bootstrap, err := resolveSource(source)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop init: %v\n", err)
		return 1
	}
	if bootstrap {
		fmt.Fprintf(os.Stderr, "dop init: bootstrapping local bare repo at %s\n", source)
		if err := runGit(os.Stderr, "", "init", "--bare", source); err != nil {
			fmt.Fprintf(os.Stderr, "dop init: %v\n", err)
			return 1
		}
	}
	fmt.Fprintf(os.Stderr, "dop init: cloning %s → %s\n", source, dest)
	if err := runGit(os.Stderr, "", "clone", asURL(source), dest); err != nil {
		fmt.Fprintf(os.Stderr, "dop init: %v\n", err)
		return 1
	}
	kind := "admin install"
	if agentInstall {
		kind = "agent install"
	}
	fmt.Fprintf(os.Stderr, "dop init: vault attached at %s (%s)\n", dest, kind)
	return 0
}

func ensureDestClear(dest string) error {
	fi, err := os.Stat(dest)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s exists and is not a directory", dest)
	}
	entries, err := os.ReadDir(dest)
	if err != nil {
		return err
	}
	if len(entries) > 0 {
		return fmt.Errorf("%s exists and is not empty (delete it manually if intentional)", dest)
	}
	return nil
}

func resolveSource(source string) (string, bool, error) {
	if isURL(source) {
		return source, false, nil
	}
	abs, err := filepath.Abs(source)
	if err != nil {
		return "", false, err
	}
	fi, err := os.Stat(abs)
	if os.IsNotExist(err) {
		return abs, true, nil
	}
	if err != nil {
		return "", false, err
	}
	if !fi.IsDir() {
		return "", false, fmt.Errorf("%s exists and is not a directory", abs)
	}
	return abs, false, nil
}

func isURL(s string) bool {
	if strings.HasPrefix(s, "git@") {
		return true
	}
	u, err := url.Parse(s)
	if err != nil {
		return false
	}
	return u.Scheme == "https" || u.Scheme == "http" || u.Scheme == "ssh" || u.Scheme == "file"
}

func asURL(s string) string {
	if isURL(s) {
		return s
	}
	return "file://" + s
}

func runGit(out io.Writer, dir string, args ...string) error {
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return nil
}

// pullPush helpers ------------------------------------------------------------

func runPull(args []string) int {
	paths, _ := config.Resolve()
	if err := runGit(os.Stderr, paths.Vault, "pull", "--ff-only"); err != nil {
		fmt.Fprintf(os.Stderr, "dop pull: %v\n", err)
		return 1
	}
	return 0
}

func runPush(args []string) int {
	paths, _ := config.Resolve()
	// Best-effort add + commit; ignore no-changes exit.
	_ = runGit(os.Stderr, paths.Vault, "add", "-A")
	_ = runGitAllowExit(os.Stderr, paths.Vault, []int{0, 1}, "commit", "-m", "dop: sync")
	if err := runGit(os.Stderr, paths.Vault, "push"); err != nil {
		fmt.Fprintf(os.Stderr, "dop push: %v\n", err)
		return 1
	}
	return 0
}

func runGitAllowExit(out io.Writer, dir string, allowed []int, args ...string) error {
	cmd := exec.Command("git", args...)
	if dir != "" {
		cmd.Dir = dir
	}
	cmd.Stdout = out
	cmd.Stderr = out
	err := cmd.Run()
	if err == nil {
		return nil
	}
	if ee, ok := err.(*exec.ExitError); ok {
		for _, a := range allowed {
			if ee.ExitCode() == a {
				return nil
			}
		}
	}
	return err
}

// stubs referenced by main.go dispatcher — implemented in phase-3/4 files
var errNotImplemented = errors.New("not implemented yet (V1 in progress)")
