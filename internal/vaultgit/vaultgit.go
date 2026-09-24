// Package vaultgit handles vault-repo scaffolding: creating a local bare
// repo (option 3, no remote), cloning an existing vault repo, and installing
// the SOPS merge driver + `.sops.yaml` + `.gitattributes` in the working
// clone.
//
// P1 shells out to the `git` binary — a Go git library would double our
// dependency weight for negligible upside. Users need git installed anyway.
package vaultgit

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// Attach either clones an existing vault repo, or creates a new local bare
// repo + working clone if the source doesn't exist yet (option 3 dev path).
//
// `source` is a path or URL: bare repo dir, git URL (ssh/https/file), or a
// path that doesn't exist yet (bootstrapped as a fresh bare repo).
// `dest` is the working-clone target (typically config.Paths.Vault).
//
// After clone: installs `.sops.yaml` for the given age recipient (if not
// present), installs `.gitattributes` for the SOPS merge driver, and
// registers the merge driver in the clone's `.git/config` so subsequent
// `git merge` on encrypted YAML routes through dop.
func Attach(source, dest, ageRecipient string, out io.Writer) error {
	if _, err := exec.LookPath("git"); err != nil {
		return errors.New("git binary not found in $PATH — install git first")
	}

	if err := ensureDestClear(dest); err != nil {
		return err
	}

	sourceURL, bootstrap, err := resolveSource(source)
	if err != nil {
		return err
	}

	if bootstrap {
		fmt.Fprintf(out, "vault: bootstrapping fresh bare repo at %s\n", sourceURL)
		if err := runGit(out, "", "init", "--bare", sourceURL); err != nil {
			return err
		}
	}

	fmt.Fprintf(out, "vault: cloning %s → %s\n", sourceURL, dest)
	// file:// URLs let git clone from bare repos without SSH; also works for pull/push.
	if err := runGit(out, "", "clone", fileURL(sourceURL), dest); err != nil {
		return err
	}

	if err := ensureSopsYAML(dest, ageRecipient, out); err != nil {
		return err
	}
	if err := ensureGitAttributes(dest, out); err != nil {
		return err
	}
	if err := installMergeDriver(dest, out); err != nil {
		return err
	}

	fmt.Fprintf(out, "vault: attached at %s\n", dest)
	return nil
}

func ensureDestClear(dest string) error {
	fi, err := os.Stat(dest)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("stat %s: %w", dest, err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s exists and is not a directory", dest)
	}
	entries, err := os.ReadDir(dest)
	if err != nil {
		return fmt.Errorf("read %s: %w", dest, err)
	}
	if len(entries) > 0 {
		return fmt.Errorf("vault clone target %s exists and is not empty — remove it or choose another path", dest)
	}
	return nil
}

// resolveSource interprets the `source` argument. Returns (sourceForGit, needsBootstrap, err).
//
//   - existing local dir  → use as-is, no bootstrap
//   - non-existent path   → treat as new bare repo location, bootstrap
//   - URL (ssh/https/git) → use as-is, no bootstrap
func resolveSource(source string) (string, bool, error) {
	if isURL(source) {
		return source, false, nil
	}
	abs, err := filepath.Abs(source)
	if err != nil {
		return "", false, fmt.Errorf("abs path: %w", err)
	}
	fi, err := os.Stat(abs)
	if os.IsNotExist(err) {
		return abs, true, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("stat source: %w", err)
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
	return u.Scheme == "https" || u.Scheme == "http" || u.Scheme == "ssh" || u.Scheme == "git" || u.Scheme == "file"
}

func fileURL(s string) string {
	if isURL(s) {
		return s
	}
	return "file://" + s
}

func ensureSopsYAML(dest, ageRecipient string, out io.Writer) error {
	path := filepath.Join(dest, ".sops.yaml")
	if _, err := os.Stat(path); err == nil {
		fmt.Fprintf(out, "vault: .sops.yaml already present, leaving as-is\n")
		return nil
	}
	body := fmt.Sprintf("creation_rules:\n  - path_regex: '.*\\.ya?ml$'\n    age: %s\n", ageRecipient)
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		return fmt.Errorf("write .sops.yaml: %w", err)
	}
	fmt.Fprintf(out, "vault: wrote .sops.yaml with age recipient\n")
	return nil
}

func ensureGitAttributes(dest string, out io.Writer) error {
	path := filepath.Join(dest, ".gitattributes")
	line := "*.yaml diff=dopdiffer merge=dop\n"
	// Read-modify-write: append if line missing.
	existing, _ := os.ReadFile(path)
	if strings.Contains(string(existing), "merge=dop") {
		fmt.Fprintf(out, "vault: .gitattributes already registers dop merge driver\n")
		return nil
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open .gitattributes: %w", err)
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		return fmt.Errorf("write .gitattributes: %w", err)
	}
	fmt.Fprintf(out, "vault: registered dop merge driver in .gitattributes\n")
	return nil
}

func installMergeDriver(dest string, out io.Writer) error {
	// Register a merge driver named `dop` in the clone's local git config.
	// The driver command receives %O (base) %A (ours) %B (theirs) and writes merged into %A.
	//
	// Full merge-driver binary lands in P1.b — for P1.a we just wire the
	// registration so the .gitattributes contract is complete. If a merge
	// actually fires without the driver implemented, git falls back to the
	// default and produces a conflict marker on the ciphertext (loud failure,
	// which is what we want — better than silent corruption).
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("locate self: %w", err)
	}
	driver := fmt.Sprintf("%s merge-driver %%O %%A %%B", self)
	if err := runGit(out, dest, "config", "merge.dop.name", "DOP SOPS+age merge driver"); err != nil {
		return err
	}
	if err := runGit(out, dest, "config", "merge.dop.driver", driver); err != nil {
		return err
	}
	fmt.Fprintf(out, "vault: registered git merge driver (merge.dop.driver = %s)\n", driver)
	return nil
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
