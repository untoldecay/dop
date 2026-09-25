// dop — Doors of Perception CLI.
//
// P0 wire path (walking skeleton): vault load → resolve → exec.
// P1 adds: age key management, SOPS-encrypted vault, `dop init`.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"

	"time"

	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/execchild"
	"github.com/fray/dop/internal/initcmd"
	"github.com/fray/dop/internal/resolve"
	"github.com/fray/dop/internal/vault"
	"github.com/fray/dop/internal/vaultgit"
	"github.com/fray/dop/internal/vaultsync"
	"github.com/fray/dop/internal/yamlmerge"

	"filippo.io/age"
)

const usage = `dop — Doors of Perception

usage:
  dop init                                       first-run setup (generate age key)
  dop init --vault <path-or-url>                 attach a vault repo (option 3: local path OK)
  dop encrypt <plaintext.yaml> <encrypted.yaml>  encrypt a plaintext vault with your age key
  dop exec   [--vault PATH] [--agent-name NAME] [--clean-env] [--no-pull] -- CMD [ARGS...]
  dop whoami [--vault PATH]
  dop env    [--vault PATH]
  dop pull                                       git pull the vault clone
  dop push                                       stage/commit/push logs + vault changes
  dop merge-driver <base> <ours> <theirs>        internal: git merge driver (see .gitattributes)
  dop help

env:
  DOP_TOKEN         bearer auth token (required for exec/whoami/env)
  DOP_VAULT         default --vault path (overridable per-call)
  DOP_AUTO_PULL     max staleness before dop exec auto-pulls (Go duration, default 5m)
  SOPS_AGE_KEY_FILE overrides DOP's own age key path (advanced)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	// Point SOPS at DOP's key file by default so `vault.Load` on encrypted
	// vaults just works. Callers may override via SOPS_AGE_KEY_FILE.
	if os.Getenv("SOPS_AGE_KEY_FILE") == "" {
		if paths, err := config.Resolve(); err == nil {
			if _, statErr := os.Stat(paths.KeyFile); statErr == nil {
				os.Setenv("SOPS_AGE_KEY_FILE", paths.KeyFile)
			}
		}
	}

	switch os.Args[1] {
	case "init":
		os.Exit(runInit(os.Args[2:]))
	case "encrypt":
		os.Exit(runEncrypt(os.Args[2:]))
	case "exec":
		os.Exit(runExec(os.Args[2:]))
	case "whoami":
		os.Exit(runWhoami(os.Args[2:]))
	case "env":
		os.Exit(runEnv(os.Args[2:]))
	case "pull":
		os.Exit(runPull(os.Args[2:]))
	case "push":
		os.Exit(runPush(os.Args[2:]))
	case "merge-driver":
		os.Exit(runMergeDriver(os.Args[2:]))
	case "help", "-h", "--help":
		fmt.Print(usage)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "dop: unknown command %q\n\n", os.Args[1])
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func runInit(args []string) int {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	vaultSrc := fs.String("vault", "", "path or URL to a vault repo (creates a local bare repo if the path doesn't exist)")
	_ = fs.Parse(args)

	paths, err := initcmd.Init(os.Stderr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop init: %v\n", err)
		return 1
	}

	if *vaultSrc == "" {
		return 0
	}

	// Load our key to get the recipient for .sops.yaml
	id, err := loadAgeIdentity(paths.KeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop init: %v\n", err)
		return 1
	}
	if err := vaultgit.Attach(*vaultSrc, paths.Vault, id.Recipient().String(), os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "dop init --vault: %v\n", err)
		return 1
	}
	return 0
}

func runEncrypt(args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: dop encrypt <plaintext.yaml> <encrypted.yaml>")
		return 2
	}
	src, dst := args[0], args[1]

	paths, err := config.Resolve()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop encrypt: %v\n", err)
		return 1
	}
	id, err := loadAgeIdentity(paths.KeyFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop encrypt: %v (run `dop init` first?)\n", err)
		return 1
	}

	if _, err := os.Stat(src); err != nil {
		fmt.Fprintf(os.Stderr, "dop encrypt: %v\n", err)
		return 1
	}
	if err := encryptYAML(src, dst, id.Recipient().String()); err != nil {
		fmt.Fprintf(os.Stderr, "dop encrypt: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "dop encrypt: wrote %s (age recipient %s)\n", dst, id.Recipient())
	return 0
}

func runExec(args []string) int {
	fs := flag.NewFlagSet("exec", flag.ExitOnError)
	vaultPath := fs.String("vault", envOr("DOP_VAULT", defaultVaultPath()), "path to vault YAML")
	agentName := fs.String("agent-name", "", "self-reported agent identifier (audit only)")
	cleanEnv := fs.Bool("clean-env", false, "strip inherited env, keep only PATH/HOME/USER + injected")
	noPull := fs.Bool("no-pull", false, "skip the auto-pull freshness check")
	_ = fs.Parse(args)

	child := fs.Args()
	if len(child) == 0 {
		fmt.Fprintln(os.Stderr, "dop exec: missing command after --")
		return 2
	}

	if !*noPull {
		freshnessCheck(*vaultPath)
	}

	res, err := loadAndResolve(*vaultPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop exec: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr,
		"dop exec: agent=%q grants=%v env_keys=%d\n",
		*agentName, res.GrantsUsed, len(res.Env),
	)
	if err := execchild.Run(child, res.Env, *cleanEnv); err != nil {
		fmt.Fprintf(os.Stderr, "dop exec: %v\n", err)
		return 1
	}
	return 0
}

// freshnessCheck runs an auto-pull on the vault clone if the last pull was
// older than DOP_AUTO_PULL (default 5m). Never blocks — network errors are
// downgraded to warnings on stderr.
func freshnessCheck(vaultPath string) {
	if vaultPath == "" {
		return
	}
	// Auto-pull is only meaningful when the vault lives under a `dop init --vault`
	// clone (i.e. inside config.Paths.Vault). External vault paths are left alone.
	paths, err := config.Resolve()
	if err != nil {
		return
	}
	if !strings.HasPrefix(vaultPath, paths.Vault) {
		return
	}
	maxAge := 5 * time.Minute
	if v, ok := os.LookupEnv("DOP_AUTO_PULL"); ok && v != "" {
		if parsed, err := time.ParseDuration(v); err == nil {
			maxAge = parsed
		}
	}
	vaultsync.EnsureFresh(paths.Vault, maxAge, os.Stderr)
}

func runPull(args []string) int {
	fs := flag.NewFlagSet("pull", flag.ExitOnError)
	_ = fs.Parse(args)
	paths, err := config.Resolve()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop pull: %v\n", err)
		return 1
	}
	if err := vaultsync.Pull(paths.Vault, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "dop pull: %v\n", err)
		return 1
	}
	return 0
}

func runPush(args []string) int {
	fs := flag.NewFlagSet("push", flag.ExitOnError)
	_ = fs.Parse(args)
	paths, err := config.Resolve()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop push: %v\n", err)
		return 1
	}
	if err := vaultsync.Push(paths.Vault, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "dop push: %v\n", err)
		return 1
	}
	return 0
}

func runWhoami(args []string) int {
	fs := flag.NewFlagSet("whoami", flag.ExitOnError)
	vaultPath := fs.String("vault", envOr("DOP_VAULT", defaultVaultPath()), "path to vault YAML")
	_ = fs.Parse(args)

	res, err := loadAndResolve(*vaultPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop whoami: %v\n", err)
		return 1
	}
	fmt.Printf("token: %s (name: %s)\n", tokenID(res.TokenID), res.TokenID)
	fmt.Printf("grants:\n")
	for _, g := range res.GrantsUsed {
		fmt.Printf("  - %s\n", g)
	}
	return 0
}

func runEnv(args []string) int {
	fs := flag.NewFlagSet("env", flag.ExitOnError)
	vaultPath := fs.String("vault", envOr("DOP_VAULT", defaultVaultPath()), "path to vault YAML")
	_ = fs.Parse(args)

	res, err := loadAndResolve(*vaultPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop env: %v\n", err)
		return 1
	}
	sort.Strings(res.Env)
	for _, kv := range res.Env {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			fmt.Printf("export %s='%s'\n", kv[:i], kv[i+1:])
		}
	}
	return 0
}

// runMergeDriver is the git merge driver hook (P1.b).
//
// git invokes:  dop merge-driver <base> <ours> <theirs>
//   %O — path to base (ancestor) copy
//   %A — path to our copy (git overwrites this on success with merged content)
//   %B — path to their copy
//
// Behavior:
//   1. Decrypt each side to plaintext YAML (skipping decrypt for empty/missing files)
//   2. Run yamlmerge.Merge for a structural three-way merge
//   3. If clean, re-encrypt the result and write it back to %A
//   4. If conflicting, print the conflict paths and exit non-zero so git
//      shows the conflict to the human (encrypted %A stays intact)
func runMergeDriver(args []string) int {
	if len(args) < 3 {
		fmt.Fprintln(os.Stderr, "dop merge-driver: expected <base> <ours> <theirs>")
		return 2
	}
	basePath, oursPath, theirsPath := args[0], args[1], args[2]

	base, err := decryptForMerge(basePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop merge-driver: decrypt base %s: %v\n", basePath, err)
		return 1
	}
	ours, err := decryptForMerge(oursPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop merge-driver: decrypt ours %s: %v\n", oursPath, err)
		return 1
	}
	theirs, err := decryptForMerge(theirsPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop merge-driver: decrypt theirs %s: %v\n", theirsPath, err)
		return 1
	}

	res, err := yamlmerge.Merge(base, ours, theirs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop merge-driver: %v\n", err)
		return 1
	}
	if len(res.Conflicts) > 0 {
		fmt.Fprintln(os.Stderr, "dop merge-driver: unresolved conflicts:")
		for _, p := range res.Conflicts {
			fmt.Fprintln(os.Stderr, "  -", p)
		}
		return 1
	}

	mergedPlain, err := yamlmerge.EmitBytes(res.Merged)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop merge-driver: emit merged YAML: %v\n", err)
		return 1
	}

	// Re-encrypt with sops using the age recipient from vault's .sops.yaml.
	// Because sops --encrypt takes a filepath, stage the plaintext in a tempfile.
	tmp, err := os.CreateTemp("", "dop-merge-*.yaml")
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop merge-driver: %v\n", err)
		return 1
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(mergedPlain); err != nil {
		tmp.Close()
		fmt.Fprintf(os.Stderr, "dop merge-driver: %v\n", err)
		return 1
	}
	tmp.Close()

	// Rely on .sops.yaml in the working tree to select recipients.
	cmd := exec.Command("sops", "--encrypt", "--input-type", "yaml", "--output-type", "yaml", "--output", oursPath, tmpPath)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "dop merge-driver: sops encrypt: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "dop merge-driver: merged cleanly")
	return 0
}

// decryptForMerge returns plaintext YAML for one side of the merge. Empty
// or missing files return an empty document — matches yamlmerge's nil-safe
// semantics for adds/deletes.
func decryptForMerge(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}
	if !isSOPSEnvelope(raw) {
		return raw, nil
	}
	// Explicit --input-type yaml — git passes temp file paths without a .yaml
	// suffix, and sops otherwise falls back to JSON parsing.
	cmd := exec.Command("sops", "--decrypt", "--input-type", "yaml", "--output-type", "yaml", path)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("sops --decrypt: %s (%w)", stderr.String(), err)
	}
	return stdout.Bytes(), nil
}

func isSOPSEnvelope(raw []byte) bool {
	return bytes.Contains(raw, []byte("\nsops:")) || bytes.HasPrefix(raw, []byte("sops:"))
}

func loadAndResolve(vaultPath string) (*resolve.Resolution, error) {
	if vaultPath == "" {
		return nil, fmt.Errorf("no vault path (--vault, $DOP_VAULT, or run `dop init --vault ...` to attach one)")
	}
	v, err := vault.Load(vaultPath)
	if err != nil {
		return nil, err
	}
	bearer := os.Getenv("DOP_TOKEN")
	return resolve.Resolve(v, bearer)
}

func defaultVaultPath() string {
	paths, err := config.Resolve()
	if err != nil {
		return ""
	}
	candidate := paths.Vault + "/vault.yaml"
	if _, err := os.Stat(candidate); err == nil {
		return candidate
	}
	return ""
}

func loadAgeIdentity(path string) (*age.X25519Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open key file: %w", err)
	}
	defer f.Close()
	ids, err := age.ParseIdentities(f)
	if err != nil {
		return nil, fmt.Errorf("parse identities: %w", err)
	}
	for _, id := range ids {
		if x, ok := id.(*age.X25519Identity); ok {
			return x, nil
		}
	}
	return nil, fmt.Errorf("no X25519 identity in %s", path)
}

// encryptYAML shells out to the `sops` binary to wrap a plaintext YAML file
// in a SOPS+age envelope. This is a rare admin operation (a few times per
// vault) — programmatic encrypt via the sops Go API is thorny enough that
// depending on the CLI is the pragmatic choice for P1.
//
// Runtime dep: `sops` (>=3.7) must be on $PATH. `dop doctor` (P8) will assert
// this. If missing, we return a clear installation hint rather than a
// cryptic exec error.
func encryptYAML(plaintextPath, encryptedPath, ageRecipient string) error {
	if _, err := exec.LookPath("sops"); err != nil {
		return fmt.Errorf("sops binary not found in $PATH — install via `brew install sops` or from https://github.com/getsops/sops/releases")
	}
	cmd := exec.Command("sops", "--encrypt", "--age", ageRecipient, "--output", encryptedPath, plaintextPath)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sops encrypt: %w", err)
	}
	return nil
}

func tokenID(bearer string) string {
	if len(bearer) <= 12 {
		return bearer
	}
	return bearer[:12] + "…"
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}
