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
	"github.com/fray/dop/internal/trust"
	"github.com/fray/dop/internal/vault"
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
	if rc := attachRepo(source, paths.Vault, false); rc != 0 {
		return rc
	}
	// v1.6.3 — bootstrap admins.trust on first attach if a session is
	// already active. This is the chicken-and-egg fix: an admin who
	// runs `admin init` + `init --vault` but no `token issue` never
	// wrote admins.trust, so agent clones couldn't verify signatures.
	// Best-effort; requires an unlocked session because trust.Write
	// needs the admin pubkey from status.
	if err := seedTrustIfPossible(paths); err != nil {
		fmt.Fprintf(os.Stderr, "dop init: trust seed skipped: %v\n", err)
	}
	return 0
}

// seedTrustIfPossible writes an initial admins.trust with just this
// admin's pubkey — but only if we have an active admin session AND the
// trust file doesn't already exist. Silent no-op otherwise; the trust
// file will land at first `token issue` via saveVaultViaDaemon.
//
// The stat guard matters when a second admin joins an existing vault:
// their `dop init --vault` must NOT overwrite the trust list that
// already includes the first admin (v1.6.3 shipped without this guard;
// caught in third-pass review).
func seedTrustIfPossible(paths *config.Paths) error {
	client := admin.NewClient(admin.SockPath(paths))
	if !client.SessionActive() {
		return nil
	}
	if _, err := os.Stat(trust.Path(paths)); err == nil {
		return nil // don't clobber an existing trust list
	}
	st, err := client.Status()
	if err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "admin"
	}
	v := &vault.Vault{
		SchemaVersion: vault.SchemaVersion,
		Admins: map[string]vault.Admin{
			hostname: {
				AgeRecipient:  st.AgeRecipient,
				Ed25519Pubkey: st.AdminPubkey,
				Note:          "self",
			},
		},
	}
	return trust.Write(paths, v)
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
	// v1.6.3 — seed a .gitignore inside the vault dir so temp files
	// from atomic renames or SOPS staging never get accidentally
	// committed. Idempotent: skip if already present.
	if err := ensureVaultGitignore(dest); err != nil {
		fmt.Fprintf(os.Stderr, "dop init: warning: %v\n", err)
	}
	fmt.Fprintf(os.Stderr, "dop init: vault attached at %s (%s)\n", dest, kind)
	return 0
}

// ensureVaultGitignore writes a minimal .gitignore inside the vault
// checkout the first time we attach. Prevents editor swap files, SOPS
// staging tempfiles, and atomic-rename leftovers from being committed
// by `dop push` (which does `git add -A`).
func ensureVaultGitignore(dest string) error {
	p := filepath.Join(dest, ".gitignore")
	if _, err := os.Stat(p); err == nil {
		return nil
	}
	body := `# DOP-managed vault checkout — never commit these
.dop-encrypt-*.yaml
.vault-edit-*.yaml
*.tmp
*.swp
.DS_Store
`
	return os.WriteFile(p, []byte(body), 0o644)
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
	fs := flag.NewFlagSet("pull", flag.ExitOnError)
	takeTheirs := fs.Bool("take-theirs", false, "discard local commits, force-reset to origin (DATA LOSS)")
	takeOurs := fs.Bool("take-ours", false, "keep local commits, force-push over origin on next push (DATA LOSS on remote)")
	_ = fs.Parse(args)

	paths, _ := config.Resolve()

	// Destructive strategies short-circuit — no need to try FF first.
	if *takeTheirs && *takeOurs {
		fmt.Fprintln(os.Stderr, "dop pull: --take-theirs and --take-ours are mutually exclusive")
		return 2
	}
	if *takeTheirs {
		return pullTakeTheirs(paths)
	}
	if *takeOurs {
		return pullTakeOurs(paths)
	}

	// Default: try fast-forward first (safe).
	if err := runGit(io.Discard, paths.Vault, "pull", "--ff-only"); err == nil {
		fmt.Fprintln(os.Stderr, "dop pull: fast-forwarded to origin.")
		return 0
	}

	// FF failed → figure out why so we can give an actionable error.
	// Fetch first so origin/main is up to date.
	if err := runGit(io.Discard, paths.Vault, "fetch", "origin"); err != nil {
		fmt.Fprintf(os.Stderr, "dop pull: fetch failed: %v\n", err)
		return 1
	}
	// Count commits in each direction. `git rev-list --count A..B`.
	ahead, _ := gitRevListCount(paths.Vault, "origin/main..HEAD")
	behind, _ := gitRevListCount(paths.Vault, "HEAD..origin/main")
	if ahead == 0 && behind == 0 {
		fmt.Fprintln(os.Stderr, "dop pull: up-to-date (nothing to pull).")
		return 0
	}
	if ahead == 0 && behind > 0 {
		// This shouldn't happen if --ff-only failed, but handle it anyway.
		if err := runGit(os.Stderr, paths.Vault, "merge", "--ff-only", "origin/main"); err != nil {
			fmt.Fprintf(os.Stderr, "dop pull: %v\n", err)
			return 1
		}
		return 0
	}
	// Diverged. Vault is sops-encrypted, so text-merge on vault.yaml
	// almost always produces garbage. Refuse to guess.
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintf(os.Stderr, "dop pull: local and origin have diverged.\n")
	fmt.Fprintf(os.Stderr, "  your branch is ahead by %d commit(s) and behind by %d.\n\n", ahead, behind)
	fmt.Fprintln(os.Stderr, "your local commits (top = newest):")
	_ = runGit(os.Stderr, paths.Vault, "log", "--oneline", "-n", "10", "origin/main..HEAD")
	fmt.Fprintln(os.Stderr, "\nremote commits you don't have:")
	_ = runGit(os.Stderr, paths.Vault, "log", "--oneline", "-n", "10", "HEAD..origin/main")
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "vault.yaml is sops-encrypted; git text-merge will corrupt it. Options:")
	fmt.Fprintln(os.Stderr, "  dop pull --take-theirs   discard YOUR local commits (safe if remote has everything you need)")
	fmt.Fprintln(os.Stderr, "  dop pull --take-ours     keep local, override remote on next `dop push --force`")
	fmt.Fprintln(os.Stderr, "  manual                   `git merge origin/main` + resolve vault.yaml by re-adding")
	fmt.Fprintln(os.Stderr, "                           any changes lost via `dop token issue` / `dop integration add` etc.")
	return 1
}

// pullTakeTheirs discards local commits and hard-resets to origin/main.
// Destructive — the operator asked for it, we do it after a heads-up
// git reflog line so recovery is at least discoverable.
func pullTakeTheirs(paths *config.Paths) int {
	if err := runGit(io.Discard, paths.Vault, "fetch", "origin"); err != nil {
		fmt.Fprintf(os.Stderr, "dop pull --take-theirs: fetch: %v\n", err)
		return 1
	}
	// Reflog anchor so `git reset --keep ORIG_HEAD` can recover.
	fmt.Fprintln(os.Stderr, "dop pull --take-theirs: discarding local commits. Recovery: `git reflog` shows the pre-reset HEAD.")
	if err := runGit(os.Stderr, paths.Vault, "reset", "--hard", "origin/main"); err != nil {
		fmt.Fprintf(os.Stderr, "dop pull --take-theirs: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "dop pull --take-theirs: reset to origin/main.")
	return 0
}

// pullTakeOurs is essentially a no-op on the working tree — it just
// tells the operator how to force-push their local state over origin
// on the next push.
func pullTakeOurs(paths *config.Paths) int {
	_ = runGit(io.Discard, paths.Vault, "fetch", "origin")
	ahead, _ := gitRevListCount(paths.Vault, "origin/main..HEAD")
	behind, _ := gitRevListCount(paths.Vault, "HEAD..origin/main")
	fmt.Fprintf(os.Stderr, "dop pull --take-ours: keeping local (ahead=%d, behind=%d).\n", ahead, behind)
	if behind > 0 {
		fmt.Fprintln(os.Stderr, "  origin has commits your local doesn't; to override them on next push:")
		fmt.Fprintln(os.Stderr, "    dop push --force   (or: git push --force-with-lease origin main)")
	} else {
		fmt.Fprintln(os.Stderr, "  origin is already an ancestor of your local — `dop push` will fast-forward.")
	}
	return 0
}

// gitRevListCount returns the number of commits in a rev-list range.
// Returns 0 on any error so the caller doesn't have to branch on it.
func gitRevListCount(dir, rng string) (int, error) {
	cmd := exec.Command("git", "rev-list", "--count", rng)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, r := range strings.TrimSpace(string(out)) {
		if r < '0' || r > '9' {
			return 0, nil
		}
		n = n*10 + int(r-'0')
	}
	return n, nil
}

func runPush(args []string) int {
	fs := flag.NewFlagSet("push", flag.ExitOnError)
	force := fs.Bool("force", false, "use --force-with-lease to override remote (pairs with `dop pull --take-ours`)")
	_ = fs.Parse(args)

	paths, _ := config.Resolve()
	// Best-effort add + commit; ignore no-changes exit.
	_ = runGit(os.Stderr, paths.Vault, "add", "-A")
	_ = runGitAllowExit(os.Stderr, paths.Vault, []int{0, 1}, "commit", "-m", "dop: sync")
	pushArgs := []string{"push"}
	if *force {
		pushArgs = append(pushArgs, "--force-with-lease")
	}
	if err := runGit(os.Stderr, paths.Vault, pushArgs...); err != nil {
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
