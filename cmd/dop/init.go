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

// runPull — plain-English driver over a real 3-way vault merge.
//
// Terminology used in the operator-facing output (no git jargon):
//   "your machine"  — HEAD, the local checkout
//   "the team"      — origin/main, what the remote holds
//   "your changes"  — commits ahead of the shared point
//   "team changes"  — commits behind (that you haven't pulled)
//   "merged vault"  — the decrypted-then-unioned result
//
// Flags:
//   --keep-mine    force-take local state (was: --take-ours). Preserved
//                  as an alias for muscle memory.
//   --keep-team    force-take remote state (was: --take-theirs).
//   --no-merge     print diagnosis and stop; do not attempt to merge.
func runPull(args []string) int {
	fs := flag.NewFlagSet("pull", flag.ExitOnError)
	keepTeam := fs.Bool("keep-team", false, "throw away your changes, use the team's version")
	keepMine := fs.Bool("keep-mine", false, "throw away the team's changes, use your version (needs `dop push --force` next)")
	noMerge := fs.Bool("no-merge", false, "diagnose only; do not attempt to merge")
	// Back-compat aliases from v1.10.1.
	takeTheirs := fs.Bool("take-theirs", false, "alias for --keep-team")
	takeOurs := fs.Bool("take-ours", false, "alias for --keep-mine")
	_ = fs.Parse(args)

	if *takeTheirs {
		*keepTeam = true
	}
	if *takeOurs {
		*keepMine = true
	}
	if *keepTeam && *keepMine {
		fmt.Fprintln(os.Stderr, "dop pull: pick one — either --keep-mine or --keep-team, not both.")
		return 2
	}

	paths, _ := config.Resolve()

	// Step 1: try the boring case first — nothing on our side, just fetch.
	if err := runGit(io.Discard, paths.Vault, "pull", "--ff-only"); err == nil {
		fmt.Fprintln(os.Stderr, "dop pull: your machine is now up to date with the team.")
		return 0
	}

	// Step 2: figure out where we stand.
	if err := runGit(io.Discard, paths.Vault, "fetch", "origin"); err != nil {
		fmt.Fprintf(os.Stderr, "dop pull: couldn't reach the team's vault (%v). Check your network / git remote.\n", err)
		return 1
	}
	ours, _ := gitRevListCount(paths.Vault, "origin/main..HEAD")
	theirs, _ := gitRevListCount(paths.Vault, "HEAD..origin/main")
	if ours == 0 && theirs == 0 {
		fmt.Fprintln(os.Stderr, "dop pull: your machine is already up to date with the team.")
		return 0
	}
	if ours == 0 {
		// Just behind — this shouldn't happen after --ff-only failed,
		// but if it does, do the safe thing.
		if err := runGit(os.Stderr, paths.Vault, "merge", "--ff-only", "origin/main"); err != nil {
			fmt.Fprintf(os.Stderr, "dop pull: %v\n", err)
			return 1
		}
		return 0
	}

	// Step 3: both sides changed. Handle the escape hatches first.
	if *keepTeam {
		return pullKeepTeam(paths)
	}
	if *keepMine {
		return pullKeepMine(paths, ours, theirs)
	}
	if *noMerge {
		printPullDivergedIntro(paths, ours, theirs)
		fmt.Fprintln(os.Stderr, "Your options:")
		fmt.Fprintln(os.Stderr, "  dop pull                merge both sides (this is what you probably want)")
		fmt.Fprintln(os.Stderr, "  dop pull --keep-mine    throw away the team's changes, keep yours")
		fmt.Fprintln(os.Stderr, "  dop pull --keep-team    throw away your changes, take the team's")
		fmt.Fprintln(os.Stderr, "  (--no-merge: stopping here; drop the flag to attempt the auto-merge.)")
		return 1
	}

	// Step 4: real 3-way merge on the decrypted plaintext.
	return pullSmartMerge(paths, ours, theirs)
}

// printPullDivergedIntro prints the plain-English header explaining
// what happened. Used by --no-merge and by the smart-merge path when
// there's a genuine conflict.
func printPullDivergedIntro(paths *config.Paths, ours, theirs int) {
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "Your vault and the team's have both moved on separately since you last synced.")
	fmt.Fprintf(os.Stderr, "  You made:   %d change(s) here.\n", ours)
	fmt.Fprintf(os.Stderr, "  Team made:  %d change(s) upstream.\n\n", theirs)
	fmt.Fprintln(os.Stderr, "Your recent local changes (newest first):")
	_ = runGit(os.Stderr, paths.Vault, "log", "--oneline", "-n", "10", "origin/main..HEAD")
	fmt.Fprintln(os.Stderr, "\nTeam changes you don't have yet:")
	_ = runGit(os.Stderr, paths.Vault, "log", "--oneline", "-n", "10", "HEAD..origin/main")
	fmt.Fprintln(os.Stderr, "")
}

// pullKeepTeam replaces your local state with the team's, discarding
// your local commits. Non-recoverable via `dop` (git reflog remains).
func pullKeepTeam(paths *config.Paths) int {
	fmt.Fprintln(os.Stderr, "dop pull --keep-team: throwing away your local changes and taking the team's version.")
	fmt.Fprintln(os.Stderr, "  (Your discarded commits stay in git's reflog for a while if you need to recover them:")
	fmt.Fprintln(os.Stderr, "     git -C \""+paths.Vault+"\" reflog show HEAD )")
	if err := runGit(os.Stderr, paths.Vault, "reset", "--hard", "origin/main"); err != nil {
		fmt.Fprintf(os.Stderr, "dop pull --keep-team: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "dop pull --keep-team: your vault now matches the team's.")
	return 0
}

// pullKeepMine tells the user how to force the team's vault to match
// theirs on the next push. It doesn't modify the working tree.
func pullKeepMine(paths *config.Paths, ours, theirs int) int {
	fmt.Fprintf(os.Stderr, "dop pull --keep-mine: keeping your %d local change(s); the %d team change(s) will be overwritten.\n", ours, theirs)
	fmt.Fprintln(os.Stderr, "  To push your version and overwrite the team's, run:")
	fmt.Fprintln(os.Stderr, "     dop push --force")
	fmt.Fprintln(os.Stderr, "  This is not reversible from the team side. Only do this if you're sure.")
	return 0
}

// pullSmartMerge decrypts local + remote + common-ancestor vaults,
// three-way merges them, and either commits the merged result (clean
// merge) or prints plain-English conflicts and lets the operator
// choose --keep-mine / --keep-team.
func pullSmartMerge(paths *config.Paths, ours, theirs int) int {
	fmt.Fprintln(os.Stderr, "dop pull: your changes and the team's both need to land. Merging safely…")

	// Find the common ancestor.
	base, err := gitMergeBase(paths.Vault, "HEAD", "origin/main")
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop pull: couldn't find a shared history point with the team (%v).\n", err)
		fmt.Fprintln(os.Stderr, "  This usually means the two vaults were created independently. Fix:")
		fmt.Fprintln(os.Stderr, "     dop pull --keep-team    to abandon your local vault, or")
		fmt.Fprintln(os.Stderr, "     dop pull --keep-mine    to overwrite the team's on next push.")
		return 1
	}

	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop pull: %v — an admin session is required to decrypt vaults for merging.\n", err)
		return 1
	}

	// Extract + decrypt all three sides.
	localV, err := decryptVaultAtRef(client, paths, "HEAD")
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop pull: couldn't decrypt your local vault: %v\n", err)
		return 1
	}
	remoteV, err := decryptVaultAtRef(client, paths, "origin/main")
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop pull: couldn't decrypt the team's vault: %v\n", err)
		return 1
	}
	baseV, err := decryptVaultAtRef(client, paths, base)
	if err != nil {
		// Missing ancestor version isn't fatal — treat as empty.
		baseV = &vault.Vault{}
	}

	result := vault.Merge(baseV, localV, remoteV)

	if len(result.Conflicts) > 0 {
		printPullDivergedIntro(paths, ours, theirs)
		fmt.Fprintln(os.Stderr, "Both sides changed the same thing in incompatible ways:")
		for _, c := range result.Conflicts {
			fmt.Fprintf(os.Stderr, "  • %s — %s\n", c.Path, c.Reason)
			fmt.Fprintf(os.Stderr, "      your version:  %s\n", c.Local)
			fmt.Fprintf(os.Stderr, "      team version:  %s\n", c.Remote)
		}
		fmt.Fprintln(os.Stderr, "")
		fmt.Fprintln(os.Stderr, "DOP won't guess. Pick one:")
		fmt.Fprintln(os.Stderr, "  dop pull --keep-mine    keep your version, discard the team's changes for these entries")
		fmt.Fprintln(os.Stderr, "  dop pull --keep-team    take the team's version, discard yours")
		fmt.Fprintln(os.Stderr, "  or:  open `dop vault edit`, reconcile by hand, then `dop push`.")
		return 1
	}

	// No conflicts → commit the merged plaintext.
	if err := saveMergedVault(client, paths, result.Merged); err != nil {
		fmt.Fprintf(os.Stderr, "dop pull: couldn't save the merged vault: %v\n", err)
		return 1
	}

	// Make a real merge commit so history reflects both sides.
	// -s ours accepts the other side's commits into history without
	// changing our tree (we already wrote the merged vault ourselves).
	if err := runGit(os.Stderr, paths.Vault, "merge", "-s", "ours", "origin/main",
		"--no-ff", "-m", "dop: merged your changes with the team's"); err != nil {
		fmt.Fprintf(os.Stderr, "dop pull: git couldn't finalize the merge commit: %v\n", err)
		return 1
	}

	// Print plain-English summary.
	s := result.Summary
	fmt.Fprintln(os.Stderr, "")
	fmt.Fprintln(os.Stderr, "dop pull: merged cleanly.")
	if len(s.AddedIntegrations) > 0 {
		fmt.Fprintf(os.Stderr, "  + integrations added: %v\n", s.AddedIntegrations)
	}
	if len(s.RemovedIntegrations) > 0 {
		fmt.Fprintf(os.Stderr, "  - integrations removed: %v\n", s.RemovedIntegrations)
	}
	if len(s.AddedGrants) > 0 {
		fmt.Fprintf(os.Stderr, "  + grants added: %v\n", s.AddedGrants)
	}
	if len(s.RemovedGrants) > 0 {
		fmt.Fprintf(os.Stderr, "  - grants removed: %v\n", s.RemovedGrants)
	}
	if s.AddedCapabilities > 0 {
		fmt.Fprintf(os.Stderr, "  + %d issued token(s) added\n", s.AddedCapabilities)
	}
	if s.RemovedCapabilities > 0 {
		fmt.Fprintf(os.Stderr, "  - %d issued token(s) removed (revoked or deleted)\n", s.RemovedCapabilities)
	}
	if len(s.AddedAdmins) > 0 {
		fmt.Fprintf(os.Stderr, "  + admins added: %v\n", s.AddedAdmins)
	}
	if len(s.RemovedAdmins) > 0 {
		fmt.Fprintf(os.Stderr, "  - admins removed: %v\n", s.RemovedAdmins)
	}
	fmt.Fprintln(os.Stderr, "  Push your merge back to the team with `dop push`.")
	return 0
}

// decryptVaultAtRef reads vault.yaml at a specific git ref, writes it
// to a temp file, and asks the daemon to decrypt + parse it.
func decryptVaultAtRef(client *admin.Client, paths *config.Paths, ref string) (*vault.Vault, error) {
	cmd := exec.Command("git", "show", ref+":vault.yaml")
	cmd.Dir = paths.Vault
	enc, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("read vault.yaml at %s: %w", ref, err)
	}
	tmp, err := os.CreateTemp("", "dop-pull-*.enc.yaml")
	if err != nil {
		return nil, err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(enc); err != nil {
		tmp.Close()
		return nil, err
	}
	tmp.Close()
	plain, err := client.DecryptVault(tmp.Name())
	if err != nil {
		// Might already be plaintext (older vaults).
		if v, perr := vault.ParsePlain(enc); perr == nil {
			return v, nil
		}
		return nil, err
	}
	return vault.ParsePlain(plain)
}

// saveMergedVault re-encrypts + writes the merged vault via the daemon,
// respecting the admin recipient list already in place.
func saveMergedVault(client *admin.Client, paths *config.Paths, v *vault.Vault) error {
	vp := paths.Vault + "/vault.yaml"
	return saveVaultViaDaemon(client, paths, vp, v)
}

// gitMergeBase returns the commit hash both refs share as an ancestor.
func gitMergeBase(dir, a, b string) (string, error) {
	cmd := exec.Command("git", "merge-base", a, b)
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
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
