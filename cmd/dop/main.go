// dop — Doors of Perception CLI.
//
// P0 wire path (walking skeleton): vault load → resolve → exec.
// P1 adds: age key management, SOPS-encrypted vault, `dop init`.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"time"

	"github.com/fray/dop/internal/agentauth"
	"github.com/fray/dop/internal/audit"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/execchild"
	"github.com/fray/dop/internal/initcmd"
	"github.com/fray/dop/internal/resolve"
	"github.com/fray/dop/internal/tokenio"
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
  dop exec   [--vault PATH] [--agent-name NAME] [--sign-with KEYFILE] [--clean-env] [--no-pull] -- CMD [ARGS...]
  dop whoami [--vault PATH]
  dop env    [--vault PATH]
  dop pull                                       git pull the vault clone
  dop push                                       stage/commit/push logs + vault changes
  dop token issue --grants g1,g2 [--name X] [--expires D] [--note T]  mint a new auth token
  dop token list [--vault PATH]                  show active tokens (never prints bearer values)
  dop token revoke <name-or-prefix>              remove a token from the vault
  dop log tail [--n N]                           print recent audit log lines
  dop log grep KEY=VAL [KEY=VAL...]              filter audit log by JSON field equality
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
	case "token":
		os.Exit(runToken(os.Args[2:]))
	case "log":
		os.Exit(runLog(os.Args[2:]))
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
	agentName := fs.String("agent-name", "", "self-reported agent identifier (audit only) OR the agent_pubkeys key when --sign-with is used")
	signWith := fs.String("sign-with", "", "path to age private key file for signed-challenge auth (skips DOP_TOKEN)")
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

	auditor := auditWriter()
	cmdHead := audit.TruncCmdHead(child)

	res, authMethod, err := resolveAuth(*vaultPath, *signWith, *agentName)
	if err != nil {
		_ = auditor.Log(audit.Event{
			Op:         "exec",
			AgentName:  *agentName,
			AuthMethod: authMethod,
			TokenHash:  audit.HashBearer(os.Getenv("DOP_TOKEN")),
			Outcome:    "denied",
			Reason:     err.Error(),
			CmdHead:    cmdHead,
		})
		fmt.Fprintf(os.Stderr, "dop exec: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr,
		"dop exec: agent=%q auth=%s grants=%v env_keys=%d\n",
		*agentName, authMethod, res.GrantsUsed, len(res.Env),
	)
	// Log BEFORE exec — the syscall replaces this process, so a post-exec
	// log write would never run. Outcome "ok" here means "we successfully
	// resolved credentials"; whether the child command succeeds is out of scope.
	_ = auditor.Log(audit.Event{
		Op:         "exec",
		AgentName:  *agentName,
		AuthMethod: authMethod,
		TokenHash:  audit.HashBearer(res.TokenID),
		Grants:     res.GrantsUsed,
		Outcome:    "ok",
		CmdHead:    cmdHead,
	})
	if err := execchild.Run(child, res.Env, *cleanEnv); err != nil {
		fmt.Fprintf(os.Stderr, "dop exec: %v\n", err)
		return 1
	}
	return 0
}

// auditWriter returns a Writer scoped to the DOP config logs dir. Returns
// a no-op Writer if config resolution fails — audit is best-effort, never
// blocks the hot path.
func auditWriter() *audit.Writer {
	paths, err := config.Resolve()
	if err != nil {
		return audit.New("")
	}
	return audit.New(paths.Logs)
}

// resolveAuth picks between bearer-token and signed-challenge auth based
// on flag presence, then builds the env from the resolved grants.
func resolveAuth(vaultPath, signWith, agentName string) (*resolve.Resolution, string, error) {
	if vaultPath == "" {
		return nil, "", fmt.Errorf("no vault path (--vault or $DOP_VAULT)")
	}
	v, err := vault.Load(vaultPath)
	if err != nil {
		return nil, "", err
	}
	if signWith != "" {
		grants, err := agentauth.Verify(v, agentName, signWith)
		if err != nil {
			return nil, "signed", err
		}
		return buildResolutionFromGrants(v, agentName, grants)
	}
	bearer := os.Getenv("DOP_TOKEN")
	res, err := resolve.Resolve(v, bearer)
	if err != nil {
		return nil, "bearer", err
	}
	return res, "bearer", nil
}

// buildResolutionFromGrants materializes env vars for a grant list, without
// going through the bearer→auth_tokens lookup. Used for signed-challenge auth.
func buildResolutionFromGrants(v *vault.Vault, tokenID string, grants []string) (*resolve.Resolution, string, error) {
	// Reuse resolve's env-building logic via a synthetic auth-token entry.
	// Insert a temporary auth_token into an in-memory copy of the vault so we
	// can call resolve.Resolve with a bearer string.
	synthetic := "signed:" + tokenID
	if v.AuthTokens == nil {
		v.AuthTokens = map[string]vault.AuthToken{}
	}
	v.AuthTokens[synthetic] = vault.AuthToken{
		Name:   "signed:" + tokenID,
		Grants: grants,
	}
	res, err := resolve.Resolve(v, synthetic)
	// Remove our synthetic entry from the caller-visible vault (defensive; we
	// don't persist v anywhere but be tidy).
	delete(v.AuthTokens, synthetic)
	if err != nil {
		return nil, "signed", err
	}
	res.TokenID = "signed:" + tokenID
	return res, "signed", nil
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

// runToken dispatches `dop token <issue|list|revoke>`.
func runToken(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: dop token <issue|list|revoke> ...")
		return 2
	}
	switch args[0] {
	case "issue":
		return runTokenIssue(args[1:])
	case "list":
		return runTokenList(args[1:])
	case "revoke":
		return runTokenRevoke(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "dop token: unknown subcommand %q\n", args[0])
		return 2
	}
}

func runTokenIssue(args []string) int {
	fs := flag.NewFlagSet("token issue", flag.ExitOnError)
	vaultPath := fs.String("vault", envOr("DOP_VAULT", defaultVaultPath()), "path to vault YAML")
	grantsCSV := fs.String("grants", "", "comma-separated grant IDs (required)")
	name := fs.String("name", "", "human-readable label for this token")
	expires := fs.String("expires", "", "expiry date (YYYY-MM-DD) — optional")
	note := fs.String("note", "", "free-text note")
	yes := fs.Bool("yes", false, "skip confirmation for sensitive grants (scripting)")
	_ = fs.Parse(args)

	if *vaultPath == "" {
		fmt.Fprintln(os.Stderr, "dop token issue: no vault path (--vault or $DOP_VAULT)")
		return 1
	}
	if strings.TrimSpace(*grantsCSV) == "" {
		fmt.Fprintln(os.Stderr, "dop token issue: --grants is required")
		return 2
	}
	grants := splitCSV(*grantsCSV)

	plain, err := tokenio.LoadPlain(*vaultPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token issue: %v\n", err)
		return 1
	}
	root, err := tokenio.ParseTree(plain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token issue: %v\n", err)
		return 1
	}

	known := tokenio.KnownGrants(root)
	for _, g := range grants {
		if !known[g] {
			fmt.Fprintf(os.Stderr, "dop token issue: unknown grant %q\n", g)
			return 1
		}
	}

	// Confirmation gate for sensitive scopes. Best-effort friction (documented
	// in ARCHITECTURE.md), not a security boundary.
	sensitive := tokenio.SensitiveGrants(root, grants)
	if len(sensitive) > 0 && !*yes {
		fmt.Fprintf(os.Stderr, "dop token issue: this token will unlock sensitive grants: %v\n", sensitive)
		fmt.Fprint(os.Stderr, "  type YES to continue: ")
		var answer string
		fmt.Fscanln(os.Stdin, &answer)
		if strings.TrimSpace(answer) != "YES" {
			fmt.Fprintln(os.Stderr, "dop token issue: aborted")
			return 1
		}
	}

	bearer, err := tokenio.TokenBearer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token issue: %v\n", err)
		return 1
	}
	rec := tokenio.TokenRecord{
		Name:      *name,
		Grants:    grants,
		ExpiresAt: *expires,
		Note:      *note,
	}
	if rec.Name == "" {
		rec.Name = "token-" + bearer[4:12]
	}
	if err := tokenio.AddAuthToken(root, bearer, rec, currentActor()); err != nil {
		fmt.Fprintf(os.Stderr, "dop token issue: %v\n", err)
		return 1
	}
	out, err := tokenio.EmitTree(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token issue: %v\n", err)
		return 1
	}
	if err := tokenio.SavePlain(*vaultPath, out); err != nil {
		fmt.Fprintf(os.Stderr, "dop token issue: %v\n", err)
		return 1
	}

	// The bearer is the secret — print it once on stdout, keep audit metadata on stderr.
	fmt.Fprintf(os.Stderr, "dop token issue: issued %q (grants: %v)\n", rec.Name, grants)
	fmt.Fprintln(os.Stderr, "  keep the bearer below safe — it is printed ONCE:")
	fmt.Println(bearer)
	_ = auditWriter().Log(audit.Event{
		Op:         "token-issue",
		AgentName:  rec.Name,
		AuthMethod: "-",
		TokenHash:  audit.HashBearer(bearer),
		Grants:     grants,
		Outcome:    "ok",
	})
	return 0
}

func runTokenList(args []string) int {
	fs := flag.NewFlagSet("token list", flag.ExitOnError)
	vaultPath := fs.String("vault", envOr("DOP_VAULT", defaultVaultPath()), "path to vault YAML")
	_ = fs.Parse(args)
	if *vaultPath == "" {
		fmt.Fprintln(os.Stderr, "dop token list: no vault path")
		return 1
	}
	plain, err := tokenio.LoadPlain(*vaultPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token list: %v\n", err)
		return 1
	}
	root, err := tokenio.ParseTree(plain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token list: %v\n", err)
		return 1
	}
	recs := tokenio.ListTokens(root)
	if len(recs) == 0 {
		fmt.Println("(no tokens)")
		return 0
	}
	for _, r := range recs {
		exp := r.ExpiresAt
		if exp == "" {
			exp = "-"
		}
		fmt.Printf("- %s  grants=%v  created=%s  expires=%s\n", r.Name, r.Grants, r.CreatedAt, exp)
		if r.Note != "" {
			fmt.Printf("    note: %s\n", r.Note)
		}
	}
	return 0
}

func runTokenRevoke(args []string) int {
	fs := flag.NewFlagSet("token revoke", flag.ExitOnError)
	vaultPath := fs.String("vault", envOr("DOP_VAULT", defaultVaultPath()), "path to vault YAML")
	_ = fs.Parse(args)

	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "usage: dop token revoke <name-or-prefix>")
		return 2
	}
	query := rest[0]

	if *vaultPath == "" {
		fmt.Fprintln(os.Stderr, "dop token revoke: no vault path")
		return 1
	}
	plain, err := tokenio.LoadPlain(*vaultPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token revoke: %v\n", err)
		return 1
	}
	root, err := tokenio.ParseTree(plain)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token revoke: %v\n", err)
		return 1
	}
	hits := tokenio.FindByName(root, query)
	switch len(hits) {
	case 0:
		fmt.Fprintf(os.Stderr, "dop token revoke: no token matches %q\n", query)
		return 1
	case 1:
		if !tokenio.RemoveAuthToken(root, hits[0]) {
			fmt.Fprintln(os.Stderr, "dop token revoke: internal error (found but not removed)")
			return 1
		}
	default:
		fmt.Fprintf(os.Stderr, "dop token revoke: ambiguous query %q — %d matches; be more specific\n", query, len(hits))
		return 1
	}
	out, err := tokenio.EmitTree(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token revoke: %v\n", err)
		return 1
	}
	if err := tokenio.SavePlain(*vaultPath, out); err != nil {
		fmt.Fprintf(os.Stderr, "dop token revoke: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "dop token revoke: removed %q\n", query)
	_ = auditWriter().Log(audit.Event{
		Op:        "token-revoke",
		AgentName: query,
		Outcome:   "ok",
	})
	return 0
}

// runLog dispatches `dop log <tail|grep>`.
func runLog(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: dop log <tail|grep> ...")
		return 2
	}
	switch args[0] {
	case "tail":
		return runLogTail(args[1:])
	case "grep":
		return runLogGrep(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "dop log: unknown subcommand %q\n", args[0])
		return 2
	}
}

func runLogTail(args []string) int {
	fs := flag.NewFlagSet("log tail", flag.ExitOnError)
	n := fs.Int("n", 20, "number of most-recent lines to print")
	_ = fs.Parse(args)
	lines, err := readAllLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop log tail: %v\n", err)
		return 1
	}
	start := len(lines) - *n
	if start < 0 {
		start = 0
	}
	for _, l := range lines[start:] {
		fmt.Println(l)
	}
	return 0
}

func runLogGrep(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: dop log grep KEY=VAL [KEY=VAL ...]")
		return 2
	}
	// Parse KEY=VAL predicates.
	preds := map[string]string{}
	for _, a := range args {
		i := strings.IndexByte(a, '=')
		if i <= 0 {
			fmt.Fprintf(os.Stderr, "dop log grep: bad predicate %q (want KEY=VAL)\n", a)
			return 2
		}
		preds[a[:i]] = a[i+1:]
	}
	lines, err := readAllLogLines()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop log grep: %v\n", err)
		return 1
	}
	for _, l := range lines {
		var e audit.Event
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			continue
		}
		if !matchEvent(e, preds) {
			continue
		}
		fmt.Println(l)
	}
	return 0
}

func matchEvent(e audit.Event, preds map[string]string) bool {
	for k, want := range preds {
		var got string
		switch k {
		case "op":
			got = e.Op
		case "agent_name":
			got = e.AgentName
		case "auth_method":
			got = e.AuthMethod
		case "outcome":
			got = e.Outcome
		case "token_hash":
			got = e.TokenHash
		default:
			return false // unknown key → no match
		}
		if got != want {
			return false
		}
	}
	return true
}

// readAllLogLines reads every access-*.jsonl file under the DOP logs dir,
// concatenated in filename-sorted order. Chronological within a file;
// across-file ordering is only right if callers accept the natural sort
// (per-host, per-month) — which is fine for tail/grep at V1.
func readAllLogLines() ([]string, error) {
	paths, err := config.Resolve()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(paths.Logs)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "access-") && strings.HasSuffix(e.Name(), ".jsonl") {
			files = append(files, e.Name())
		}
	}
	sort.Strings(files)

	var out []string
	for _, name := range files {
		b, err := os.ReadFile(filepath.Join(paths.Logs, name))
		if err != nil {
			continue
		}
		for _, ln := range strings.Split(string(b), "\n") {
			ln = strings.TrimSpace(ln)
			if ln != "" {
				out = append(out, ln)
			}
		}
	}
	return out, nil
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// currentActor is a best-effort audit-line identity used in `created_by`.
// Prefers $DOP_ACTOR, then $USER. Never fails.
func currentActor() string {
	if v := os.Getenv("DOP_ACTOR"); v != "" {
		return v
	}
	if v := os.Getenv("USER"); v != "" {
		return v
	}
	return ""
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
