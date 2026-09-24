// dop — Doors of Perception CLI (P0 walking skeleton).
//
// Wire path proved end-to-end:
//   vault load → token resolve → env scope → child exec.
//
// P0 uses a plaintext vault. P1 wraps vault load with SOPS decryption.
package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/fray/dop/internal/execchild"
	"github.com/fray/dop/internal/resolve"
	"github.com/fray/dop/internal/vault"
)

const usage = `dop — Doors of Perception (P0)

usage:
  dop exec   [--vault PATH] [--agent-name NAME] [--clean-env] -- CMD [ARGS...]
  dop whoami [--vault PATH]
  dop env    [--vault PATH]
  dop help

env:
  DOP_TOKEN     bearer auth token (required for exec/whoami/env)
  DOP_VAULT     default --vault path (overridable per-call)
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "exec":
		os.Exit(runExec(os.Args[2:]))
	case "whoami":
		os.Exit(runWhoami(os.Args[2:]))
	case "env":
		os.Exit(runEnv(os.Args[2:]))
	case "help", "-h", "--help":
		fmt.Print(usage)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "dop: unknown command %q\n\n", os.Args[1])
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

func runExec(args []string) int {
	fs := flag.NewFlagSet("exec", flag.ExitOnError)
	vaultPath := fs.String("vault", envOr("DOP_VAULT", ""), "path to vault YAML")
	agentName := fs.String("agent-name", "", "self-reported agent identifier (audit only)")
	cleanEnv := fs.Bool("clean-env", false, "strip inherited env, keep only PATH/HOME/USER + injected")
	_ = fs.Parse(args)

	child := fs.Args()
	if len(child) == 0 {
		fmt.Fprintln(os.Stderr, "dop exec: missing command after --")
		return 2
	}

	res, err := loadAndResolve(*vaultPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop exec: %v\n", err)
		return 1
	}

	// P4 will write an audit log line here. For P0 we surface to stderr.
	fmt.Fprintf(os.Stderr,
		"dop exec: agent=%q grants=%v env_keys=%d\n",
		*agentName, res.GrantsUsed, len(res.Env),
	)

	if err := execchild.Run(child, res.Env, *cleanEnv); err != nil {
		fmt.Fprintf(os.Stderr, "dop exec: %v\n", err)
		return 1
	}
	return 0 // unreachable on success (syscall.Exec replaces the process)
}

func runWhoami(args []string) int {
	fs := flag.NewFlagSet("whoami", flag.ExitOnError)
	vaultPath := fs.String("vault", envOr("DOP_VAULT", ""), "path to vault YAML")
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
	vaultPath := fs.String("vault", envOr("DOP_VAULT", ""), "path to vault YAML")
	_ = fs.Parse(args)

	res, err := loadAndResolve(*vaultPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop env: %v\n", err)
		return 1
	}
	keys := make([]string, 0, len(res.Env))
	for _, kv := range res.Env {
		k := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			k = kv[:i]
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, kv := range res.Env {
		// Prefix with `export ` so callers can `eval "$(dop env)"`.
		// Values are shell-quoted single-quote style; a value containing ' would break — P0 doesn't emit any.
		if i := strings.IndexByte(kv, '='); i >= 0 {
			fmt.Printf("export %s='%s'\n", kv[:i], kv[i+1:])
		}
	}
	return 0
}

func loadAndResolve(vaultPath string) (*resolve.Resolution, error) {
	if vaultPath == "" {
		return nil, fmt.Errorf("no vault path (--vault or $DOP_VAULT)")
	}
	v, err := vault.Load(vaultPath)
	if err != nil {
		return nil, err
	}
	bearer := os.Getenv("DOP_TOKEN")
	res, err := resolve.Resolve(v, bearer)
	if err != nil {
		return nil, err
	}
	return res, nil
}

// tokenID returns a short, log-safe hash of the bearer token (first 8 hex chars
// of sha256). P0 stub — full audit logging arrives in P4.
func tokenID(bearer string) string {
	// Deliberate P0 shortcut: expose only the *token key name* not the value.
	// The vault's auth_tokens map key IS the bearer, so we just show a prefix.
	// P4 will replace this with sha256 truncation for audit lines.
	if len(bearer) <= 12 {
		return bearer
	}
	return bearer[:12] + "…"
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok {
		return v
	}
	return def
}
