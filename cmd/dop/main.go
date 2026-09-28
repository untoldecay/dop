// dop — Doors of Perception CLI (v1.0).
//
// Two authority planes:
//   - Administrative plane (admin session): manages the vault.
//   - Execution plane (bearer + capability bundle): runs child processes
//     with scoped env vars. Never touches the vault.
//
// See ARCHITECTURE.md for the full model.
package main

import (
	"fmt"
	"os"
)

const usage = `dop — Doors of Perception (v1.0)

usage:
  dop                                            interactive TUI (default when on a TTY)
  dop help                                       this message

  # Admin plane
  dop admin init                                 generate + wrap admin keys (one-time)
  dop admin login                                start session (prompts passphrase)
  dop admin logout                               end session
  dop admin status                               show session state + TTL
  dop init --vault <url|path>                    attach vault (admin-required for first attach)
  dop token issue --grants CSV --name L [flags]  mint a capability + bearer (admin-required)
  dop token list                                 list capabilities (admin-required)
  dop token revoke <name>                        revoke a capability (admin-required)
  dop team add-key --name W --pubkey <age>       add admin recipient (admin-required)
  dop team list                                  list admins (admin-required)

  # Agent / execution plane
  dop init --cache <url|path>                    clone vault as agent (no admin keys generated)
  dop exec [--token-file PATH] --agent-name X -- CMD [ARGS...]
  dop whoami                                     describe current bearer
  dop env                                        print shell-eval-able exports

  # Common
  dop pull                                       git pull vault
  dop push                                       git push vault
  dop doctor [--security]                        health check

env:
  DOP_TOKEN          bearer for exec/whoami/env
  DOP_TOKEN_FILE     path to a file containing a bearer (alternative to env)
  DOP_VAULT          override vault path
  DOP_NO_TUI         disable TUI on 'dop' alone (agents/cron)
  DOP_ADMIN_TTL      admin session idle timeout (default 15m)
  DOP_ADMIN_MAX_TTL  admin session absolute timeout (default 60m)
  DOP_AUTO_PULL      max staleness before dop exec auto-pulls (default 5m)
`

func main() {
	if len(os.Args) < 2 {
		// TUI launch stubbed for Phase 5. For now: print usage.
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	// Strip global flags before subcommand dispatch.
	os.Args = stripGlobalFlags(os.Args)

	switch os.Args[1] {
	case "admin":
		os.Exit(runAdmin(os.Args[2:]))
	case "init":
		os.Exit(runInit(os.Args[2:]))
	case "token":
		os.Exit(runToken(os.Args[2:]))
	case "team":
		os.Exit(runTeam(os.Args[2:]))
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
	case "doctor":
		os.Exit(runDoctor(os.Args[2:]))
	case "help", "-h", "--help":
		fmt.Print(usage)
		return
	default:
		fmt.Fprintf(os.Stderr, "dop: unknown command %q\n\n", os.Args[1])
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
}

// stripGlobalFlags removes flags that apply globally (like --no-tui)
// before subcommand parsing.
func stripGlobalFlags(argv []string) []string {
	out := argv[:0]
	for _, a := range argv {
		if a == "--no-tui" || a == "-no-tui" {
			continue
		}
		out = append(out, a)
	}
	return out
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}
