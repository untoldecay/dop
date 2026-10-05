// dop — Doors of Perception CLI.
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

	"github.com/fray/dop/internal/tui"
	"github.com/fray/dop/internal/version"
)

// versionString wraps the version package for backwards-compat with
// existing call sites in this file.
func versionString() string { return version.String() }

const usage = `dop — Doors of Perception

usage:
  dop                                            interactive TUI (default when on a TTY)
  dop version | -v | --version                   print version + commit + build date
  dop uninstall [--force]                        wipe DOP from this machine (alias for admin reset)
  dop skill install [--force] [--path FILE]      install the DOP agent skill AND /dop-use slash command — loose files at ~/.claude/skills/dop + ~/.claude/commands/dop-use.md AND a local-marketplace plugin at ~/.claude-local-plugins/dop-tools (registered via the claude CLI if available, for Orca and plugin-only Claude Code). --path installs only the skill at that path (loose file only, no plugin).
  dop skill show                                 print the embedded skill content to stdout (agent-agnostic install)
  dop skill show-command                         print the /dop-use slash command content to stdout
  dop help                                       this message

  # Admin plane
  dop admin init                                 generate + wrap admin keys (one-time)
  dop admin login                                start session (prompts passphrase)
  dop admin logout                               end session
  dop admin status                               show session state + TTL
  dop admin set-approval                         (re)set the approval passphrase
  dop admin join <VAULT-URL> <PIN>               join a vault as a new admin device (v1.9)
  dop admin reset [--force]                      wipe local DOP state (v1.9.2)
  dop team invite --name <label>                 open an admin invite (v1.9)
  dop init --vault <url|path>                    attach vault (admin-required for first attach)
  dop token issue --grants CSV --name L [flags]  mint a capability + bearer (admin-required)
  dop token list                                 list capabilities (admin-required)
  dop token show <lookup|subject> [--json]       detail view: subject, expiry, binding, grants (admin-required)
  dop token revoke <name>                        revoke a capability (admin-required)
  dop token repin --subject S [--pin-ttl D]      reissue an expired/consumed PIN (admin-required)
  dop token reseal <lookup|subject>              re-encrypt grant env to the agent's SE key (v1.12; admin-required)
  dop token add-grant <lookup|subject> <grant>   add grant + reseal so next exec sees new env (v1.12; P-256 only)
  dop token remove-grant <lookup|subject> <grant> remove grant + reseal (v1.12; P-256 only)
  dop token rotate <lookup|subject>               issue new bearer + wrap for agent → next exec auto-rotates (v1.12; P-256)
  dop integration add --name N --token N=V:NOTE  add/update an integration (admin-required)
  dop integration list                           list integrations (admin-required)
  dop integration remove --name N [--force]      remove an integration (admin-required)
  dop grant add --id ID --integration N --token T   add a grant (admin-required)
  dop grant list                                 list grants (admin-required)
  dop grant show <id> [--all] [--json]           detail view: grant details + tokens using it (admin-required)
  dop grant remove --id ID                       remove a grant (admin-required)
  dop team add-key --name W --pubkey <age>       add admin recipient (admin-required)
  dop team list                                  list admins (admin-required)
  dop team remove --name W [--force]             remove admin (with rotation checklist)
  dop vault edit                                 open decrypted vault in $EDITOR

  # Agent keys (v1.11)
  dop agent list                                 show agent-key backend + type for each bearer
  dop agent info <lookup>                        details for one key
  dop agent migrate <lookup>                     re-enroll a legacy ed25519 key → SE-backed P-256
  dop agent sweep                                remove legacy keys past their 12h grace window

  # Agent / execution plane
  dop init --cache <url|path>                    clone vault as agent (no admin keys generated)
  dop claim <PIN> [--token-file PATH]            bind this agent to a bearer via PIN (v1.3)
                                                 v1.6: shows QR + starts Cloudflare tunnel → admin approves on phone via passphrase
                                                 --no-tunnel for LAN-only; --skip-approval for unattended
  dop exec [--token-file PATH] --agent-name X -- CMD [ARGS...]
  dop whoami                                     describe current bearer
  dop env                                        print shell-eval-able exports

  # Approval plane (v1.5) — admin confirms in-flight PIN claims
  dop pending                                    list pending claims
  dop approve <SAS>                              approve a pending claim
  dop reject <SAS>                               reject a pending claim
  dop approve-remote --subject S | --list        approve a claim staged by dop claim --remote

  # Common
  dop pull                                       git pull vault
  dop push                                       git push vault
  dop doctor [--security]                        health check
  dop watch [--since D] [--filter K,K] [--all]   live-tail the audit log
  dop credential-helper map|list|remove          manage host→grant map for dop-credential-git
  dop trust list                                 list active TrustContext grants (session approvals cached in the daemon)
  dop trust revoke [--all] [KIND VALUE SUBJECT]  drop a cached approval (or every one with --all)
  dop update [--check-only] [--channel X] [--version TAG] [--rollback]
                                                 in-place update from GitHub. Default channel: stable (--channel dev for pre-releases).
                                                 --rollback reverts to the previous stored version. Keeps last 3 at ~/.local/share/dop/old-versions/.

env:
  DOP_TOKEN                     bearer for exec/whoami/env
  DOP_TOKEN_FILE                path to a file containing a bearer (alternative to env)
  DOP_VAULT                     override vault path
  DOP_NO_TUI                    disable TUI on 'dop' alone (agents/cron)
  DOP_ADMIN_TTL                 admin session idle timeout (default 15m)
  DOP_ADMIN_MAX_TTL             admin session absolute timeout (default 60m)
  DOP_AUTO_PULL                 max staleness before dop exec auto-pulls (default 5m)
  DOP_SESSION_ID                v1.14.0-rc6i: explicit trust-context identifier so burst dop use/env calls in the same
                                conversation / terminal / shell session share one approval (keep opaque, >=128 bits)
  DOP_HARNESS                   v1.14.0-rc7i: tells the trust-context resolver which harness env var to consult. Values:
                                claude-code | codex | opencode | any | none. Normally set from Settings → Harness picker;
                                exported here for one-shot overrides and headless/CI contexts.
  DOP_INFER_HARNESS_SESSION=1   v1.14.0-rc6i, DEPRECATED (rc7i): legacy opt-in, now aliased to DOP_HARNESS=any. Prefer
                                the Settings → Harness picker (or DOP_HARNESS directly) which also recognizes Codex and
                                opencode. Still works for backward compat.
`

func main() {
	if len(os.Args) < 2 {
		if shouldLaunchTUI() {
			os.Exit(tui.Run())
		}
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
	case "use":
		os.Exit(runUse(os.Args[2:]))
	case "integration":
		os.Exit(runIntegration(os.Args[2:]))
	case "grant":
		os.Exit(runGrant(os.Args[2:]))
	case "vault":
		os.Exit(runVault(os.Args[2:]))
	case "team":
		os.Exit(runTeam(os.Args[2:]))
	case "claim":
		os.Exit(runClaim(os.Args[2:]))
	case "approve":
		os.Exit(runApprove(os.Args[2:]))
	case "approve-remote":
		os.Exit(runApproveRemote(os.Args[2:]))
	case "reject":
		os.Exit(runReject(os.Args[2:]))
	case "pending":
		os.Exit(runPending(os.Args[2:]))
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
	case "watch":
		os.Exit(runWatch(os.Args[2:]))
	case "credential-helper":
		os.Exit(runCredentialHelper(os.Args[2:]))
	case "agent":
		// v1.11 — `dop agent <subcommand>` for agent-key operations
		// (migrate ed25519 → SE P-256, list, doctor). Kept separate
		// from `dop admin` because these are per-bearer operations.
		os.Exit(runAgent(os.Args[2:]))
	case "uninstall":
		// v1.10.4 — top-level alias for `dop admin reset` so the "wipe
		// this machine" action is discoverable without knowing about
		// the admin subcommand tree.
		os.Exit(runAdminReset(os.Args[2:]))
	case "skill":
		// v1.14.0-rc6 — install the DOP Claude Code skill into
		// ~/.claude/skills/dop/SKILL.md so LLM agents on this machine
		// use the safe eval pattern + know about the approval popup.
		os.Exit(runSkill(os.Args[2:]))
	case "trust":
		// v1.14.0-rc6i — operator observability for the TrustContext
		// grant cache. `dop trust list` / `dop trust revoke` show +
		// manage the per-(context, subject) approvals cached in the
		// admin daemon.
		os.Exit(runTrust(os.Args[2:]))
	case "update":
		// v1.14.0-rc7f — in-place updater. Fetches releases from
		// GitHub, verifies checksum, atomic-renames. Keeps the last 3
		// versions in ~/.local/share/dop/old-versions/ for rollback.
		os.Exit(runUpdate(os.Args[2:]))
	case "version", "-v", "--version":
		fmt.Println(versionString())
		return
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

// shouldLaunchTUI: `dop` alone launches the TUI iff both stdin and
// stdout are TTYs AND DOP_NO_TUI isn't set.
func shouldLaunchTUI() bool {
	if os.Getenv("DOP_NO_TUI") != "" {
		return false
	}
	fi, err := os.Stdin.Stat()
	if err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	fo, err := os.Stdout.Stat()
	if err != nil || fo.Mode()&os.ModeCharDevice == 0 {
		return false
	}
	return true
}

func envOr(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}
