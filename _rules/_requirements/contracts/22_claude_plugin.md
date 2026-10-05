# Feature Contract — Claude Code Plugin + Slash Command

## Scope
- `dop skill install` writes the DOP skill as BOTH loose files AND a local-marketplace plugin bundle.
- `dop admin reset --purge` tears both down.
- `/dop-use` slash command bundled with the install.

## Purpose
- Make the DOP safety skill visible in plugin-only Claude Code harnesses (Orca and future builds) where `~/.claude/skills/*/SKILL.md` is silently ignored.

## Invariants
- MUST write loose files at `~/.claude/skills/dop/SKILL.md` + `~/.claude/commands/dop-use.md` on the default install path.
- MUST write the plugin bundle at `~/.claude-local-plugins/dop-tools/` on the default install path.
- MUST keep the loose-file install as the reliable fallback for non-Claude-Code harnesses.
- MUST hold the plugin naming constants stable across releases: marketplace=`dop-local`, plugin=`dop`, directory=`dop-tools`.
- MUST version the embedded `marketplace.json` + `plugin.json` from `internal/version.Version`.
- MUST NOT bundle the slash command when `dop skill install --path <custom>` is used (slash commands are Claude Code-specific; custom paths target other agents).

## Mandatory Behaviors
- MUST register the plugin via `claude plugin marketplace add <abs-root>` + `claude plugin install dop@dop-local` when the `claude` CLI is on PATH.
- MUST treat registration failures as non-fatal: log + continue so the loose-file install still succeeds.
- MUST surface the manual registration commands in stderr when `claude` CLI is missing.
- MUST tear down everything on `dop admin reset --purge`: `claude plugin uninstall` + `claude plugin marketplace remove` + `rm -rf ~/.claude-local-plugins/dop-tools/` + remove loose files.
- MUST filter the "not found" error from `claude plugin uninstall` on cleanup (idempotency).
- MUST ship the embedded templates verbatim from `cmd/dop/skill_template.md` + `cmd/dop/dop_use_command_template.md` via `//go:embed`.

## Forbidden Behaviors
- MUST NOT write the plugin bundle for `--path <custom>` installs (would drop a Claude Code artifact into Cursor/Zed/other-agent locations).
- MUST NOT rename or move the plugin directory between releases — operators have `claude plugin install` entries pointing at `dop-local`.
- MUST NOT prefix the skill `name:` with `dop:` in the plugin's `SKILL.md` frontmatter. Claude Code namespaces automatically.

## Interfaces
- Inputs: `dop skill install [--force] [--path FILE]`, `dop skill show`, `dop skill show-command`, `dop admin reset [--purge]`
- Outputs:
  - `~/.claude/skills/dop/SKILL.md` (0o600)
  - `~/.claude/commands/dop-use.md` (0o600)
  - `~/.claude-local-plugins/dop-tools/.claude-plugin/marketplace.json`
  - `~/.claude-local-plugins/dop-tools/plugins/dop/.claude-plugin/plugin.json`
  - `~/.claude-local-plugins/dop-tools/plugins/dop/skills/dop-credential-access/SKILL.md`
  - `~/.claude-local-plugins/dop-tools/plugins/dop/commands/dop-use.md`
- Dependencies: `claude plugin` CLI (optional — degrades to manual-step hint)

## State & Data Rules
- MUST write files with the install-file helper (`cmd/dop/skillcmd.go::installFile`): no-op when content matches; refuse when different without `--force`; mode 0o600.
- MUST re-render JSON manifests on every install so an upgraded dop binary's version lands in the plugin.

## Acceptance Criteria
- PASS if `dop skill install` on a Claude Code machine produces `claude plugin list` showing `dop@dop-local` as `enabled`.
- PASS if `dop skill install --path /tmp/foo.md` writes ONLY the loose skill at the given path (no plugin bundle, no command file).
- PASS if `dop admin reset --purge` leaves zero DOP artifacts under `~/.claude/` + `~/.claude-local-plugins/`.
- PASS if `dop skill install` on a non-Claude Code machine (no `claude` on PATH) succeeds, writes the plugin folder, and prints manual `claude plugin marketplace add` + `claude plugin install` hints.
- FAIL if the plugin install leaves orphan files when the operator runs `dop admin reset --purge`.
- FAIL if `claude plugin install` registers the plugin but the operator's `/dop:dop-use` slash command doesn't surface after Claude Code restart (plugin layout bug).

## Regression Checks
- Verify `go build ./...` embeds both templates (would fail at build time if the files are moved).
- Verify `dop skill show-command | diff - <(cat ~/.claude-local-plugins/dop-tools/plugins/dop/commands/dop-use.md)` matches after install.
- Verify `claude plugin list` after install contains the plugin.

## Open Questions
- Should we auto-detect Claude Code's installed version and skip the plugin install on versions that still support loose files? Currently always writes both.
- Should the plugin description surface the DOP version at `claude plugin details dop`? Currently it does (via rendered `plugin.json`), but no test pins this.
