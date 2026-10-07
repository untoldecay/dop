# DOP — Feature Sheet

Every DOP feature as of **v1.13.0**, in one scannable table. Grouped by surface, not by the version each landed in.

| Area | Feature | What it does | Since |
|---|---|---|---|
| Vault & admin | SOPS+age vault | Vault is a plain file in a git repo you own; SOPS+age encrypts it at rest. No server, no telemetry. | v1.0 |
| Vault & admin | Admin session daemon | One `dop admin login` per machine; subsequent commands share the unlock. Idle + absolute TTL. | v1.0 |
| Vault & admin | Approval passphrase | A second passphrase set at `dop admin init`; argon2id-hashed; guards every claim and every protection-flag flip. | v1.0 |
| Vault & admin | Multi-admin | Each admin signs the records they issue; agents verify via the `admins.trust` file without opening the vault. | v1.0 |
| Vault & admin | Admin invite flow | M-handshake: admin A opens invite → admin B joins via PIN → mutual verification + add to vault. | v1.9 |
| Vault & admin | Admin-loss safety guard | `saveVaultViaDaemon` refuses a write that would orphan another admin — catches "I pushed with only my recipient" bugs. | v1.10.4 |
| Vault & admin | 3-way merge | Concurrent admin edits merge semantically; `--take-theirs` / `--take-ours` as escape hatches. | v1.10.2 |
| Vault & admin | Auto-sync | Pull on login, push on save; no manual `git pull && git push` dance. | v1.10.3 |
| Vault & admin | Device additions | Invite a second machine of your own as "same identity" (one admin, N devices) or "separate identity" (two distinct admins). | v1.9 |
| Credentials | Scoped bearers | Each bearer carries a narrow set of grants; leak scope = that bearer only, not the whole catalog. | v1.0 |
| Credentials | `dop exec` env injection | Resolves grants to env vars for one child process; env values never land on disk. | v1.0 |
| Credentials | `dop env` | Prints the resolved env for scripting / debugging; same binding + rate limits as `exec`. | v1.0 |
| Credentials | Protected credentials | Owner-locked integrations/grants (Shape B). CLI gate + daemon-side revert catches freehand `vault edit`. | v1.13.0-rc12 |
| Credentials | Protected audit trail | 3 event kinds: `protected_create`, `protected_token_issue`, `protected_bypass_attempt`. | v1.13.0-rc12 |
| Credentials | Token lifecycle | `set-token` command (CLI + TUI): rotate value, edit scope note. Secret-safe (stdin only, never on argv). | v1.13.0-rc16 |
| Credentials | Stale pending-claim reaper | Orphan `.json` files from SIGKILL/power-loss auto-clean on `dop claim --status`. | v1.13.0-rc17 |
| Credentials | `--expires never` | Sentinel timestamp for infrastructure bearers that shouldn't auto-rotate. | v1.11.1 |
| Credentials | `token repin` | Bump a PIN without re-issuing the bearer; 1h default TTL (chat-friendly). | v1.13.0-rc9 |
| Integration kinds | Kind field (api / cli / mcp / other) | Each integration declares what it IS, so the agent env can be shaped for use not just discovery. | v1.13.0-rc13 |
| Integration kinds | Canonical env promotion | Metadata keys get exported as typed env vars (`${PREFIX}_KIND`, `_BASE_URL`, `_CMD`, `_MCP_URL`, etc.). | v1.13.0-rc13 |
| Integration kinds | Advanced hint fields | `server_root`, `allowed`, `auth_style`, `cli_install`, `cli_help` — all optional, promote to canonical env suffixes. | v1.13.0-rc17 |
| Integration kinds | `cli_auth_env` template expansion | Template `KEY=$TOKEN;KEY=$SERVER_ROOT` is parsed + substituted + exported DIRECTLY so the CLI's own env names populate. | v1.13.0-rc17 |
| Integration kinds | Safety blacklist | Refuses to export expanded keys like `PATH`, `LD_PRELOAD`, `DOP_TOKEN` even when template requests them. | v1.13.0-rc17 |
| Integration kinds | Endpoints probe | Opt-in `--probe-endpoints` walks common OpenAPI paths (api) or `tools/list` (mcp), stamps the result in metadata. | v1.13.0-rc15 |
| Integration kinds | Mutable kind | Flip an integration between api / cli / mcp / other without re-issuing. | v1.13.0-rc13 |
| Integration kinds | Legacy default | Pre-rc13 integrations with no `kind` field read as `api`. Zero migration. | v1.13.0-rc13 |
| Agent identity | P-256 Secure Enclave | Hardware-backed, non-extractable on signed macOS builds. | v1.11 |
| Agent identity | File-backed P-256 fallback | Loud fallback (boxed warning + doctor flag) when SE isn't reachable; opt-in via `DOP_ALLOW_FILE_KEYS=1`. | v1.11 |
| Agent identity | Legacy ed25519 | Still readable; one-command migration via `dop agent migrate`. | v1.0 |
| Agent identity | Direct availability | Grant edits + bearer rotation take effect on the agent's next exec without re-claim. ECDH re-wrap over the admin daemon. | v1.12 |
| Agent identity | Way B (bearer-free exec) | `dop exec` without `$DOP_TOKEN` scans local agent-keys and resolves implicitly. For long-running agents on their own machine. | v1.13.0-rc11 |
| Agent identity | Agent key doctor | `dop doctor` reports SE vs file-key counts, flags unsigned-build downgrades loudly. | v1.11 |
| Approval UX | QR + Cloudflared tunnel | Admin's machine stands up an HTTPS tunnel per claim; TUI prints a QR with the URL. | v1.9 |
| Approval UX | Phone-based approval | Any phone camera opens the URL; the mobile form asks for the approval passphrase. No app to install. | v1.9 |
| Approval UX | 5-minute pending-claim window | Comfortable scan + unlock + type, bounded attacker window. | v1.0 |
| Approval UX | Rate limiting | 8 attempts shared across web + CLI (attacker can't bypass web counters from CLI). | v1.6.3 |
| Approval UX | SAS verification code | 6-digit code admin + approver verify out-of-band; defends against DNS/BGP tunnel hijack. | v1.0 |
| TUI | Hierarchical menu | 6 primaries (Add / Issue / List / Remove / Vault / More). Verbs, not categories. 1-5 + M keyboard jumps. | v1.13.0-rc19 |
| TUI | Preset pickers | Scope, kind, protection, probe, advanced fields — same shape across every form. `other…` escape to free-text. | v1.13.0-rc7 |
| TUI | Token drill-down | Enter on an integration → token picker → view/edit scope/rotate value/remove per token. | v1.13.0-rc16 |
| TUI | Integration-level edit | `e` on the list opens kind/description/URL form; pre-populated with current values. | v1.13.0-rc16 |
| TUI | Status bar | Per-cursor-row details below every list view (`selected: boiler  \|  kind=cli  \|  grants=3  \|  tokens=5`). | v1.13.0-rc20 |
| TUI | Dynamic column widths | Longest entry sets the column; no clipping on long names. | v1.13.0-rc20 |
| TUI | Shared metadata block | Same renderer across integration drill-down and detail pane. Single source of truth for field order + empty-row logic. | v1.13.0-rc17 |
| TUI | `kvLine` detail helper | Shared label-padded row renderer across every detail pane (integration / grant / bearer). | v1.13.0-rc18 |
| TUI | `\|` separators | Mole-style keybinding legends in every help footer. | v1.13.0-rc20 |
| TUI | Pending-claim banner | `a` from the main menu opens the inline approver when a claim is live. | v1.7 |
| TUI | Settings `f` toggle | Toggles AllowFileKeys; TUI prefs stored in `tui-prefs.yaml`. | v1.9 |
| TUI | Rotate value stdin flow | Masked input in TUI → `--value-stdin` to CLI → never on argv. | v1.13.0-rc16 |
| Audit log | Append-only JSONL | `<Logs>/audit.jsonl`, mode 0600, atomic via POSIX O_APPEND. | v1.0 |
| Audit log | 20+ event kinds | `issue`, `claim*`, `repin`, `revoke`, `exec`, `env*`, `admin_*`, `invite*`, `agent_migrated`, `protected_*`, `integration_probed`, `integration_token_set`. | v1.0+ |
| Audit log | `dop watch` live tail | `--since D`, `--all`, `--filter K,K,K`, `--no-color`. Detects log rotation via inode change. | v1.0 |
| Audit log | macOS notifications | On `claim_pending` / `claim_denied` / `revoke`. `DOP_NO_NOTIFY=1` for CI. | v1.0 |
| Audit log | Non-blocking writes | Audit failures never block primary flows. | v1.0 |
| Audit log | Admin-free read | Inspect the audit log on a locked machine without `dop admin login`. | v1.0 |
| Observability | `dop doctor` | Binary deps, admin session state, trust file, SE vs file-key counts, codesign posture, recent audit activity. | v1.0 |
| Observability | `dop doctor --security` | Adds hardening-focused checks on top of the base run. | v1.7 |
| Observability | Clean non-admin errors | `integration list` on a locked vault → "run `dop admin login`" message, not a raw SOPS parse error. | v1.13.0-rc17 |
| Observability | Loud SE-fallback warning | Bordered Unicode box when the binary can't reach the Secure Enclave. | v1.13.0-rc17 |
| Developer / ops | `git-credential-dop` | Git picks up tokens from DOP automatically for clone/push. | v1.0 |
| Developer / ops | `--skip-approval` | CI test paths can bypass approval; refused outside test contexts. | v1.0 |
| Developer / ops | `--passphrase-stdin` | Every passphrase prompt accepts stdin alternative; TUI uses this for secret-safe hand-off. | v1.13.0-rc12 |
| Developer / ops | `DOP_NO_TUI=1` | Headless invocations; TUI never opens. Used by the TUI's own subprocess calls to the CLI. | v1.0 |
| Developer / ops | 39 E2E shell scripts | Full command-path coverage in `testdata/e2e/`. `./scripts/test.sh` runs the suite. | v1.0+ |
| Developer / ops | Contract-driven features | Every feature has (or updates) a numbered design contract (kept in the maintainers' working notes, not published). | v1.0+ |

## Documented contracts

| # | Title |
|---|---|
| 01 | Two-plane authority |
| 02 | Admin session daemon |
| 03 | Vault schema |
| 04 | Capability envelope |
| 05 | Signed record + trust |
| 06 | PIN claim binding |
| 07 | Approval gate |
| 08 | Web approval flow |
| 09 | Agent exec |
| 10 | Audit log + notifications |
| 11 | Team lifecycle |
| 12 | Vault git sync |
| 13 | Handoff text shape |
| 14 | TUI patterns |
| 15 | Protected credentials |
| 16 | Integration kinds |
| 17 | Endpoints discovery probe |
| 18 | Token lifecycle |
