# DOP — Feature Sheet

What DOP ships as of **v1.13.0**. Organized by surface, not by the version that introduced each feature.

## Vault & admin

- **SOPS+age-encrypted vault** stored as a plain file in a private git repo you own (GitHub, GitLab, Gitea, self-hosted). No server, no account, no telemetry.
- **Admin session daemon** — one unlock per machine, shared across every shell on it. `dop admin login` once; subsequent commands skip the passphrase.
- **Approval passphrase** — a second passphrase set at `dop admin init`, argon2id-hashed, used to guard every claim and every protection-flag flip.
- **Multi-admin** with signed capability records + `admins.trust` file. Each admin signs the records they issue; agents verify against the trust list without opening the vault.
- **Admin invite flow** (M-handshake). Admin A opens an invite → admin B joins via PIN → mutual verification + add to vault.
- **Admin-loss safety guard** — refuses to save a vault that would orphan another admin. Catches the "I pushed a vault with only my recipient" class of bug.
- **3-way merge** on concurrent admin edits. `dop pull --take-theirs` / `--take-ours` for conflict resolution.
- **Auto-sync** on login + push.
- **Device additions**: invite a second machine of your own via "same identity" (one admin, N devices) or "separate identity" (two distinct admins).

## Credentials

- **Scoped bearers** — grants carry *narrow* permissions. A bearer leaking leaks only what it carries, not the whole credential set.
- **`dop exec` child-process env injection** — grants resolve to env vars for one subprocess. The env values never land on disk.
- **`dop env`** — print the resolved env for scripting / debugging. Same binding + rate-limit as `exec`.
- **Protected credentials** (Shape B + daemon revert) — mark an integration or grant as owner-locked. CLI refuses non-owner mutations; the daemon reverts any that slip through (`vault edit` free-form, etc.). Three audit events: `protected_create`, `protected_token_issue`, `protected_bypass_attempt`.
- **Token lifecycle** — rotate value, edit scope note from CLI (`dop integration set-token --value-stdin`) or TUI drill-down. Secret-safe: stdin only, never on argv.
- **Stale pending-claim reaper** — orphan `.json` files from SIGKILL/power-loss get auto-cleaned on `dop claim --status`.

## Integration kinds (api / cli / mcp / other)

- **Canonical env promotion** — well-known metadata keys get exported as typed env vars (`${PREFIX}_KIND`, `_BASE_URL`, `_CMD`, `_MCP_URL`, etc.).
- **Advanced fields**: `cli_auth_env`, `server_root`, `allowed`, `auth_style`, `cli_install`, `cli_help`. Each promotes to its canonical env suffix.
- **CLI auth template expansion** — `cli_auth_env` template (`BOILER_TOKEN=$TOKEN;BOILER_SERVER=$SERVER_ROOT`) is parsed, substituted with the resolved token + server root, and exported *directly* under the CLI's native env names. The CLI just works, zero wrapper needed.
- **Safety blacklist** on direct-exported keys — refuses `PATH`, `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `DOP_TOKEN`, and friends. Admin is trusted; defense-in-depth still applies.
- **Opt-in endpoints probe** — `dop integration add --probe-endpoints` walks the common OpenAPI paths (`/.well-known/openapi.json`, `/openapi.json`, `/v3/api-docs`, etc.) or MCP `tools/list`, stamps the result in metadata. Non-fatal; always audited.
- **Mutable kind** — flip an integration between api / cli / mcp / other without re-issuing.
- **Legacy default** — pre-rc13 integrations with no `kind` field read as `api`. Zero migration.

## Agent identity

- **P-256 Secure Enclave** on signed macOS builds. Hardware-backed, non-extractable.
- **File-backed P-256 fallback** on unsigned builds and Linux. Opt-in via `DOP_ALLOW_FILE_KEYS=1`. Loud warning box + `dop doctor` flag so operators see the downgrade.
- **Legacy ed25519** (pre-v1.11) still readable. One-command migration to P-256 (`dop agent migrate`).
- **Direct availability** — grant edits, env reseal, and bearer rotation take effect on the agent's next exec without re-claim. Admin's daemon re-encrypts the env to the agent's P-256 pubkey over ECDH.
- **Way B** — bearer-free exec. `dop exec` without `$DOP_TOKEN` scans local agent-keys and resolves implicitly. For long-running agents on their own machine.

## Approval UX

- **QR + Cloudflared quick tunnel** — admin's machine stands up a short-lived HTTPS tunnel per claim; TUI prints a QR encoding the URL.
- **Phone-based approval** — any phone camera opens the URL; the form asks for the approval passphrase. No app to install.
- **5-minute pending-claim window** — plenty of time for scan + unlock + type; short enough to limit the attacker window.
- **Rate limiting** (8 attempts shared across web + CLI) — attacker can't burn attempts from the CLI to bypass web counters.
- **Pending-claim auto-reap** of dead/expired records.

## TUI

- **Hierarchical menu** (post-rc19) — 6 primaries (Add / Issue / List / Remove / Vault / More), each opens a sub-page. Verbs, not categories. 1-5 + M keyboard jumps.
- **Preset pickers** everywhere forms exist — scope (`read-only`/`read-write`/`admin`/`other…`), kind (`api`/`cli`/`mcp`/`other`), protection, probe, advanced-fields.
- **Token drill-down** — enter on an integration row → token picker → view/edit scope/rotate value/remove per token. Rotate uses stdin; the value never crosses argv.
- **Integration-level edit** — `e` on the list opens kind/description/URL form; pre-populated with current values.
- **Status bar** on every list view — per-cursor-row details (`selected: boiler  |  kind=cli  |  grants=3  |  tokens=5  |  🔒 owner=a1b2c3d4…`). Rows stay clean; detail follows the cursor.
- **Dynamic column widths** — longest entry sets the column; no clipping on names like `boiler_skills-registry`.
- **Shared metadata block** — same renderer across integration drill-down and detail pane. Keeps the field order + "only non-empty" logic in one place.
- **`|` separators** in all help legends (Mole-style).
- **Pending-claim banner** — `a` from the main menu opens the inline approver when a claim is live.
- **Settings** — `f` toggles AllowFileKeys; TUI prefs stored in `tui-prefs.yaml`.

## Audit log

- **Append-only JSONL** at `<Logs>/audit.jsonl`, mode 0600, atomic via POSIX O_APPEND.
- **~20 event kinds**: `issue`, `claim*`, `repin`, `revoke`, `exec`, `env*`, `admin_*`, `invite*`, `agent_migrated`, `protected_*`, `integration_probed`, `integration_token_set`.
- **`dop watch`** — live tail with `--since D`, `--all`, `--filter K,K,K`, `--no-color`. Detects log rotation via inode change.
- **macOS notifications** on `claim_pending` / `claim_denied` / `revoke`. `DOP_NO_NOTIFY=1` for CI.
- **Non-blocking writes** — audit failures never block primary flows.
- **Reads work without admin unlock** — tester / operator can inspect the audit log on a locked machine.

## Observability

- **`dop doctor`** — binary deps, admin session state, trust file, SE vs file-key counts, codesign posture, recent audit activity. `--security` mode adds hardening checks.
- **Clear error messages** on vault-encrypted-but-no-admin (points at `dop admin login` or `$DOP_TOKEN` instead of leaking the raw SOPS parse error).
- **Loud SE-fallback warning** (bordered box) when the binary can't reach the Secure Enclave.

## Developer / ops

- **`git-credential-dop`** — git picks up tokens from DOP automatically for repo cloning / pushing.
- **CI-friendly flags**: `--skip-approval` for test paths, `--passphrase-stdin` everywhere, `DOP_NO_TUI=1` for headless invocations.
- **`token issue --expires never`** sentinel for infrastructure-only bearers.
- **`token repin`** — bump a bearer's PIN without re-issuing. 1h default TTL for chat-friendly handoffs.
- **E2E suite** — 39 shell scripts cover every command path end-to-end.

## Documented contracts

18 numbered feature contracts in `_rules/_requirements/contracts/` pin the invariants each feature MUST honor across releases. Every rc that adds a feature also adds or updates its contract.

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
