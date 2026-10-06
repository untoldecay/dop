# CLI reference

Every `dop` command, grouped by what you're trying to do. Bare `dop` launches the TUI; everything below is the non-interactive surface.

## Contents

- [Top-level](#top-level) — `dop`, `version`, `help`, `uninstall`
- [Admin session](#admin-session) — `init`, `login`, `logout`, `status`, `set-approval`, `join`, `reset`
- [Vault attach + sync](#vault-attach--sync) — `init`, `pull`, `push`, `vault edit`, `doctor`
- [Integrations](#integrations) — `add`, `list`, `remove`, `remove-token`, `set-token`
- [Grants](#grants) — `add`, `list`, `show`, `remove`
- [Tokens](#tokens-bearers) — `issue`, `list`, `show`, `revoke`, `prune`, `repin`, `reseal`, `add-grant`, `remove-grant`, `rotate`
- [Claim + approval](#claim--approval) — `claim`, `pending`, `approve`, `reject`, `approve-remote`
- [Agent keys](#agent-keys) — `list`, `info`, `migrate`, `sweep`, `delete`
- [Execution plane](#execution-plane) — `exec`, `whoami`, `env`
- [Team](#team) — `invite`, `add-key`, `list`, `remove`
- [Audit + git credentials](#audit--git-credentials) — `watch`, `credential-helper`
- [Environment variables](#environment-variables)

---

## Top-level

### `dop`

Launch the TUI when stdin and stdout are TTYs; otherwise print usage. `--no-tui` or `DOP_NO_TUI=1` suppresses the TUI.

### `dop version`

Print version, commit, build date. Aliases: `-v`, `--version`.

### `dop help`

Print the long usage block. Aliases: `-h`, `--help`.

### `dop uninstall`

Alias for [`dop admin reset`](#dop-admin-reset).

```
dop uninstall [--force]
```

| Flag | Default | Description |
|---|---|---|
| `--force` | false | Skip the typed `RESET` confirmation. |

---

## Admin session

All admin-plane mutations require an unlocked session.

### `dop admin init`

Generate the admin keypair (age + ed25519), wrap with a passphrase, set a separate approval passphrase. One-shot per machine.

```
dop admin init [--force] [--passphrase-stdin]
```

| Flag | Default | Description |
|---|---|---|
| `--force` | false | Overwrite an existing admin key. Destroys access to any vault it decrypts. |
| `--passphrase-stdin` | false | Read passphrases from stdin. Expects two lines: admin, then approval. |

Admin passphrase ≥ 8 chars, approval ≥ 10. Failures roll back so retry works without `--force`.

### `dop admin login`

Prompt for the admin passphrase, unwrap keys, fork the session daemon. Runs a silent pull + merge so your next action sees the latest team state.

```
dop admin login [--passphrase-stdin]
```

Session idle TTL defaults to 15m, absolute to 60m. Override with `DOP_ADMIN_TTL` / `DOP_ADMIN_MAX_TTL`.

### `dop admin logout`

End the current session. No-op if none active.

```
dop admin logout
```

### `dop admin status`

Print session state, admin pubkey, age recipient, remaining TTLs, and an agent-key backend summary.

```
dop admin status
```

Prints `locked` with no session; `unlocked` plus details otherwise.

### `dop admin set-approval`

Rotate the approval passphrase without touching the admin key. Requires an active session.

```
dop admin set-approval [--passphrase-stdin]
```

### `dop admin join`

Attach a new admin device to an existing vault using a PIN from `dop team invite`.

```
dop admin join <VAULT-URL> <PIN> [--timeout 30m] [--passphrase-stdin]
```

| Flag | Default | Description |
|---|---|---|
| `--timeout` | `30m` | How long to wait for the original admin to approve. |
| `--passphrase-stdin` | false | Read passphrase from stdin. |

Clones the vault if not attached; otherwise pulls. Supports both per-device and shared-identity invite kinds.

### `dop admin reset`

Wipe all local DOP state (admin keys, approval hash, vault clone, agent keys, caches, audit log, credential map). Binary is not touched. Prints paths to be deleted and requires typing `RESET`.

```
dop admin reset [--force]
```

| Flag | Default | Description |
|---|---|---|
| `--force` | false | Skip the typed confirmation. |

Nothing on other admin machines is affected. If this machine has a vault admin entry, run `dop team remove --name <label> --force` from another machine to prune it.

---

## Vault attach + sync

### `dop init`

Attach a vault. Exactly one of `--vault` (admin install) or `--cache` (agent install).

```
dop init --vault <url|path>
dop init --cache <url|path>
```

| Flag | Default | Description |
|---|---|---|
| `--vault` | "" | Admin install. Requires an existing admin key on this machine. |
| `--cache` | "" | Agent install. Refuses if an admin key exists. |

Local paths that don't exist are bootstrapped as bare git repos. URLs are cloned as-is.

### `dop pull`

Fetch and merge the vault. If both sides moved, DOP does a real three-way merge on the decrypted plaintext.

```
dop pull [--keep-mine|--keep-team] [--no-merge]
```

| Flag | Default | Description |
|---|---|---|
| `--keep-team` | false | Overwrite your local with the team's. |
| `--keep-mine` | false | Keep yours; prints how to force-push. |
| `--no-merge` | false | Diagnose and stop. |
| `--take-theirs` | false | Alias for `--keep-team`. |
| `--take-ours` | false | Alias for `--keep-mine`. |

Smart-merge needs an active admin session (decrypt required). Conflicts drop you back with a plain-English list and the one-shot flags above.

### `dop push`

Stage, commit (if dirty), push.

```
dop push [--force]
```

| Flag | Default | Description |
|---|---|---|
| `--force` | false | `--force-with-lease`. Pair with `dop pull --keep-mine`. Not reversible from the team side. |

### `dop vault edit`

Open the decrypted vault in `$EDITOR` and re-encrypt on save. Plaintext lives in a mode-0600 tempfile scrubbed on close. Admin session required.

```
dop vault edit [--editor <bin>]
```

| Flag | Default | Description |
|---|---|---|
| `--editor` | `$EDITOR` or `vi` | Override the editor binary. |

Sidecar records are rewritten on save; orphaned or revoked capabilities are cleaned up.

### `dop doctor`

Health check across binaries, admin install, vault attach, trust list, agent keys, codesign posture, sidecars, audit log, gen cache, pending claims, prefix collisions.

```
dop doctor [--security]
```

| Flag | Default | Description |
|---|---|---|
| `--security` | false | Add paranoia-mode checks: bundle perms, shell-history leaks, vault.yaml perms, long TTLs. |

Non-zero exit if any check hard-fails.

---

## Integrations

Admin-session required for mutations.

### `dop integration add`

Add or update an integration. Merges into an existing entry: metadata keys update, untouched tokens stay.

```
dop integration add --name <N> --token NAME=VALUE[:SCOPE_NOTE] [...]
```

| Flag | Default | Description |
|---|---|---|
| `--name` | "" | Integration name (required). Normalized: `Notion` and `notion` collide to one key. |
| `--token` | — | `NAME=VALUE:SCOPE_NOTE` (repeatable). Required on create, optional on update. |
| `--description` | "" | Free-text description. |
| `--base-url` | "" | Base URL for the service. |
| `--metadata` | — | Extra `KEY=VALUE` (repeatable). |
| `--kind` | "" | `api` (default) · `cli` · `mcp` · `other`. |
| `--endpoints-url` | "" | api — URL where the service documents its endpoints. |
| `--auth-header` | "" | api — auth-header template (defaults to `Bearer`). |
| `--auth-style` | "" | api — e.g. `bearer-header`, `basic`, `query-param`. |
| `--cmd` | "" | cli — binary name the agent should invoke. |
| `--args-hint` | "" | cli — free-form usage snippet. |
| `--cli-auth-env` | "" | cli — `KEY=VAL;KEY=VAL` template; substitutes `$TOKEN`, `$SERVER_ROOT`, `$BASE_URL`. |
| `--cli-install` | "" | cli — install hint for the binary. |
| `--cli-help` | "" | cli — command the agent runs to self-discover the CLI. |
| `--mcp-url` | "" | mcp — HTTP URL for the MCP server. |
| `--mcp-cmd` | "" | mcp — stdio launcher command. |
| `--server-root` | "" | Server root distinct from `base_url`. |
| `--allowed` | "" | Scope allowlist hint (free-form, non-enforced). |
| `--probe-endpoints` | false | Opt-in: scan common OpenAPI paths (api) or `tools/list` (mcp) and stamp the result. |
| `--protected` | false | Owner-lock to the current admin. Prompts the approval passphrase. |
| `--passphrase-stdin` | false | Read approval passphrase from stdin (with `--protected`). |

### `dop integration list`

List integrations with their tokens, metadata, kind, and lock status. Admins see all; non-admin bearers see only integrations their grants reference.

```
dop integration list
```

### `dop integration remove`

```
dop integration remove --name <N> [--force]
```

| Flag | Default | Description |
|---|---|---|
| `--name` | "" | Required. |
| `--force` | false | Also remove grants referencing it. |

### `dop integration remove-token`

Remove one or more tokens and cascade through grants + active capabilities. Empties the integration if no tokens remain.

```
dop integration remove-token --name <N> --token <T> [--token <T2>...]
  [--force-revoke-ed25519]
```

| Flag | Default | Description |
|---|---|---|
| `--name` | "" | Required. |
| `--token` | — | Upstream token name (repeatable, required). |
| `--force-revoke-ed25519` | false | Revoke ed25519 bearers whose bundle env can't be resealed. |

### `dop integration set-token`

Rotate a token's value and/or edit its scope note. At least one of `--value`, `--value-stdin`, `--scope-note` is required.

```
dop integration set-token --name <N> --token-name <T>
  [--value <V>|--value-stdin] [--scope-note <S>]
```

| Flag | Default | Description |
|---|---|---|
| `--name` | "" | Integration (required). |
| `--token-name` | "" | Upstream token (required). |
| `--value` | "" | New value. |
| `--value-stdin` | false | Read value from stdin (keeps secrets off the command line). |
| `--scope-note` | "" | New scope note. |

P-256 bearers see the new value on next `dop exec`. ed25519 bearers need `dop token reseal <subject>`.

---

## Grants

A grant maps `integration.token` to an env var prefix. Issued tokens bundle grants.

### `dop grant add`

Add or update a grant.

```
dop grant add --id <ID> --integration <N> --token <T>
  [--env-prefix <P>] [--projects CSV] [--tags CSV]
```

| Flag | Default | Description |
|---|---|---|
| `--id` | "" | Grant id, e.g. `notion.read` (required). |
| `--integration` | "" | Integration name (required). |
| `--token` | "" | Upstream token name (required). |
| `--env-prefix` | "" | Env var prefix. Default `<INTEGRATION>_<TOKEN>`, sanitized. |
| `--projects` | "" | Comma-separated project tags (cosmetic grouping). |
| `--tags` | "" | Comma-separated free-form tags. |

Grants inherit `protected` + `owner` from their parent integration.

### `dop grant list`

List grouped by project. Non-admin bearers see only grants on their own capability.

```
dop grant list [--project <P>] [--tag <T>]
```

| Flag | Default | Description |
|---|---|---|
| `--project` | "" | Only grants in this project. |
| `--tag` | "" | Only grants with this tag. |

### `dop grant show`

Grant metadata plus every active token referencing it.

```
dop grant show <grant-id> [--all] [--json]
```

| Flag | Default | Description |
|---|---|---|
| `--all` | false | Include revoked tokens. |
| `--json` | false | JSON instead of human-readable. |

### `dop grant remove`

Remove a grant and cascade through active capabilities.

```
dop grant remove --id <ID> [--force-revoke-ed25519]
```

| Flag | Default | Description |
|---|---|---|
| `--id` | "" | Grant id (required). |
| `--force-revoke-ed25519` | false | Revoke ed25519 bearers whose bundle env can't be resealed; otherwise they're left stale with a warning. |

---

## Tokens (bearers)

A token is a bearer secret paired with a signed capability record. Admin session required.

### `dop token issue`

Mint a capability + bearer.

```
dop token issue --grants CSV --name <L> [flags]
dop token issue --project <P> [--tags CSV] --name <L> [flags]
```

| Flag | Default | Description |
|---|---|---|
| `--grants` | "" | CSV of grant IDs. Required unless `--project` is set. |
| `--project` | "" | Bundles all grants tagged with this project. |
| `--tags` | "" | Keep only grants carrying ALL these tags. |
| `--name` | "" | Human-readable subject/label. |
| `--expires` | `72h` | Duration (`72h`, `30d`, `4w`) or the literal `never`. |
| `--note` | "" | Free-text note (unused). |
| `--bind-pubkey` | "" | Pre-bind to this ed25519 pubkey (hex) instead of PIN. |
| `--no-bind` | false | Unbound bearer — bearer alone grants access. Unsafe outside local tests. |
| `--pin-ttl` | `1h` | PIN validity window when default-bound. Use `dop token repin` if it expires. |
| `--passphrase-stdin` | false | Read approval passphrase from stdin (required when any grant is protected). |

Prints bearer + PIN exactly once on stdout. Env-prefix collisions in the grant set are refused up front.

### `dop token list`

```
dop token list [--all]
```

| Flag | Default | Description |
|---|---|---|
| `--all` | false | Include revoked capabilities. |

### `dop token show`

Detail view for one token.

```
dop token show <lookup|subject> [--json]
```

Argument is a lookup-id prefix (min 6), cap-id prefix, or exact subject. Rotated-plus-active pair prefers active.

### `dop token revoke`

Revoke by subject, cap-id prefix, or lookup-id prefix.

```
dop token revoke <subject|cap-id-prefix|lookup-prefix>
```

Deletes bundle, record sidecar, local agent key file. Bumps generation.

### `dop token prune`

Delete old revoked and rotated records.

```
dop token prune [--older-than 30d] [--dry-run] [--yes]
```

| Flag | Default | Description |
|---|---|---|
| `--older-than` | `30d` | Cutoff. Go durations plus `d` and `w`. |
| `--dry-run` | false | Print the candidates (subject, status, age, lookup id) and change nothing. |
| `--yes` | false | Skip the `prune N records? [y/N]` prompt (`DOP_FROM_TUI=1` skips it too). |

A record is a candidate when it is revoked or rotated and it was revoked (`revoked_at`) or rotated (the rotation seal) longer ago than the cutoff, so a rotated bearer's agent keeps the full cutoff to pick up the new bearer. Records revoked before `revoked_at` existed age from their newest creation, claim or seal time. Active records are never pruned. Removes the records from the vault, deletes their bundle, record and local agent key files, saves the vault once and writes one `prune` audit event. Generation counters stay. Prints `pruned N records (older than 30d)`, or `nothing to prune`.

### `dop token repin`

Give an unclaimed PIN-bound bearer a new PIN, for example when the first one expired before the agent claimed.

```
dop token repin --subject <S> [--pin-ttl 1h] [--passphrase-stdin]
```

| Flag | Default | Description |
|---|---|---|
| `--subject` | "" | Required. |
| `--pin-ttl` | `1h` | New PIN window. |
| `--passphrase-stdin` | false | Read the approval passphrase from stdin (asked only when the bearer holds a protected grant). |

DOP never keeps a bearer it has handed out, so repin re-issues it the way `dop token portable --on` does for an unclaimed bearer: a new bearer with the same subject, grants, expiry and binding policy and a new PIN, the old record revoked in the same save (its bundle and record files removed). A portable copy, when the old bearer had one, is stored again from the new bearer. Prints the bearer and PIN once, like `dop token issue`; hand both to the agent.

Refuses a claimed bearer (use `dop token rotate`), a bearer that is not PIN-bound, and a revoked or expired one.

### `dop token portable`

Make a bearer portable (`--on`) or remove its portable copy (`--off`), the copy wrapped to your admin age key that `dop use` reads.

DOP never keeps a bearer it has handed out, so `--on` re-issues it with the same subject, grants, expiry and binding, and stores the portable copy from the fresh value:

- **Claimed** (bound pubkey): rotated exactly like `dop token rotate`. The old record becomes `rotated` with the new bearer sealed to the agent's key; the agent switches on its next `dop exec`, nothing to hand over.
- **Unclaimed** (PIN, or unbound): a new bearer is issued (with a new PIN, valid `1h`) and the old one is revoked. The new bearer and PIN print once, same format as `dop token issue`.
- **Revoked or expired**: refused.

`--on` asks the approval passphrase only when the bearer holds a protected grant; `--off` always asks it.

```
dop token portable --subject <S> (--on | --off) [--passphrase-stdin]
```

### `dop token reseal`

Regenerate `EnvWrapped` from current vault grants using the agent's P-256 pubkey. Needed to push grant-list changes to a bound bearer when `token add-grant` / `remove-grant` isn't an option.

```
dop token reseal <lookup|subject>
```

### `dop token add-grant`

Add a grant to an existing bearer and reseal `EnvWrapped`. Agent's next `dop exec` sees the new env; no re-claim.

```
dop token add-grant [--passphrase-stdin] <lookup|subject> <grant-id>
```

P-256-bound only. Ed25519 bearers get a clear "migrate first, or revoke + reissue" error. Prompts the approval passphrase for protected grants.

### `dop token remove-grant`

Symmetric to `add-grant`.

```
dop token remove-grant [--passphrase-stdin] <lookup|subject> <grant-id>
```

### `dop token rotate`

Rotate the bearer in place for a P-256-bound capability. Writes a fresh bundle + record under a new lookup id, marks the old record `status=rotated`, and attaches a `BearerWrapped` envelope so the agent's next exec picks up the new bearer transparently.

```
dop token rotate <lookup|subject>
```

Ed25519 bearers cannot rotate — migrate first with `dop agent migrate`.

---

## Claim + approval

### `dop claim`

Agent-side: bind a PIN-issued bearer to a local agent key. Default flow shows a QR, starts a Cloudflare quick tunnel, and blocks until the admin approves on their phone with the approval passphrase.

```
dop claim <PIN> [flags]
dop claim --cancel
dop claim --status [--json]
```

| Flag | Default | Description |
|---|---|---|
| `--token-file` | "" | Read bearer from file. |
| `--shell` | false | Also print `export DOP_TOKEN=...`. |
| `--skip-approval` | false | Finalize without out-of-band approval. Unsafe for chat handoff. |
| `--no-tunnel` | false | Serve the approval page on LAN only; bind to `0.0.0.0`. |
| `--bind` | `127.0.0.1` with tunnel, `0.0.0.0` without | Interface to bind the approval server. |
| `--remote` | false | No admin daemon here — stage the claim in the vault for `dop approve-remote`. |
| `--key-type` | "" (auto) | `p256` or `ed25519`. P-256 is required for direct grant edits and bearer rotation. |
| `--cancel` | false | Delete the in-flight pending claim for `$DOP_TOKEN` and exit. |
| `--status` | false | Print the pending-claim state and exit. |
| `--json` | false | Emit JSONL events on stdout. |

With `--cancel` or `--status` and no bearer, DOP scans the local pending-claims directory and acts on the one entry (or lists them if ambiguous).

### `dop pending`

List all pending PIN claims on this machine.

```
dop pending
```

### `dop approve`

Approve a pending claim. Prompts the approval passphrase; wrong passphrases burn one of the claim's attempts.

```
dop approve <SAS> [--passphrase-stdin]
```

### `dop reject`

Reject a pending claim. No passphrase (rejecting is safe).

```
dop reject <SAS>
```

### `dop approve-remote`

Admin-side: accept a `dop claim --remote` staged in the vault. Verifies the agent's signature, prompts the passphrase, swaps the bundle, writes an updated signed record, pushes.

```
dop approve-remote --subject <S> [--passphrase-stdin]
dop approve-remote --list
```

| Flag | Default | Description |
|---|---|---|
| `--subject` | "" | Required unless `--list`. |
| `--list` | false | List pending remote claims. |
| `--passphrase-stdin` | false | Read passphrase from stdin. |

---

## Agent keys

Per-bearer key material. On macOS, new keys land in the Secure Enclave when the binary is Developer-ID-signed; else fall back to file-backed P-256 (with `DOP_ALLOW_FILE_KEYS=1`) or legacy ed25519.

### `dop agent list`

Enumerate agent keys with backend, type, status (active · grace-delete · orphan).

```
dop agent list [--json]
```

### `dop agent info`

Lookup id, type, backend, extractability, storage path, pubkey.

```
dop agent info <lookup-id-or-prefix>
```

Prefix must be ≥ 4 characters.

### `dop agent migrate`

Re-enroll a legacy ed25519 key as SE-backed P-256. Admin session required. Keeps the old `.key` file 12h as a safety net.

```
dop agent migrate <lookup-id-or-prefix>
```

### `dop agent sweep`

Remove expired legacy keys past their 12h window, and any orphan agent-key files (post-revoke leftovers).

```
dop agent sweep
```

### `dop agent delete`

Delete the key for a lookup id from every backend (Keychain + file). Idempotent.

```
dop agent delete <lookup-id-or-prefix>
```

Pass a full 32+ char lookup id to also delete a Keychain entry that doesn't surface in `list`.

---

## Execution plane

Read a capability bundle and never open the vault.

### `dop exec`

Resolve the bearer (or local agent key), inject the scoped env, exec the child. `DOP_TOKEN` / `DOP_TOKEN_FILE` are always stripped from the child's env.

```
dop exec [--agent-name X] [--token-file PATH] [--inherit-env] [--no-pull] -- CMD [ARGS...]
```

| Flag | Default | Description |
|---|---|---|
| `--agent-name` | "" | Self-reported label for audit. Disambiguates when multiple agent keys are present. |
| `--token-file` | "" | Read bearer from file. |
| `--inherit-env` | false | Let the child see the parent's env. Default is clean-env (keeps only `PATH`, `HOME`, `USER`, `SHELL`, `TERM`, `LANG`). |
| `--no-pull` | false | Skip the silent auto-pull. |
| `--clean-env` | — | Deprecated no-op. |

When the child is `git`, DOP strips `GIT_SSH_COMMAND` / `GIT_EXTERNAL_DIFF` / `GIT_ASKPASS` and disables hooks + ext protocols before injecting env.

Bearer-free mode: with no bearer supplied, DOP scans local P-256 agent keys and resolves env via ECDH over the record's `EnvWrapped`. Ambiguous → pass `--agent-name`.

### `dop whoami`

Fingerprint, subject, generation, expiry, binding.

```
dop whoami
```

### `dop env`

Shell-eval-able `export KEY='value'` lines for the current bearer's scoped env. Same binding check as `exec`.

```
dop env
```

Auto-pull applies; opt out with `DOP_NO_AUTO_PULL=1`.

---

## Team

### `dop team invite`

Open an admin invite. Polls the vault until the joining machine responds, then prompts for the approval passphrase and completes the add.

```
dop team invite --name <L> [--kind device|team_member]
  [--pin-ttl 30m] [--timeout 30m] [--share-identity] [--passphrase-stdin]
```

| Flag | Default | Description |
|---|---|---|
| `--name` | "" | Label for the new admin device (required). |
| `--kind` | `device` | `device` (another machine of yours) or `team_member`. |
| `--pin-ttl` | `30m` | Invite validity window. |
| `--timeout` | `30m` | How long to wait for the response. |
| `--share-identity` | false | Flavor Y — hand the joining machine THIS machine's admin identity (one revocation surface across devices). |
| `--passphrase-stdin` | false | Read passphrase(s) from stdin. |

Prints the PIN + vault URL + the exact `dop admin join` command for the other machine.

### `dop team add-key`

Add an admin by pubkey directly (no interactive invite). Rare; most flows use `invite`.

```
dop team add-key --name <L> --pubkey <age1...> [--ed25519 <hex>] [--note <N>]
```

| Flag | Default | Description |
|---|---|---|
| `--name` | "" | Admin label (required). |
| `--pubkey` | "" | Age recipient (required). Must start with `age1`. |
| `--ed25519` | "" | Admin ed25519 pubkey (optional; needed for signature verification). |
| `--note` | "" | Free-text. |

### `dop team list`

List admins with age recipient, ed25519 pubkey, note.

```
dop team list
```

### `dop team remove`

Remove an admin and revoke every capability they issued. Dry-run by default — prints the upstream-token rotation checklist first.

```
dop team remove --name <L> [--force]
```

| Flag | Default | Description |
|---|---|---|
| `--name` | "" | Admin to remove (required). |
| `--force` | false | Actually remove. Otherwise prints the checklist and exits. |

Refuses to remove the only admin, and refuses to remove yourself.

---

## Audit + git credentials

### `dop watch`

Live-tail the audit log. Backfills from `--since`, then follows.

```
dop watch [--since 24h] [--all] [--filter K,K] [--no-color] [--follow=true]
```

| Flag | Default | Description |
|---|---|---|
| `--since` | `24h` | Backfill window. |
| `--all` | false | Print the entire log before following. |
| `--filter` | "" | Comma-separated event kinds (`issue`, `claim`, `claim_denied`, `repin`, `revoke`, …). |
| `--no-color` | false | Disable ANSI. Automatic when stdout isn't a TTY. |
| `--follow` | true | Keep tailing after backfill. |

Admin session unlocks the full feed; otherwise `$DOP_TOKEN` filters to events for that bearer's lookup id. No admin + no bearer → refused.

### `dop credential-helper map`

Add/update a `host → grant` mapping consumed by `dop-credential-git`.

```
dop credential-helper map --host <H> --grant <ID> [--username dop] [--env-prefix <P>]
```

| Flag | Default | Description |
|---|---|---|
| `--host` | "" | Host (required). |
| `--grant` | "" | Grant id whose `_TOKEN` env var is returned (required). |
| `--username` | `dop` | Username field returned to git. |
| `--env-prefix` | "" | Override auto-derived env prefix. |

Wire into git with `git config --global credential.helper 'dop-credential-git'`.

### `dop credential-helper list`

```
dop credential-helper list
```

### `dop credential-helper remove`

```
dop credential-helper remove --host <H>
```

---

## Environment variables

| Var | Default | Description |
|---|---|---|
| `DOP_TOKEN` | — | Bearer for `exec`, `whoami`, `env`, `claim`, `watch`. |
| `DOP_TOKEN_FILE` | — | Path to a file containing a bearer. Writable targets auto-rotate on bearer rotation. |
| `DOP_VAULT` | — | Override the vault path. |
| `DOP_NO_TUI` | — | `1` makes bare `dop` print usage instead of launching the TUI. |
| `DOP_ADMIN_TTL` | `15m` | Admin session idle timeout. |
| `DOP_ADMIN_MAX_TTL` | `60m` | Admin session absolute timeout. |
| `DOP_AUTO_PULL` | `5m` | Max staleness before `dop exec` auto-pulls. |
| `DOP_AUTOPULL_MAX_AGE_SEC` | `15` | Rate-limit window for the exec/env silent auto-pull. |
| `DOP_NO_AUTO_PULL` | — | `1` disables the login + exec/env auto-pull. |
| `DOP_NO_AUTO_PUSH` | — | `1` disables the auto-push after admin-plane saves. |
| `DOP_ALLOW_FILE_KEYS` | — | `1` permits file-backed P-256 agent keys (Linux/CI; macOS fallback). |
| `DOP_ALLOW_ADMIN_SHRINK` | — | Internal: lets `dop team remove` bypass the admin-shrink save guard. Do not set manually. |
