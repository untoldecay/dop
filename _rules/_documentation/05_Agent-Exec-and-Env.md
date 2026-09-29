# Agent Exec & Env

**Date:** 2026-09-29
**Contracts:** [`09_agent_exec.md`](../_requirements/contracts/09_agent_exec.md), [`05_signed_record_and_trust.md`](../_requirements/contracts/05_signed_record_and_trust.md), [`06_pin_claim_binding.md`](../_requirements/contracts/06_pin_claim_binding.md)

Once a bearer is issued and (if bound) claimed, this is how the agent actually spends it. Everything here runs on the execution plane — no vault access, no admin keys.

---

## Commands

### `dop exec --agent-name <label> -- <cmd> [args]`
`apps/dop/cmd/dop/execcmd.go:29`

Resolves the bearer, verifies the signature, injects the granted env vars, then `execve()`s the child.

```bash
DOP_TOKEN=tok_1... dop exec --agent-name notion-import -- python migrate.py
```

| Flag | Default | Meaning |
|---|---|---|
| `--agent-name` | "" | Free-text label logged in audit + shown in error banners |
| `--token-file <path>` | — | Read bearer from file instead of env |
| `--clean-env` | off | Strip inherited env except PATH/HOME/USER/SHELL/TERM/LANG |
| `--no-pull` | off | Skip freshness check (currently no-op — Phase 5 polish) |

What it does (contract 09):
1. Read bearer from `$DOP_TOKEN` / `--token-file` / `$DOP_TOKEN_FILE`.
2. Compute `lookup_id = HMAC(vault_context, bearer)[:20]`.
3. Load and verify `<Vault>/capabilities/<lookup_id>.record` against `admins.trust` — signature + `issued_by` + `bundle_hash` + `status`.
4. Decrypt `<Vault>/capabilities/<lookup_id>.bundle` with the bearer.
5. Cross-check binding: if the record's binding requires a pubkey, load `<Root>/agent-keys/<lookup_id>.key` (mode 0600) and verify it matches.
6. Bump the generation cache if the bundle's gen is higher than what we've seen.
7. Emit an `exec` audit event.
8. Harden the env for known-risky children (git today; see below).
9. `syscall.Exec` — no shell in between.

### `dop whoami`
`execcmd.go:88`

Resolves the bearer and prints subject, generation, expiry, binding state. Safe to run in a chat context — reveals only metadata, never the upstream token value.

### `dop env`
`execcmd.go:143`

Emits `export KEY='VALUE'` lines suitable for `eval`. **This prints the actual upstream secrets** — don't run in an untrusted terminal.

---

## Env-hardening for git

When `argv[0]` basename is `git`, `execChild` (`execcmd.go:294`) does:

**Strip** these inherited env vars:
- `GIT_SSH_COMMAND`
- `GIT_EXTERNAL_DIFF`
- `GIT_ASKPASS`

**Inject** these before the token env:
```
GIT_TERMINAL_PROMPT=0
GIT_CONFIG_NOSYSTEM=1
GIT_CONFIG_COUNT=2
GIT_CONFIG_KEY_0=core.hooksPath
GIT_CONFIG_VALUE_0=/dev/null
GIT_CONFIG_KEY_1=protocol.ext.allow
GIT_CONFIG_VALUE_1=never
```

Prevents a hostile repo's post-checkout hook (or a rogue `~/.gitconfig include-if`) from running with the credentials in reach. Pattern lifted from Buzz's `configure_git_auth`.

---

## Env injection rules

- Every grant contributes `<PREFIX>_TOKEN` = the upstream token value.
- Any integration `metadata: {k: v}` contributes `<PREFIX>_<K_UPPER>` = v.
- Keys are injected sorted for deterministic child env order.
- The bearer itself is never in the child env.
- The agent private key is never in the child env.

Example: grant `notion.read` (integration `notion` with `metadata: {base_url: https://api.notion.com/v1}`) → child sees:
```
NOTION_TOKEN=ntn_...
NOTION_BASE_URL=https://api.notion.com/v1
```

---

## Failure modes

| Message | Meaning |
|---|---|
| `no bearer (set $DOP_TOKEN or --token-file)` | Set DOP_TOKEN. |
| `unknown bearer (or revoked)` | Bundle missing. Bearer is invalid or was revoked. |
| `record verify: no signed record for this bearer` | `.record` sidecar missing — pull the vault. |
| `record verify: no admins.trust file` | Fresh agent install; admin needs to push after their first `token issue`. |
| `record verify: signature: ...` | Tampered sidecar. Do not use. |
| `this bearer requires a PIN claim first` | Run `dop claim <PIN>` before exec. |
| `no agent key on this machine` | Bearer bound elsewhere. Reissue on this host. |
| `local agent key does not match the bound pubkey` | Someone rebound the bearer. Reissue. |
| `bundle superseded (gen N < min M)` | Rollback replay. A newer bundle was seen; this one is old. |

---

## Best practices

- Use `--agent-name <specific-task>` every time. It's the audit-log dimension you'll grep by.
- Prefer `dop exec` over `eval $(dop env)`. `exec` never puts the secret in your shell's environment.
- `--clean-env` for anything you don't trust to inherit safely.
- For git, `dop exec` already hardens — no manual work.

---

## Dependencies

- `crypto/ed25519` — sig verify, pubkey match.
- `syscall.Exec` — direct process replacement, no shell.
- `internal/capability` (Read, LookupID).
- `internal/trust` (Load).
- `internal/audit`.

---

## Next steps

- Extend env-hardening to docker (`DOCKER_CONFIG=/dev/null`), kubectl, ssh.
- Optional `--audit-tags k=v,k=v` for richer audit context per invocation.
- Auto-freshness check via `dop pull` when the last-modified bundle is older than `$DOP_AUTO_PULL` (default 5m, currently unwired).
