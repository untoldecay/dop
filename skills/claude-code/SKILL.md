---
name: dop-credential-access
description: Use when needing to call a service whose credentials live in the DOP vault (Notion, Boiler, GitHub, Linear, custom APIs) — for reading data, writing changes, or admin operations
---

# DOP Credential Access

## Overview

DOP holds service credentials in a per-agent scoped vault. Always invoke the target command through `dop exec` — never handle bearers directly.

## When to Use

- User references DOP, "the vault", "my scoped token", "the read-only token", or a service known to be under DOP (Notion, Boiler, GitHub, Linear, and any others declared in `dop token list`)
- User says "call the API", "read the Notion database", "write to Boiler" and hasn't told you to use a different auth path

## When NOT to Use

- User has provided direct credentials for a one-off task
- Target service is not tracked in the vault
- User explicitly asks for a different auth mechanism

## Onboarding (first time the user hands you access)

If the user gives you a bearer AND a PIN (something like `SP-BZ-SA`), bind first:

```bash
DOP_TOKEN=<bearer> dop claim <PIN>
```

`dop claim` will print a QR code + a public URL and block. The user scans the QR on their phone (or opens the URL), enters their DOP approval passphrase, and approves. Then `dop claim` records this agent's cryptographic identity and writes a private key to `~/.dop/agent-keys/<lookup_id>.key`. Subsequent `dop exec` calls prove possession of that key automatically.

**Wait for the approval — do not cancel and retry.** The approval window is 2 minutes; if it expires, ask the user for a fresh PIN via `dop token repin --subject <name>`.

If the user only gives you a bearer (no PIN), the token was issued with `--no-bind` — skip claim, jump straight to `dop exec`.

If the PIN has expired ("PIN does not match" after clearly correct input), ask the user to run `dop token repin --subject <name>` and hand you a fresh one.

## Core Pattern

Every credential-requiring command becomes:

```bash
dop exec --agent-name <specific-task-name> -- <your command>
```

`--agent-name` labels the audit log. Use something specific to the task (`claude-notion-migration-check`, not `claude`). It is not a secret.

## Quick Reference

| Task | Command |
|---|---|
| Discover what your token unlocks | `dop whoami` |
| Preview env vars the token injects | `dop env` |
| Run a command with scoped env | `dop exec --agent-name X -- CMD` |
| Strip inherited env from the child | add `--clean-env` |

## Do NOT

- Request `DOP_TOKEN` or any bearer in chat. It stays in the shell env only.
- Run `dop token issue` or `dop token revoke` unprompted. Both are admin ops.
- Fall back to raw upstream env vars (e.g. `NOTION_TOKEN=...`) if `dop exec` fails. Report the error instead.

## Common Failure Modes

- **`approval window expired`** — the user didn't run `dop approve <SAS>` in time. Ask them to run `dop token repin --subject <name>` for a fresh PIN, then start over.
- **`claim rejected by admin`** — the user chose to deny. Stop and ask them why before retrying.
- **`this bearer requires a PIN claim first`** — run `dop claim <PIN>` with the PIN the user gave you before attempting exec.
- **`this bearer is bound but no agent key is present on this machine`** — the bearer was claimed on a different machine. Ask the user to revoke + re-issue for this host.
- **`PIN does not match` / `PIN expired`** — ask the user for a fresh PIN via `dop token repin --subject <name>`.
- **`unknown bearer (bundle not found)`** — `DOP_TOKEN` is set but not in the vault. Ask the user to check they exported the right one.
- **`no vault path`** — the user hasn't run `dop init --vault ...` on this machine. Point them at the DOP README.
- **`sops binary not found`** — installer prereq missing. Suggest `brew install sops`.

## Audit Trail

Every invocation writes one line to `~/.config/dop/logs/access-<host>-<YYYY-MM>.jsonl`. Users grep by `agent_name`, so make `--agent-name` distinctive per task.
