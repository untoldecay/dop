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

If the user hands you the DOP welcome text (starts with "You have been given scoped credential access via DOP"), it already contains the exact command. Run it verbatim:

```bash
DOP_TOKEN=<bearer> dop claim <PIN>
```

`dop claim` will block for up to 5 minutes waiting for the user to approve on their phone. **While it runs, it prints a structured header on stderr with these fields:**

```
QR image: /Users/you/Library/Application Support/dop/pending-claims/<hex>.qr.png
Public URL: https://random-name.trycloudflare.com/c/<hex>
LAN URL: http://192.168.1.42:57553/c/<hex>
```

**What you MUST do next:**

1. **Attach the QR image file to your reply in this chat** (in Claude Code, use your file-display tool such as `SendUserFile` with the exact path from the `QR image:` line). This lets the user see + scan the QR right in the chat without leaving.
2. **Print the `Public URL` line as text** so the user can copy it and open on their phone if scanning fails.
3. Tell the user: *"Scan the QR above or open the URL on your phone, then enter your DOP approval passphrase to approve this binding."*
4. **Then wait — do NOT retry the claim.** It blocks until the user approves. The command will exit successfully on its own.

**Do NOT try to render the QR from ASCII or Unicode blocks yourself.** The terminal will show its own Unicode QR after the structured header — ignore it. The PNG file is the authoritative version.

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
