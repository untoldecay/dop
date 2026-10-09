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

## Which kind of bearer do you have?

Three kinds exist and each has one correct way in. Check with `dop whoami` if unsure.

| You were given | Kind | How to use it |
|---|---|---|
| bearer + PIN (`dop claim …` in the handoff) | **claimed** | run the claim once; from then on `dop exec --agent-name <subject> -- <cmd>` with **no `DOP_TOKEN`** — this host's agent key is the proof |
| a subject name and `/dop-use` or `dop use` | **portable** | `eval "$(dop use <subject>)" && dop exec --agent-name <task> -- <cmd>` in every shell call |
| a bare bearer, no PIN | **unbound** | `DOP_TOKEN=<bearer> dop exec --agent-name <task> -- <cmd>` |

Never `eval "$(dop env)"`: it puts the raw keys in your shell. `dop env` is refused for claimed bearers anyway. Never write a key's value into a command; reference it by name inside the child, e.g. `dop exec --agent-name x -- sh -c 'curl -H "Authorization: Bearer $NOTION_TOKEN" …'`.

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

**Alternative — `--json` for structured parsing:** if terminal-scraping the stderr header is fragile in your harness, run `dop claim --json <PIN>` instead. This emits JSONL on stdout:

```json
{"event":"pending","state":"pending","subject":"...","sas":"...","public_url":"...","lan_url":"...","qr_png":"/path/to/foo.qr.png","expires_at":"...","ttl_seconds":300,"cancel_hint":"dop claim --cancel"}
```

then on approval/rejection/timeout, a `{"event":"result","state":"claimed"|"aborted",...}` line. Parse fields directly instead of grepping the pretty header.

**If you need to abort a pending claim** (agent tool timeout, wrong PIN, user changed their mind), run `DOP_TOKEN=<bearer> dop claim --cancel` from any shell — it deletes the pending-claim file, the blocked `dop claim` process sees it disappear and exits. Also useful: `dop claim --status --json` reports the current state (`pending`, `approved`, `rejected`, `expired`, or `absent`) without spawning a new claim.

### After the claim

The bearer has done its job. Drop it from your environment (`unset DOP_TOKEN`) and stop passing it inline. Every later call is just:

```bash
dop exec --agent-name <subject> -- <your command>
```

If the handoff command carried `--remote`, the claim is staged in the vault repo and the operator approves it from their machine. Tell them it is waiting, then try the exec above; it works as soon as they approve. If the claim prints a URL or QR instead, relay it to the operator immediately — that is their approval page.

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
| Preview env var names the token injects | `dop whoami` (`dop env` is refused for claimed bearers) |
| Run a command with scoped env | `dop exec --agent-name X -- CMD` |
| Strip inherited env from the child | add `--clean-env` |

## Do NOT

- Request `DOP_TOKEN` or any bearer in chat. It stays in the shell env only.
- Run `dop token issue` or `dop token revoke` unprompted. Both are admin ops.
- Fall back to raw upstream env vars (e.g. `NOTION_TOKEN=...`) if `dop exec` fails. Report the error instead.
- Run `dop use` on a claimed bearer, or `eval "$(dop env)"` on anything. Claimed means `dop exec` alone.
- Keep passing `DOP_TOKEN=…` after a claim succeeded. The agent key replaces it.

## Common Failure Modes

- **`approval window expired`** — the user didn't run `dop approve <SAS>` in time. Ask them to run `dop token repin --subject <name>` for a fresh PIN, then start over.
- **`claim rejected by admin`** — the user chose to deny. Stop and ask them why before retrying.
- **`this bearer requires a PIN claim first`** — run `dop claim <PIN>` with the PIN the user gave you before attempting exec.
- **`this bearer is bound but no agent key is present on this machine`** — the bearer was claimed on a different machine. Ask the user to revoke + re-issue for this host.
- **`PIN does not match` / `PIN expired`** — ask the user for a fresh PIN via `dop token repin --subject <name>`.
- **`unknown bearer (bundle not found)`** — `DOP_TOKEN` is set but not in the vault. `dop claim` pulls the vault first, so the admin most likely has not pushed yet; ask them to `dop push` and retry.
- **`dop env: refused — … bound to an agent key`** — expected for a claimed bearer. Use `dop exec --agent-name <subject> -- <cmd>` instead.
- **`no vault path`** — the user hasn't run `dop init --vault ...` on this machine. Point them at the DOP README.
- **`sops binary not found`** — installer prereq missing. Suggest `brew install sops`.

## Audit Trail

Every invocation writes one line to `~/.config/dop/logs/access-<host>-<YYYY-MM>.jsonl`. Users grep by `agent_name`, so make `--agent-name` distinctive per task.
