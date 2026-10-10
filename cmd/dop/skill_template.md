---
name: dop-credential-access
description: Use when needing to call a service whose credentials live in the DOP vault (Notion, Boiler, GitHub, Linear, custom APIs) — for reading data, writing changes, or admin operations
---

# DOP Credential Access

## Overview

DOP holds service credentials in a per-agent scoped vault. Always invoke the target command through `dop exec` — never handle bearers directly.

## If you don't normally use DOP (short rule for unfamiliar agents)

**Use `DOP_TOKEN` if it's already in your environment. Otherwise behave as if DOP isn't installed.**

| Environment state | What you do |
|---|---|
| `DOP_TOKEN` is set | The operator already approved your access by running `eval "$(dop use <subject>)"` before invoking you. Use the token. Prefer `dop exec --agent-name <task> -- <cmd>` for scoped env; otherwise pass `$DOP_TOKEN` as a bearer in your HTTP calls. |
| `DOP_TOKEN` is unset | The operator did not grant you DOP access. Do NOT invoke `dop use`, `dop token issue`, `dop env`, or `dop claim` yourself. Fall back to whatever credential path you'd use otherwise (hardcoded env, OAuth, user prompt). If none exists, tell the operator you can't do the task without credentials. |

**Why:** every DOP command that prints a secret requires a native approval popup the operator sees. An agent that invokes `dop use` on its own triggers an unexpected popup — the operator will likely deny (because they didn't ask for this), and your task fails anyway. Announcing your intent (either by using what's in env OR declining the task cleanly) is strictly better than guessing.

**Do NOT invoke on your own:** `dop use`, `dop token issue`, `dop env`, `dop claim`.
**Safe commands (no popup, no mutation):** `dop whoami`, `dop version`, `dop help`, `dop exec --agent-name <X> -- <cmd>` (uses an existing `DOP_TOKEN` if set; refuses otherwise, with no popup).

## When to Use

- User references DOP, "the vault", "my scoped token", "the read-only token", or a service known to be under DOP (Notion, Boiler, GitHub, Linear, and any others declared in `dop token list`)
- User says "call the API", "read the Notion database", "write to Boiler" and hasn't told you to use a different auth path

## When NOT to Use

- User has provided direct credentials for a one-off task
- Target service is not tracked in the vault
- User explicitly asks for a different auth mechanism

## Which kind of bearer do you have?

Three kinds exist and each has one correct way in. Check with `dop whoami` if unsure.

| You were given | Kind | How to use it |
|---|---|---|
| bearer + PIN (`dop claim …` in the handoff) | **claimed** | run the claim once; from then on `dop exec --agent-name <subject> -- <cmd>` with **no `DOP_TOKEN`** — this host's agent key is the proof |
| a subject name and `/dop-use` or `dop use` | **portable** | `eval "$(dop use <subject>)" && dop exec --agent-name <task> -- <cmd>` in every shell call |
| a bare bearer, no PIN | **unbound** | `DOP_TOKEN=<bearer> dop exec --agent-name <task> -- <cmd>` |

Never `eval "$(dop env)"`: it puts the raw keys in your shell. `dop env` is refused for claimed bearers anyway. Never write a key's value into a command; reference it by name inside the child, e.g. `dop exec --agent-name x -- sh -c 'curl -H "Authorization: Bearer $NOTION_TOKEN" …'`.

## Onboarding (first time the user hands you access)

If the user gives you a bearer AND a PIN (something like `SP-BZ-SA`), bind first:

```bash
DOP_TOKEN=<bearer> dop claim <PIN>
```

`dop claim` records this agent's cryptographic identity against the bearer and writes a private key to `~/.dop/agent-keys/<lookup_id>.key`. Subsequent `dop exec` calls proof-of-possession against that key automatically.

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

## Portable bearers (admin plane)

If the user has issued a bearer with `--portable`, they can grant it to any of their own shells with `dop use <subject>` — no PIN claim, no `dop claim` dance. These bearers resolve against the admin's own age identity (stashed on the capability record) rather than an agent-bound key.

### The transcript leak trap

**Never run `! dop use <subject>` directly.** When you execute via the `!` prefix, your runtime captures stdout and writes it into the chat transcript on disk. `dop use`'s default output IS `export DOP_TOKEN=<bearer>` on stdout, so bare invocation leaks the bearer value into the transcript.

v1.14.0-rc3+ refuses to print to a non-tty by default, which saves you most of the time. But the right incantation is still:

```bash
! eval "$(dop use <subject>)"
```

`$(...)` captures stdout into the shell before anything prints; `eval` consumes it to set `DOP_TOKEN`; nothing lands in the transcript. The only thing logged is the literal command text `eval "$(dop use <subject>)"`.

For reads that need the var in the SAME command (your tool calls don't share shell state across invocations), inline the resolve each time:

```bash
! eval "$(dop use <subject>)" && <command that reads DOP_TOKEN>
```

### If you already ran `! dop use <subject>` by accident

The bearer value is in the transcript. Treat it as leaked. Ask the user to:

1. `dop token revoke <subject>`
2. `dop token issue --name <subject> --grants ... --portable` (fresh bearer, same scope)

Then rerun your task with `eval "$(dop use <subject>)"`.

## Do NOT

- Request `DOP_TOKEN` or any bearer in chat. It stays in the shell env only.
- Run `dop token issue` or `dop token revoke` unprompted. Both are admin ops.
- Fall back to raw upstream env vars (e.g. `NOTION_TOKEN=...`) if `dop exec` fails. Report the error instead.
- Run `! dop use <subject>` directly (see "Portable bearers" above). Always wrap in `eval "$(...)"`.
- Run `dop use` on a claimed bearer, or `eval "$(dop env)"` on anything. Claimed means `dop exec` alone.
- Keep passing `DOP_TOKEN=…` after a claim succeeded. The agent key replaces it.

## Common Failure Modes

- **`this bearer requires a PIN claim first`** — run `dop claim <PIN>` with the PIN the user gave you before attempting exec.
- **`this bearer is bound but no agent key is present on this machine`** — the bearer was claimed on a different machine. Ask the user to revoke + re-issue for this host.
- **`PIN does not match` / `PIN expired`** — ask the user for a fresh PIN via `dop token repin --subject <name>`.
- **`unknown bearer (bundle not found)`** — `DOP_TOKEN` is set but not in the vault. `dop claim` pulls the vault first, so the admin most likely has not pushed yet; ask them to `dop push` and retry.
- **`dop env: refused — … bound to an agent key`** — expected for a claimed bearer. Use `dop exec --agent-name <subject> -- <cmd>` instead.
- **`no vault path`** — the user hasn't run `dop init --vault ...` on this machine. Point them at the DOP README.
- **`sops binary not found`** — installer prereq missing. Suggest `brew install sops`.

## Audit Trail

Every invocation writes one line to `~/.config/dop/logs/access-<host>-<YYYY-MM>.jsonl`. Users grep by `agent_name`, so make `--agent-name` distinctive per task.
