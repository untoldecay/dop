# Skill: dop — scoped credential access

Run any command with per-agent scoped credentials from your DOP vault.
Never asks you for the token; never prints it back.

## When to use

Use this skill whenever you need to call a service in the DOP vault
(Notion, Boiler, GitHub, Linear, custom APIs) and the human has said
something like:

- "use the credentials from dop"
- "read from my boiler / notion"
- "run this against prod / staging"
- "with my read-only token"

If the user hasn't authorized a specific service, ask before proceeding.

## Prerequisites (must be true before invoking)

The token must already be in the shell env — either as `DOP_TOKEN=<bearer>`
or via a `--sign-with <keyfile>` reference the user gave you. Never request
the raw credential in chat; that would leak it into your context window
and into transcripts.

## Usage pattern

Always run the target command via `dop exec`:

```bash
dop exec --agent-name <short-descriptive-name> -- <your command>
```

Where:

- `--agent-name` is a self-reported label that ends up in the audit log.
  Use something specific to the task (`claude-notion-migration-check`,
  `claude-boiler-daily-report`), not just `claude`. It is NOT a secret.
- `<your command>` is whatever you actually want to run. `dop` injects
  environment variables like `BOILER_TOKEN`, `NOTION_TOKEN`,
  `BOILER_BASE_URL`, etc., scoped to what the current token unlocks.

## Discovering what your token can do

Before doing anything sensitive, run:

```bash
dop whoami
```

This prints the token's *name* and the *grants* it unlocks (e.g.
`boiler.read`, `notion.write`). NEVER print bearers.

If a grant you need is missing, stop and tell the human — do not attempt
to escalate.

## Cryptographic-identity (`--sign-with`) variant

If the user tells you to use a signed-challenge auth (e.g. for a Buzz
agent that has its own keypair), the shape is:

```bash
dop exec --agent-name <agent-name-in-vault> \
         --sign-with <path-to-age-keyfile> \
         -- <your command>
```

The `--agent-name` here must match a `agent_pubkeys.<name>` entry in the
vault; DOP verifies the keyfile's derived age recipient matches.

## Do NOT

- **Do not** copy `DOP_TOKEN` into chat, PR descriptions, git commits,
  logs, or files. The whole point is that it stays in the env only.
- **Do not** run commands outside `dop exec` if they need any credential
  the vault manages — you'd end up either failing (no env vars) or
  reaching for a fallback secret that shouldn't exist.
- **Do not** call `dop token issue` or `dop token revoke` from an
  automated turn without the human explicitly asking. Both are admin ops.

## Failure modes and what to do

- **`dop exec: unknown auth token`** — `DOP_TOKEN` is set but not
  recognized by the vault. Ask the human to check they exported the
  right token; do not retry silently.
- **`dop exec: no vault path`** — the user hasn't run `dop init --vault
  <path>` on this machine. Point them at the DOP README.
- **`dop exec: sops binary not found in $PATH`** — installer prereq
  missing. Suggest `brew install sops`.

## Where the audit log lives

Every `dop exec` you make writes a line to
`~/.config/dop/logs/access-<host>-<YYYY-MM>.jsonl`. The human can review
your access with `dop log tail` or `dop log grep agent_name=<yours>`.
Choose a distinctive `--agent-name` so your session is greppable later.
