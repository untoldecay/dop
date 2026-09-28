# dop — Doors of Perception

A local-first, git-synced, per-agent-scoped credential gateway CLI with a
**two-plane authority model**:

- **Administrative plane** — decrypts + mutates the vault. Protected by a
  passphrase-unlocked admin session (sudo-style TTL).
- **Execution plane** — consumes per-bearer capability bundles. Never
  touches the vault. Remote servers install with no admin key at all.

Design docs: [`../../_rules/_projects/DOP/`](../../_rules/_projects/DOP/) —
`PROJECT_BRIEF.md`, `ARCHITECTURE.md`, `BUILD_PLAN.md`.

## Status

**v1.0.0.** Fresh cutover from v0.3.x — no automatic migration.

## Runtime dependencies

- `git`
- `sops` (>= 3.7) — `brew install sops` or [releases](https://github.com/getsops/sops/releases)

## Build

```
cd apps/dop
go build -o dop ./cmd/dop
```

## Testing

```
./scripts/test.sh              # unit + e2e (~11s)
./scripts/test.sh --unit-only  # unit only (~1s)
./scripts/test.sh --e2e-only   # e2e only (needs sops, git, python3)
```

Unit tests live next to code (Go convention). E2E scripts live in
`testdata/e2e/v1_*.sh`.

## Quick start — admin machine

```
# One-time
dop admin init                                         # prompt: passphrase (twice)
dop init --vault https://github.com/you/dop-vault.git  # attach a vault

# Per session
dop admin login                                        # prompt: passphrase
                                                       # session lasts 15m idle / 60m absolute

# Issue a bearer (admin session required)
dop token issue --grants notion.read --name research --expires 72h
# → prints tok_1... ONCE — copy it now
```

## Quick start — agent / remote server

```
# No admin key generated on this machine
dop init --cache https://github.com/you/dop-vault.git

# Bearer arrives out-of-band (SSH, systemd credential, etc.)
export DOP_TOKEN=tok_1...

# Run scoped commands
dop exec --agent-name my-job -- ./run.sh
dop whoami           # shows subject + generation + expiry
dop env              # shell-eval-able exports
```

## Commands

Admin session:
```
dop admin init          generate wrapped admin keys (once per machine)
dop admin login         start session
dop admin logout        end session
dop admin status        show state + TTL
```

Attach vault:
```
dop init --vault <path-or-url>    admin install
dop init --cache <path-or-url>    agent install (no admin keys)
```

Vault contents (admin session required):
```
dop integration add --name N --token N=V:SCOPE [--base-url URL] [--token …]
dop integration list
dop integration remove --name N [--force]     # --force cascades to grants

dop grant add --id ID --integration N --token T [--env-prefix P]
dop grant list
dop grant remove --id ID

dop token issue --grants CSV --name L [--expires 72h]
dop token list
dop token revoke <name>

dop team add-key --name W --pubkey <age> [--ed25519 P] [--note T]
dop team list
dop team remove --name W [--force]             # rotation checklist

dop vault edit                                  # open decrypted vault in $EDITOR
```

Execution (bearer required):
```
dop exec [--token-file PATH] --agent-name X -- CMD
dop whoami
dop env
```

Common:
```
dop pull / dop push       git pull/push the vault
dop doctor [--security]   health check
```

Or launch the TUI (`dop` alone on a TTY, unless `DOP_NO_TUI=1`).

Env vars:

- `DOP_TOKEN`, `DOP_TOKEN_FILE` — bearer for agent commands
- `DOP_VAULT` — override vault path
- `DOP_NO_TUI` — force headless mode
- `DOP_ADMIN_TTL` — session idle timeout (default 15m)
- `DOP_ADMIN_MAX_TTL` — session absolute timeout (default 60m)
