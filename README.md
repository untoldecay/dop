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

```
dop admin init                              generate wrapped admin keys (once)
dop admin login                             start session
dop admin logout                            end session
dop admin status                            show state + TTL

dop init --vault <path-or-url>              admin install
dop init --cache <path-or-url>              agent install (no admin keys)

dop token issue --grants CSV --name L [flags]  admin session required
dop token list                              admin session required
dop token revoke <name>                     admin session required

dop team add-key --name W --pubkey <age>    admin session required
dop team list                               admin session required

dop exec [--token-file P] --agent-name X -- CMD    bearer required
dop whoami                                  describe current bearer
dop env                                     print exports

dop pull / dop push                         git pull/push the vault
dop doctor [--security]                     health check
```

Env vars:

- `DOP_TOKEN`, `DOP_TOKEN_FILE` — bearer for agent commands
- `DOP_VAULT` — override vault path
- `DOP_NO_TUI` — force headless mode
- `DOP_ADMIN_TTL` — session idle timeout (default 15m)
- `DOP_ADMIN_MAX_TTL` — session absolute timeout (default 60m)
