# dop — Doors of Perception

Local-first, git-synced, per-agent-scoped credential gateway CLI.

Design docs: `../../_rules/_projects/DOP/`
- `PROJECT_BRIEF.md` — vision + model
- `ARCHITECTURE.md` — data shapes + threat model
- `BUILD_PLAN.md` — phased roadmap

## Status

**P0–P5 shipped.** Encrypted vault, git-synced with a real SOPS-aware three-way merge driver, `dop token issue/list/revoke` with a confirmation gate for sensitive grants, signed-challenge auth for crypto agents (`--sign-with`), JSONL audit log with `dop log tail/grep`, and a Claude Code skill + docs recipes.

## Testing

One command runs everything:

```zsh
./scripts/test.sh              # unit + e2e (skips the recursive p10)
./scripts/test.sh --unit-only  # Go unit tests (~1s, no external deps)
./scripts/test.sh --e2e-only   # shell e2e (needs sops, git, age-keygen, gh, goreleaser, python3)
WITH_P10=1 ./scripts/test.sh   # include p10_first_run (~doubles runtime — it re-runs everything else)
```

**Unit tests** live next to the code they test (Go convention): every
`internal/*/` package with logic has a `*_test.go` sibling.

**End-to-end tests** live in `testdata/e2e/`, one shell script per phase:
`p1b_merge.sh` (merge driver), `p2_token_issue.sh` (token CLI),
`p3_signed_auth.sh`, `p4_audit_log.sh`, `p5_skill_recipe.sh`,
`p6_team_ops.sh`, `p7_distribution.sh`, `p8_doctor.sh`,
`p9_tui_gates.sh`, `p10_first_run.sh`.

Each e2e script spins up a fresh temp `$HOME`, `dop init`s from
scratch, and cleans up after itself. Safe to run repeatedly.

## Runtime dependencies

- `git` on `$PATH`
- `sops` (>= 3.7) on `$PATH` — install via `brew install sops` or [GitHub releases](https://github.com/getsops/sops/releases)

(SOPS is shelled out to instead of linked in — keeps the binary ~3MB stripped instead of ~40MB, and lets you `sops vault.yaml` to edit encrypted vaults with your normal tooling.)

## Build

```
cd apps/dop
go build -o dop ./cmd/dop
./dop help
```

## Quick start (encrypted vault, local bare repo)

```
cd apps/dop
go build -o dop ./cmd/dop

# 1. Generate your age key (once per machine)
./dop init

# 2. Attach a vault repo (option 3: local bare — no remote needed)
./dop init --vault /tmp/my-dop-vault-repo

# 3. Seed your first vault. The clone lives at ~/.config/dop/vault/
#    (or ~/Library/Application Support/dop/vault/ on macOS)
VAULT_DIR="$(./dop env-config vault-dir 2>/dev/null || echo ~/.config/dop/vault)"
cp ./testdata/vault.example.yaml "$VAULT_DIR/vault.plain.yaml"

# 4. Encrypt it with your age key
./dop encrypt "$VAULT_DIR/vault.plain.yaml" "$VAULT_DIR/vault.yaml"

# 5. Use it — resolves scoped env vars from the encrypted vault
export DOP_TOKEN=tok_p0_readonly
./dop whoami       # shows grants for your token
./dop env          # prints shell-eval-able exports
./dop exec --agent-name "demo" -- env | grep -E '^(BOILER|NOTION)_'
```

## Plaintext quick start (no encryption, no git — for tests only)

```
export DOP_VAULT=./testdata/vault.example.yaml
export DOP_TOKEN=tok_p0_readonly

./dop whoami
./dop env
./dop exec --agent-name "demo" -- env | grep -E '^(BOILER|NOTION)_'
```

## Commands

```
dop init                            first-run: generate age key
dop init --vault <path-or-url>      attach vault repo (bootstraps if path missing)
dop encrypt <plain.yaml> <enc.yaml> encrypt a plaintext vault with your age key
dop exec [--clean-env] -- CMD ...   run CMD with scoped env from DOP_TOKEN
dop whoami                          show what DOP_TOKEN resolves to
dop env                             print `export KEY=VAL` lines (for `eval "$(dop env)"`)
```

## Recipes

See [`docs/RECIPES.md`](docs/RECIPES.md) for shell/cron, Claude Code, and Buzz cryptographic-agent patterns.

## Layout

```
apps/dop/
├── cmd/dop/main.go              CLI entry, subcommand dispatch
├── internal/
│   ├── config/                  ~/.config/dop path resolution (XDG-aware)
│   ├── agekeys/                 age keypair generation + load
│   ├── initcmd/                 dop init logic
│   ├── vaultgit/                dop init --vault: bootstrap + clone + install driver
│   ├── vault/                   YAML loader (auto-decrypt SOPS via shell-out)
│   ├── resolve/                 bearer token → grants → env vars
│   └── execchild/               syscall.Exec wrapper (--clean-env)
└── testdata/vault.example.yaml  fixture vault (plaintext, for tests)
```
