# dop — Doors of Perception

Local-first, git-synced, per-agent-scoped credential gateway CLI.

Design docs: `../../_rules/_projects/DOP/`
- `PROJECT_BRIEF.md` — vision + model
- `ARCHITECTURE.md` — data shapes + threat model
- `BUILD_PLAN.md` — phased roadmap

## Status

**P0 walking skeleton.** Plaintext vault, bearer-token resolve, `syscall.Exec` child. No SOPS, no audit log, no signed challenges yet — see `BUILD_PLAN.md`.

## Build

```
cd apps/dop
go build -o dop ./cmd/dop
./dop help
```

## Try the walking skeleton

```
cd apps/dop
go build -o dop ./cmd/dop

export DOP_VAULT=./testdata/vault.example.yaml
export DOP_TOKEN=tok_p0_readonly

./dop whoami
# → token: tok_p0_reado… (name: tok_p0_readonly)
#   grants:
#     - boiler.read
#     - notion.read

./dop env
# → export BOILER_ADMIN_EMAIL='cam@example.co'
#   export BOILER_BASE_URL='https://boiler.example.internal'
#   export BOILER_TOKEN='blr_ro_FIXTURE_TOKEN_READ'
#   export NOTION_BASE_URL='https://api.notion.com/v1'
#   export NOTION_TOKEN='ntn_ro_FIXTURE_TOKEN'

./dop exec --agent-name "demo-agent" -- env | grep -E '^(BOILER|NOTION)_'
# → same vars, but injected into the child process env

# Swap to the writer token — different scope, different env
export DOP_TOKEN=tok_p0_writer
./dop whoami
# → grants:
#     - boiler.write
#     - notion.read
```

## Layout

```
apps/dop/
├── cmd/dop/main.go              CLI entry, subcommand dispatch
├── internal/
│   ├── vault/                   YAML loader + types (P0: plaintext)
│   ├── resolve/                 bearer token → grants → env vars
│   └── execchild/               syscall.Exec wrapper
└── testdata/vault.example.yaml  fixture vault for local dev
```
