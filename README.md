# DOP — Doors of Perception

**1Password Teams, but every member is an AI agent and the credentials are scoped tokens.**

## In practice

Alice adds Notion and Linear to the shared vault; Bob adds GitHub. Any admin can now grant any agent — Alice's research-agent, Bob's deploy-agent — a slice of any of those credentials, and revoke it anytime. **Raw tokens stay in the vault; scopes move.**

A **scope** is a named permission on an integration — `notion.read`, `github.write` (DOP calls these *grants* in the CLI). The agent uses it by running `dop exec --agent-name X -- <command>`: DOP injects the scoped env into that one child process — the env values never land on disk, and every call is appended to the audit log.

## How it works

The vault is a [`sops+age`](https://github.com/getsops/sops)-encrypted file in a private git repo you own (GitHub, GitLab, Gitea — any host that accepts `git push`). Each admin pulls, mutates through the TUI, and pushes. No server, no account, no telemetry. Each AI agent generates its own P-256 identification key on first pairing — Secure Enclave-backed on signed macOS builds, file-backed as a loud-fallback on unsigned builds and Linux — and an admin approves it from their phone.

**The phone bit.** The TUI prints a QR encoding a `https://` link to a Cloudflare quick tunnel DOP starts on the admin's machine for the ~5-minute approval window. Any phone camera opens it. The page is a form that asks for the **approval passphrase** — the second passphrase set during `dop admin init` (the first unlocks the vault, the second guards every claim). No app to install. Argon2id-hashed, rate-limited, scoped to the one pending claim.

From then on, the agent proves it owns the key every time it uses a credential, and the admin can grow or shrink its scopes without touching the raw tokens.

## When NOT to use DOP

DOP isn't a Vault replacement. If you need SOC2-grade audit retention, central RBAC, server-generated rotating credentials, or coverage for hundreds of agents or dozens of admins — use Vault / Doppler / Infisical / 1Password Secrets Automation. DOP sits in the gap between "paste the raw PAT in chat" and "stand up a Vault cluster for a team of five". That gap is wide.

## Install

```bash
# Deps (macOS; Linux: use your package manager for sops, cloudflared, git)
brew install git sops cloudflared

# dop
curl -fsSL https://raw.githubusercontent.com/untoldecay/dop/main/scripts/install.sh | bash
```

Then run `dop` to launch the TUI. For every other command, see the [CLI reference](docs/07-cli-reference.md) below.

## Guides

- **[Feature sheet](docs/00-features.md)** — every DOP feature, grouped by surface
- **[Onboarding](docs/01-onboarding.md)** — install, create vault, add tokens, pair your first agent
- **[Teams](docs/02-teams.md)** — multi-admin, cross-grant, revocation, concurrent-admin merges, laptop-loss recovery
- **[Agents in agentic hubs](docs/03-agentic-hubs.md)** — DOP alongside [Buzz](https://github.com/block/buzz) and similar workspaces where humans and agents share rooms
- **[Secure elements](docs/04-secure-elements.md)** — hardware-backed agent identity (ed25519, P-256, Secure Enclave)
- **[Threat model](docs/05-threat-model.md)** — what DOP protects and what it doesn't
- **[CI / headless](docs/06-ci-headless.md)** — pre-bound bearers for runners
- **[CLI reference](docs/07-cli-reference.md)** — every command by section, nicer-formatted `dop --help`
- **[Recipes](docs/RECIPES.md)** — copy-pasteable patterns for shell, cron, Claude Code, Buzz
