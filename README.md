# DOP — Doors of Perception

**1Password Teams, but every member is an AI agent and the credentials are scoped tokens.**

Current release: **v1.16.0** ([changelog](https://github.com/untoldecay/dop/releases)).

## In practice

Alice adds Notion and Linear to the shared vault; Bob adds GitHub. Any admin can now grant any agent — Alice's research-agent, Bob's deploy-agent — a slice of any of those credentials, and revoke it anytime. **Raw tokens stay in the vault; scopes move.**

Three words cover the model. A **credential** is a raw secret stored in the vault under an integration (Notion's API key). A **grant** is a named slice of it that agents can be given — `notion.read`, `github.write`. A **bearer** is what an agent actually holds: a token minted from one or more grants, bound to that agent's key. The agent uses it by running `dop exec --agent-name X -- <command>`: DOP injects the scoped env into that one child process — the env values never land on disk, and every call is appended to the audit log.

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

Then run `dop` to launch the TUI. On any screen, `?` shows every key and `esc` goes back one level; that is the whole learning curve. For every other command, see the [CLI reference](docs/07-cli-reference.md) below.

**Keeping it updated:** after your first install, run `dop update` (checks GitHub, verifies SHA256, atomic-replaces the binary). `More › Update` in the TUI is the same thing with a confirmation screen. Switch to pre-releases with `dop update --channel dev`. Last 3 versions kept at `~/.local/share/dop/old-versions/`; roll back with `dop update --rollback`.

## Working with AI harnesses

DOP ships a Claude Code skill + `/dop-use` slash command via `dop skill install`. The install writes BOTH loose files (`~/.claude/skills/dop/SKILL.md`, `~/.claude/commands/dop-use.md`) AND a local-marketplace plugin bundle (`~/.claude-local-plugins/dop-tools/`) auto-registered via `claude plugin install` — covers plugin-only Claude Code builds like Orca.

**Your own agents.** Issue a bearer as *portable* and `dop use <subject>` hands it to any of your shells (`eval "$(dop use <subject>)"`, or `/dop-use <subject> <task>` inside Claude Code). The issue screen tells you which one applies.

**Burst-use friction.** DOP caches operator approval across repeat `dop use` calls in the same session. On first run, pick your harness in the TUI setup wizard (or `More › Settings › Harness`): Claude Code / Codex CLI / opencode have built-in adapters that read the harness's own session env var; Cursor / Zed / aider / custom shells need you to `export DOP_SESSION_ID=$(uuidgen)` in your shell profile. One approval per conversation; auto-expires after 30min idle.

## Working with teammates

`dop team invite --name alice` stages an invite (prints invite_id + PIN + full `dop admin join` incantation), exits. Teammate joins whenever within the 7-day TTL. When they've responded, approve from `List › Team › Pending` (`a` key) — or `dop team approve-invite <id>` at the CLI. Both prompt for your approval passphrase and complete the admin addition.

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
