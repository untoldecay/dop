# DOP — Doors of Perception

**1Password Teams, but every member is an AI agent and the credentials are scoped tokens.**

## In practice

Alice adds Notion and Linear to the shared vault; Bob adds GitHub. Any admin can now grant any agent — Alice's research-agent, Bob's deploy-agent — a slice of any of those credentials, and revoke it anytime. **Raw tokens stay in the vault; scopes move.**

A **scope** is a named permission on an integration — `notion.read`, `github.write`. The agent uses it by running `dop exec --agent-name X -- <command>`: DOP injects the scoped env for that one child process, nothing persists on disk, every call lands in the audit log.

## How it works

The vault is a [`sops+age`](https://github.com/getsops/sops)-encrypted file in a private git repo you own (GitHub, GitLab, Gitea — any host that accepts `git push`). Each admin pulls, mutates through the TUI, and pushes. No server, no account, no telemetry. Each AI agent generates its own `ed25519` identification key on first pairing, which an admin approves from their phone.

**The phone bit.** The TUI prints a QR encoding a `https://` link to a Cloudflare quick tunnel DOP starts on the admin's machine for ~90 seconds. Any phone camera opens it. The page is a form that asks for the **approval passphrase** — the second passphrase set during `dop admin init` (the first unlocks the vault, the second guards every claim). No app to install. Argon2id-hashed, rate-limited, scoped to the one pending claim.

From then on, the agent proves it owns the key every time it uses a credential, and the admin can grow or shrink its scopes without touching the raw tokens.

## When NOT to use DOP

DOP isn't a Vault replacement. If you need SOC2-grade audit retention, central RBAC, server-generated rotating credentials, or coverage for hundreds of agents or dozens of admins — use Vault / Doppler / Infisical / 1Password Secrets Automation. DOP sits in the gap between "paste the raw PAT in chat" and "stand up a Vault cluster for a team of five". That gap is wide.

## Install

```bash
# Deps (macOS; Linux: use your package manager for sops & cloudflared)
brew install sops cloudflared

# dop
curl -fsSL https://raw.githubusercontent.com/untoldecay/dop/main/scripts/install.sh | bash
```

Then run `dop` to launch the TUI. For every other command, see the [CLI reference](_rules/_documentation/08_CLI-Reference.md) below.

## Guides

- **[Onboarding](_rules/_documentation/01_Admin-Lifecycle.md)** — install, create vault, add tokens, add a device, add an admin
- **[Teams](_rules/_documentation/02_Vault-Attach-Sync.md)** — multi-admin, cross-grant, revocation
- **[Agents in agentic hubs](https://github.com/block/buzz)** — DOP alongside [Buzz](https://github.com/block/buzz) and similar workspaces where humans and agents share rooms *(local guide landing soon)*
- **[Secure elements](DESIGN_v1.11_agent_key_SE.md)** — hardware-backed agent identity (Secure Enclave; *still landing*)
- **[Threat model](_rules/_requirements/contracts/)** — what DOP protects and what it doesn't
- **[CI / headless](_rules/_documentation/05_Agent-Exec-and-Env.md)** — pre-bound bearers for runners
- **[CLI reference](_rules/_documentation/08_CLI-Reference.md)** — every command by section, nicer-formatted `dop --help` *(landing soon — meanwhile run `dop --help`)*
