<!--
  DRAFT — TUI-first README (bd dop-wbp, plan _rules/_plans/readme-tui-first-landing.md).
  Lives next to the GIF so it renders in preview. When approved, move to the repo
  root and rewrite paths: out/… → docs/media/out/…, ../… → docs/….
  Re-record the tour: docs/media/record.sh tour
-->

# DOP — Doors of Perception

**1Password for your AI agents.** Give each agent a scoped, revocable slice of
your team's API keys. The raw keys never leave the vault.

![DOP tour: add a service, issue a scoped bearer, hand it to an agent, grow its access, revoke it](out/tour.gif)

```bash
brew install git sops cloudflared
curl -fsSL https://raw.githubusercontent.com/untoldecay/dop/main/scripts/install.sh | bash
dop
```

`?` shows every key, `esc` goes back. That's the learning curve.

---

### Your vault, your git repo

Keys live in a `sops`+`age` encrypted file in a private repo you own. No
server, no account, no telemetry. Every change syncs with your team's copy.
[Onboarding →](../01-onboarding.md)

### Scoped, expiring bearers

An agent gets a bearer: a named set of grants (`notion.read`,
`slack.read-only`) with an expiry. Its commands see those keys and nothing
else. Add or remove grants any time; revoke takes effect on the next call.
[Recipes →](../RECIPES.md)

### Approve agents from your phone

A new agent shows a QR code. Scan it, type your approval passphrase, done.
Nothing to install on the phone. Each agent then proves its own key on every
call. [Secure elements →](../04-secure-elements.md)

### Built for small teams

Invite another admin; they join whenever they're ready and you approve them
from the Team tab. Two admins editing at once get merged, not overwritten.
[Teams →](../02-teams.md)

### Works with your harness

Claude Code skill + `/dop-use`, plus Codex, opencode, Cursor and plain
shells. [Agents & harnesses →](../03-agentic-hubs.md)

### Everything has a CLI

Every TUI action is a `dop` command too — for scripts, CI and headless boxes.
[CLI reference →](../07-cli-reference.md) · [CI / headless →](../06-ci-headless.md)

---

### When not to use DOP

Need SOC2 audit retention, central RBAC or hundreds of agents? Use Vault,
Doppler or Infisical. DOP is for the gap between "paste the token in chat" and
"run a Vault cluster for five people".

### Docs

[Features](../00-features.md) ·
[Onboarding](../01-onboarding.md) ·
[Teams](../02-teams.md) ·
[Harnesses](../03-agentic-hubs.md) ·
[Secure elements](../04-secure-elements.md) ·
[Threat model](../05-threat-model.md) ·
[CI / headless](../06-ci-headless.md) ·
[CLI reference](../07-cli-reference.md) ·
[Recipes](../RECIPES.md)

Updates: `dop update` (or More › Update) · [Releases](https://github.com/untoldecay/dop/releases)
