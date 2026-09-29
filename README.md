# DOP — Doors of Perception

**Credential handoff for AI agents that survives chat.**

DOP lets you hand a service credential to an AI agent (Claude Code, Cursor,
your own scripts, a CI runner) without the credential ever being usable if
it leaks. The bearer you paste into a chat window is deliberately worthless
by itself — using it also requires a keypair that the agent generates on
its own machine and gets approved out-of-band by you tapping a phone.

The vault lives in a private git repo you own. There is no DOP server,
no account, no telemetry. `sops+age` for the vault at rest,
`XChaCha20-Poly1305` for the delivered credentials, ed25519 for the
signed authority chain. Everything else is a couple of small files on
disk that agents read directly.

**For you if:**
- You paste tokens into agent chat windows and it makes you uncomfortable.
- You want the same credential to work on your laptop AND a CI runner without either being the weak link.
- You want an audit line for every credential use, not just every credential creation.
- You want your agents scoped tight — one narrow permission per bearer, revocable in a `dop token revoke`.

**Not for you if:** you already have Vault/Doppler/Infisical wired in
and it's working — DOP is for the case where you don't want to run
a server or trust a SaaS with your keys.

**Built for AI-agent workflows, works with anything** — Claude Code, Cursor,
Aider, plain bash, `git`, CI runners. If it reads env vars, DOP feeds it.

---

## Quick Start

Requires [Go](https://go.dev/doc/install) 1.22+, `git`, and
[`sops`](https://github.com/getsops/sops/releases) (`brew install sops`).
For phone approval you also want
[`cloudflared`](https://developers.cloudflare.com/cloudflared/) (`brew install cloudflared`).

```bash
# One-time
go install github.com/untoldecay/dop/cmd/dop@latest
go install github.com/untoldecay/dop/cmd/dop-credential-git@latest

dop admin init                                # prompts for TWO passphrases
                                              # (admin unlock + approval)
dop init --vault git@github.com:you/dop-vault.git   # a private git repo you own

# Every session
dop admin login                               # 15 min idle / 60 min absolute
```

> [!TIP]
> The vault is just a git repo. Create an empty private repo on GitHub
> (or GitLab, Gitea, Bitbucket, self-hosted — anywhere `git push` works)
> and pass its SSH or HTTPS URL. DOP does the initial commit for you.

<details>
<summary>Prefer a local-only vault first (no remote)?</summary>

```bash
dop init --vault ~/dop-vault    # local path — bootstrapped as a bare repo
```

You can attach a remote later with plain `git remote add origin …` inside
the vault dir, then `dop push`. Useful for kicking the tires without
creating anything online.
</details>

Now add a service and issue a scoped credential:

```bash
dop integration add --name notion \
  --token read=ntn_secret:read-only \
  --metadata base_url=https://api.notion.com/v1

dop grant add --id notion.read \
  --integration notion --token read --env-prefix NOTION

dop token issue --grants notion.read --name research-agent
# → prints bearer + PIN + a copy-paste line for your agent
```

> [!TIP]
> Handing that line to a chat-based agent triggers a QR code on your terminal;
> scan it, type your approval passphrase, done. The bearer alone is useless
> until you approve — leaking it into a screenshot doesn't matter.

---

## What DOP actually does

The core move is **binding a bearer to a cryptographic identity at first use**.
You issue a token, hand a bearer + PIN to your agent. The agent runs
`dop claim <PIN>` — that generates an ed25519 keypair on its machine,
persists the private key locally, and writes the pubkey into the vault
against your bearer. From then on, `dop exec` proves possession of that
key before decrypting any credential.

You approve the claim on your phone via a Cloudflare Quick Tunnel that
DOP launches locally — the URL alone is worthless, only the passphrase
unlocks it (argon2id-hashed, rate-limited).

Your daily flow, once set up:

| What you do | What runs |
|---|---|
| Give an agent access to a service | `dop token issue --grants X --name agent` |
| Chat handoff (bearer + PIN) | agent runs `dop claim <PIN>` → you approve on phone |
| Agent calls the service | `dop exec --agent-name X -- <cmd>` (env injected, git hardened) |
| See what's happening live | `dop watch` (color-coded tail of the audit log) |
| Health check | `dop doctor --security` |
| Kill a leaked bearer | `dop token revoke <name>` |
| Add a teammate | `dop team add-key --name B --pubkey age1... --ed25519 <hex>` |

<details>
<summary>What if I don't want the phone-approval dance every time?</summary>

Three escape hatches, from strictest to loosest:

- **Pre-bind at issue** — if the agent's pubkey is known ahead of time
  (typical for a CI runner or a specific server), pass
  `--bind-pubkey <hex>` at issue. No PIN, no claim ceremony — the bundle
  is already bound to that pubkey.
- **Remote claim via git** — for hosts without an admin daemon, the agent
  stages a claim in the vault repo and you approve later with
  `dop approve-remote --subject S`. Same passphrase gate.
- **Unbound** — pass `--no-bind` at issue and the bearer works by itself.
  Legacy behavior; use for short-lived scripts and CI where the ceremony
  is theater.
</details>

<details>
<summary>Wire it into git so <code>git push</code> just works</summary>

```bash
git config --global credential.helper 'dop-credential-git'
dop credential-helper map --host github.com --grant github.readonly --username oauth
```

Any `git push` / `git clone` from now on gets a fresh token from DOP;
the underlying credential never enters `~/.gitconfig` or your shell env.
Same pattern for docker / npm / pip once those shims land.
</details>

---

## Does it hold up?

Yes, with honest caveats. Three passes of independent architecture review
converged on "we're at the plateau on hardening" — signature verification,
rate limits, TOCTOU reorder, atomic counters, sidecar propagation all
landed. 18 e2e scripts cover every command path.

The parts that are deliberately **not** protected:
- **Same-uid attacker on your machine.** DOP's boundary is the OS user.
  If something runs as you and can read the agent private key file (mode 0600),
  it can spend the bearer. That's the same threat model as an SSH key.
- **Truncated audit log.** Same-uid attacker can `> audit.jsonl`. Merkle-chain
  detection is on the roadmap.
- **Concurrent multi-admin issue.** Two admins issuing tokens at the same
  time races the git push; no semantic merge driver ships yet.
- **Long-lived bearer in a screenshot** — if it's PIN-bound and unclaimed,
  it's fine (PIN expires in 5 min). If it's `--no-bind`, treat it like a
  password.

See [`_rules/_requirements/contracts/`](./_rules/_requirements/contracts/)
for the 12 feature contracts with acceptance criteria + regression checks
per feature.

---

## Docs

**Start here**
- [Admin Lifecycle](_rules/_documentation/01_Admin-Lifecycle.md) — init, login, set-approval, session TTL.
- [Vault Attach & Sync](_rules/_documentation/02_Vault-Attach-Sync.md) — attach a vault repo, pull/push, gitignore.
- [Token Lifecycle](_rules/_documentation/03_Token-Lifecycle.md) — issue, revoke, repin, grants + integrations.
- [PIN Claim & Approval](_rules/_documentation/04_PIN-Claim-and-Approval.md) — the chat-handoff flow end-to-end.

**Concepts**
- [Two-Plane Authority](_rules/_requirements/contracts/01_two_plane_authority.md) — administrative vs execution separation.
- [Capability Envelope](_rules/_requirements/contracts/04_capability_envelope.md) — how bundles are encrypted.
- [Signed Record + Trust Anchor](_rules/_requirements/contracts/05_signed_record_and_trust.md) — how agents verify authority without vault access.
- [Approval Gate](_rules/_requirements/contracts/07_approval_gate.md) — passphrase + rate limit + argon2id.
- [Web Approval Flow](_rules/_requirements/contracts/08_web_approval_flow.md) — tunnel, QR, form, threat notes.

**Operate**
- [Agent Exec & Env](_rules/_documentation/05_Agent-Exec-and-Env.md) — `dop exec`, env-hardening for git.
- [Audit & Notifications](_rules/_documentation/06_Audit-and-Notifications.md) — `dop watch`, macOS banners, filter/rotate.
- [TUI Reference](_rules/_documentation/07_TUI-Reference.md) — the interactive front-end.
- [All feature contracts](_rules/_requirements/contracts/) — 12 files, one per feature, MUST/MUST NOT rules with acceptance criteria.

**Design provenance** (older, superseded where the code disagrees)
- [`../../_rules/_projects/DOP/`](../../_rules/_projects/DOP/) — PROJECT_BRIEF, ARCHITECTURE, BUILD_PLAN, TUI_GUIDELINES.

---

## Build / test

```bash
cd apps/dop
go build -o dop ./cmd/dop
go build -o dop-credential-git ./cmd/dop-credential-git

./scripts/test.sh              # unit + e2e (~15s)
./scripts/test.sh --unit-only  # unit only (~1s)
```

18 e2e scripts under `testdata/e2e/v1_*.sh`. Every contract in
`_rules/_requirements/contracts/` names its own regression suite.

## Env vars

- `DOP_TOKEN`, `DOP_TOKEN_FILE` — bearer for agent commands
- `DOP_VAULT` — override vault path
- `DOP_NO_TUI` — force headless mode
- `DOP_NO_NOTIFY` — suppress macOS notifications (used by tests + CI)
- `DOP_ADMIN_TTL` — session idle timeout (default 15m)
- `DOP_ADMIN_MAX_TTL` — session absolute timeout (default 60m)
