# Onboarding

From "nothing installed" to "my first agent is paired and running a scoped command." Written for the first admin on a solo setup; multi-admin bits live in [02-teams.md](02-teams.md).

## Install

```bash
# Deps. On Linux use your package manager.
brew install sops cloudflared

# dop itself
curl -fsSL https://raw.githubusercontent.com/untoldecay/dop/main/scripts/install.sh | bash
```

## Create your admin identity

Alice runs `dop admin init`. It prompts for two passphrases and keeps them separate for a reason:

```bash
# Generates age + ed25519 keys, wraps them under the first passphrase.
# Hashes the second passphrase (argon2id) for later approval gating.
dop admin init
```

- **Admin passphrase** (≥ 8 chars) wraps `~/.dop/keys/admin.age.enc`. Lose it, lose the vault.
- **Approval passphrase** (≥ 10 chars) is what she'll type into her phone every time an agent asks to be paired. Make it different from the admin one — the approval one travels through a browser form, so a phished page shouldn't hand over vault access too.

## Attach a vault and unlock

```bash
# Start the session daemon. 15 min idle TTL, 60 min absolute.
dop admin login

# Point DOP at a private git repo you own (empty is fine).
dop init --vault git@github.com:alice/dop-vault.git

# Sanity check.
dop admin status      # → unlocked, prints pubkey + TTL remaining
```

Then `dop` on its own launches the TUI. Everything from here — adding a Notion token, issuing a bearer, inspecting audit — lives inside it.

## Pair your first agent

Say Alice wants `research-agent` to read Notion. Inside the TUI (or via CLI):

```bash
# Issues a bearer + PIN pair. Copy both to wherever the agent is.
dop token issue --grants notion.read --name research-agent
# → tok_1aB...   PIN: ZZ-NR-NY
```

On the agent's side (same machine for now — cross-host claim is on the roadmap):

```bash
# Verifies the PIN, generates the agent's own ed25519 key, then blocks.
DOP_TOKEN=tok_1aB... dop claim ZZ-NR-NY
```

The agent's terminal prints a QR, a short SAS code, and a `trycloudflare.com` URL. Alice scans the QR with her phone camera, the page asks for the approval passphrase, she taps **Approve**. The agent unblocks:

```
dop claim: bound research-agent → pubkey a1b2… (gen 1)
```

That's it. The agent can now run scoped commands:

```bash
# Injects NOTION_TOKEN into one child process, nothing persists.
DOP_TOKEN=tok_1aB... dop exec --agent-name research-agent -- \
  curl -s https://api.notion.com/v1/users/me
```

## Gotchas

- **No QR?** `cloudflared` isn't on `$PATH`. Install it, or re-run with `--no-tunnel` and approve over LAN.
- **"approval window expired"** means Alice took longer than 5 min on the phone. Reissue the PIN (`dop token repin`) and go again.
- **"too many failed passphrase attempts"** — the approval endpoint caps at 8 tries, shared with `dop approve`. Reissue the PIN; if it keeps happening, the approval passphrase isn't what you think it is.
- Running `dop admin init --force` on an existing install destroys the ability to decrypt anything signed by the old key. Don't.

## What's next

- [02-teams.md](02-teams.md) — add a second admin, share the vault, cross-grant scopes.
- [06-ci-headless.md](06-ci-headless.md) — pre-bound bearers for runners that can't scan a QR.
- [07-cli-reference.md](07-cli-reference.md) — every flag on every command.
