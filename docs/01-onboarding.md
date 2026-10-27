# Onboarding

From "nothing installed" to "my first agent is paired and running a scoped command." Written for the first admin on a solo setup; multi-admin bits live in [02-teams.md](02-teams.md).

## Install

```bash
# Deps. On Linux use your package manager.
brew install cloudflared

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
- **Approval passphrase** (≥ 10 chars) is what she types every time an agent asks for something: into the DOP dialog on her Mac, or into the phone page when the agent is elsewhere. Make it different from the admin one — the approval one can travel through a browser form, so a phished page shouldn't hand over vault access too.

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

On the agent's side (same machine as the admin; for a server or CI box without an admin, see [Remote server](#remote-server) below):

```bash
# Verifies the PIN, generates the agent's own key (Secure Enclave P-256 on macOS), then blocks.
DOP_TOKEN=tok_1aB... dop claim ZZ-NR-NY
```

A DOP dialog appears on Alice's Mac: what the agent gets, which key asks, the short code to compare with the agent's terminal, how long she has. She types the approval passphrase, clicks **Approve**, the agent unblocks. If nobody answers the dialog (or there is no GUI), the agent's terminal prints a QR, the same code, and a `trycloudflare.com` URL: Alice scans it with her phone, the page is the same card, she approves there. `dop approve <code>` from any terminal on the Mac works too.

```
dop claim: bound research-agent → pubkey a1b2… (gen 1)
```

That's it. The agent can now run scoped commands:

```bash
# Injects NOTION_TOKEN into one child process, nothing persists.
DOP_TOKEN=tok_1aB... dop exec --agent-name research-agent -- \
  curl -s https://api.notion.com/v1/users/me
```

## Remote server

An agent on a host with no admin and no daemon — a VPS, a CI box, a Mac mini in a closet — claims through the vault repo instead of the approval page. Both sides need pull **and push** on the vault remote.

On the server, run `dop` and pick **Server** from the first menu (not **New setup**, which would create an admin key there). It asks for the vault URL and clones it as a cache. Same thing from the CLI:

```bash
dop init --cache git@github.com:you/vault.git     # deploy key with write access
# Verifies the PIN, generates the agent key, stages the claim in
# pending-remote-claims/ and pushes. P-256 is picked when the host can
# do it (SE on macOS; DOP_ALLOW_FILE_KEYS=1 for a file key on Linux).
DOP_TOKEN=tok_1aB... DOP_ALLOW_FILE_KEYS=1 dop claim --remote --key-type p256 ZZ-NR-NY
```

When issuing from the TUI, answer **a server** at the *Runs on* step and the handoff you paste to the agent already carries `--remote` and the P-256 flags. Once the agent runs it, Alice's TUI banner shows `1 claim pending, press a to review`; the row reads `remote · <hostname>`. She approves with the approval passphrase, or from the CLI:

```bash
dop approve-remote --list
dop approve-remote --subject research-agent     # or --reject
```

Approval records the agent's key type and, for P-256, seals the env to the agent's key right away. Back on the server, `dop pull` (or just the next `dop exec`, which auto-pulls) and the agent is live — including bearer-free exec and later `add-grant` / `remove-grant` / `rotate` without a re-claim.

A rejected or revoked remote claim leaves an orphan key on the server; `dop agent sweep` there removes it. On a server the `--remote` flag is implied: a plain `dop claim <PIN>` stages the claim too.

**Portable bearers on a server.** When the agent needs one of Alice's portable bearers it runs `dop use <subject>`; on a server that asks for a **lease** instead of printing the bearer. Alice's Mac shows the dialog with three buttons — Deny, a duration that cycles 10 min → 30 min → 1 hour, Approve — or the row sits under Bearers › Pending in the TUI. The server receives a fresh bearer with the same grants that dies at the end of the lease, reuses it for every shell call until then, and asks again after. The longest lease Alice can grant is set when she makes the bearer portable (`--lease-cap`, 1 hour by default).

## Gotchas

- **No dialog?** `dop admin status` shows `approval dialogs: on` or the reason it is off; `dop watch --filter approval_dialog` records every attempt. The QR path still works meanwhile.
- **No QR?** `cloudflared` isn't on `$PATH`. Install it, or re-run with `--no-tunnel` and approve over LAN.
- **"approval window expired"** means Alice took longer than 5 min. Reissue the PIN (`dop token repin`) and go again.
- **"too many failed passphrase attempts"** — the approval endpoint caps at 8 tries, shared with `dop approve`. Reissue the PIN; if it keeps happening, the approval passphrase isn't what you think it is.
- Running `dop admin init --force` on an existing install destroys the ability to decrypt anything signed by the old key. Don't.

## What's next

- [02-teams.md](02-teams.md) — add a second admin, share the vault, cross-grant scopes.
- [06-ci-headless.md](06-ci-headless.md) — pre-bound and unbound bearers for runners that can't scan a QR.
- [07-cli-reference.md](07-cli-reference.md) — every flag on every command.
