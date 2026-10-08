# Agents in agentic hubs

Does DOP compose with a shared-room workspace like [Buzz](https://github.com/block/buzz) — where humans and agents post signed events into one relay you own — and if so, how? Yes, by composition. The integration is a pattern you wire up, not a shipped feature today.

## The split

Two concerns, two tools:

- **The hub** (Buzz, or anything shaped like it) owns the room, the shared log, and the identities of who's in it. Every message — human or agent — is a signed event in a relay you host.
- **DOP** owns the credentials. Notion, GitHub, Linear tokens live in the sops+age vault; agents hold scopes, not raw tokens; `dop exec` injects env into one child process.

Agents live in the hub. When they need to touch an outside API, they reach for DOP.

## Why keep them separate

- **Credentials never land in the shared log.** The hub's whole point is that everyone sees everyone's events. A Notion PAT in that log is a Notion PAT every room member has forever. `dop exec` keeps the raw token in the vault and the scope in the agent's one child process — nothing to post, nothing to replay.
- **Claim once, then no more approvals.** Pairing an agent needs your approval once (QR or popup) — that's you confirming "this is the agent I just gave the claim command to". After that the agent's key on its machine *is* its identity: `dop exec` never asks again, even after the agent restarts or the hub spawns a fresh shell per tool call. An approval request you didn't expect means someone else is claiming — refuse it.
- **Agents use `dop exec`, never `dop env`.** Anything an agent prints goes to its AI provider and stays in the hub's / harness's history. `dop env` is refused for a claimed agent; `dop exec` masks keys in the output and the agent writes `$NOTION_TOKEN` in its command so the shell — not the model — expands it. `dop use` is only for portable bearers (yours, recalled in any shell).
- **Audit stays per-use.** Every `dop exec` is a line in DOP's audit log tied to the agent's `ed25519` key. The hub logs what was said in the room; DOP logs what was done with a credential. Reading them side-by-side is the honest picture.
- **Admin surfaces don't bleed.** Who's allowed in the room is the hub admin's call. Who's allowed to use `github.write` is the DOP admin's call. Same person often, but the decisions are different and the blast radius of a mistake is smaller when the levers are separate.

## A concrete scene

Alice runs a Buzz relay on her laptop. Her `research-agent` is a room member alongside her and Bob. In the room, Bob asks the agent to pull the Q3 roadmap from Notion.

The agent (already paired with DOP via `dop claim`) runs:

```bash
DOP_TOKEN=tok_1aB... dop exec --agent-name research-agent -- \
  curl -s https://api.notion.com/v1/pages/<id>
```

DOP injects `NOTION_TOKEN` into that one `curl` process and nothing else. The agent posts the fetched page content back into the Buzz room as a signed event. The Notion token never touches the relay. Alice's DOP audit log shows one `notion.read` call by `research-agent` at that timestamp; Bob's hub log shows the request and the reply.

If Alice later revokes `notion.read` from `research-agent` in the DOP TUI, the next `dop exec` fails. The hub doesn't need to know.

## What's not here yet

- **No built-in Buzz connector.** DOP doesn't read or write Buzz events. The composition is: agent process runs in the hub's context, calls `dop exec` locally, publishes results back through the hub's own client.
- **No shared identity.** The agent's DOP pubkey and its Nostr pubkey are different keys today. Binding them (so hub membership gates DOP scope use, or vice versa) is a design question we haven't answered.
- **Cross-host claim is still roadmap.** If the agent runs on a different machine than the admin, see [06-ci-headless.md](06-ci-headless.md) for the pre-bound bearer pattern that works today.

## Further reading

- [Buzz](https://github.com/block/buzz) — the workspace this page is written against.
- [CI and headless runners](06-ci-headless.md) — how `dop exec` actually injects env and what it logs.
- [Threat model](05-threat-model.md) — what DOP protects and what it leaves to the hub.
