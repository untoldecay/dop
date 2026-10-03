# Teams

One vault, multiple admins, one git remote. Every admin can add integrations, issue scopes, and revoke them. Agents don't care who owns which credential; they only care that *some* admin granted them a scope.

The mental model: Alice and Bob are both admins on the same vault. Alice owns the Notion token. Bob owns the GitHub token. Bob's deploy-agent needs read access to Alice's Notion. Alice grants it. Later she revokes it. Neither of them ever sees the other's raw token.

## Alice invites Bob

Alice already has the vault running. Bob installs `dop` on his laptop and runs:

```bash
# Bob — generates his own admin key, prints his pubkeys
dop admin init
```

Bob sends Alice his `age1...` recipient and his ed25519 hex pubkey (Slack, email, whatever — they're public).

```bash
# Alice — register Bob, push so the remote carries his recipient
dop team add-key --name bob --pubkey age1qr... --ed25519 7f3a... --note "bob's laptop"
dop push
```

The vault is now re-encrypted to both age recipients. Bob clones it:

```bash
# Bob — attach to the same remote
dop init --vault git@github.com:acme/dop-vault.git
dop admin login
```

Bob's `init` sees that `admins.trust` already exists on the remote and leaves it alone — Alice's entry is preserved. He runs `dop team list` and sees both of them.

## Bob adds an integration, Alice grants a scope

Bob adds GitHub to the vault:

```bash
# Bob
dop integration add github --token ghp_...
dop push
```

Alice pulls and sees it:

```bash
# Alice
dop pull
dop integration list
# notion   (owner: alice)
# github   (owner: bob)
```

Bob now wants his `deploy-agent` to read Alice's Notion. Alice does the grant — this is the cross-admin case and it works exactly like a same-admin grant, because the vault doesn't care who owns the integration, only who's signing the capability:

```bash
# Alice — grant Bob's agent a scope on *her* Notion credential
dop grant --agent deploy-agent --integration notion --scope notion.read
dop push
```

The `.record` is signed by Alice's ed25519. Bob's `deploy-agent` (which Bob paired earlier via the usual QR flow) pulls on its next tick, finds the record, and from then on `dop exec --agent-name deploy-agent -- <cmd>` injects a scoped Notion token for one child process. Bob never handles Alice's raw token.

## Revocation

Alice changes her mind:

```bash
# Alice
dop revoke --agent deploy-agent --integration notion
dop push
```

The `.bundle` and `.record` for that capability are deleted from the vault; the audit log gets a `revoke` event. On Bob's next `dop pull`, his agent's next `exec` against `notion.read` fails closed — the record is gone, there's nothing to verify against. The raw Notion token in the vault is untouched; only the slice issued to Bob's agent is severed.

## Concurrent admins and git conflicts

Alice and Bob both grant scopes at the same time. One of them pushes first; the other's push is rejected. `dop pull` runs `git pull --ff-only` and refuses to auto-merge `vault.yaml` — there's no merge driver, by design.

The loser does:

```bash
dop pull                    # fails: non-fast-forward
git -C ~/Library/Application\ Support/dop/vault reset --hard origin/main
# restart the admin session, re-issue the grant, push again
```

**One push wins, the other does `dop pull` + retry. No data loss, no silent merge.** The capability files are content-addressed by lookup ID, so two admins issuing to different agents never collide on the same path; the only real contention is `vault.yaml` itself, and `--ff-only` surfaces it loudly.

Rule of thumb: push after every issue, claim, or revoke. The window for conflict is however long you sit on local changes.

## Removing an admin

Bob is leaving the team. Alice runs:

```bash
# Alice
dop team remove --name bob --force
dop push
```

`--force` is required to pull the trigger on `remove`. On success:

- Every capability Bob signed is revoked (bundles + records deleted, `revoke` audit events emitted with `reason=admin_removed`).
- The vault is re-encrypted without Bob's age recipient — his future `dop pull` still works (git doesn't care), but he can no longer decrypt `vault.yaml`.
- Alice gets a printed checklist of every upstream token Bob could have seen. **Rotate those at the provider.** DOP revokes scopes; it can't invalidate a PAT that Bob copy-pasted into his notes six months ago.

Guardrails: `dop team remove` refuses to remove the last admin, and refuses self-removal, even under `--force`.

## If Alice loses her laptop

Her admin key lives in `~/Library/Application Support/dop/keys/admin.age.enc` — encrypted at rest by the password she set at `dop admin init`. Without the password, the file is useless. If she had a second device paired (the usual flow — see onboarding), she uses that to `dop team remove --name alice-oldlaptop --force` from the surviving admin, then adds a fresh key for her new machine. If she was the only admin and the laptop is gone, the vault is unrecoverable by design. For the "what if the second admin goes rogue" question, see the threat model.

## What's next

- [Onboarding](01-onboarding.md) — first-machine pairing walkthrough for a new teammate joining the vault
- [CI and headless runners](06-ci-headless.md) — how `dop exec` injects scoped env on a GitHub Actions / Dagger / Nomad runner
- [Threat model](05-threat-model.md) — what a compromised admin can and can't do
