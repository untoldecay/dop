# CI and headless runners

A GitHub Actions job can't scan a QR code. Neither can a Dagger pipeline or a Nomad allocation. The whole "admin phone approves a pending claim" ceremony assumes a human somewhere — and in CI there isn't one.

DOP has two answers. Pre-bind the bearer to an agent key at issue time, so there's no PIN dance to run. Or skip binding entirely and treat the bearer like a classic PAT. Pick based on how much you trust the runner.

## Pattern 1: pre-bound bearer

Default binding is `pin` — the bearer is useless until an agent runs `dop claim <PIN>`. For CI you prepare that pairing once on a trusted machine (your laptop, a jump host) and then ship the resulting key material to the runner. The runner never scans a QR because the pairing already happened.

```bash
# On the trusted machine. Admin issues:
dop token issue --grants notion.read \
                --name gha-notion-sync \
                --expires 30d
# → prints bearer (tok_1<hex>) and PIN

# Agent runs the claim on the SAME trusted machine (admin approves on phone):
DOP_TOKEN=tok_1... dop claim XX-XX-XX
# → materialises ~/.config/dop/agent-keys/<lookup_id>.key, 0600, raw 64 bytes

# Capture both pieces for CI:
base64 < ~/.config/dop/agent-keys/<lookup_id>.key   # → DOP_AGENT_KEY_B64
echo "tok_1..."                                      # → DOP_TOKEN
```

The runner then reconstructs the key file at the matching path on every job, pulls the vault, and runs `dop exec`. The bearer in `secrets.DOP_TOKEN` is useless without the matching key file next to it.

In GitHub Actions:

```yaml
name: notion-sync
on: { schedule: [{ cron: "0 */6 * * *" }] }

jobs:
  sync:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install dop
        run: |
          curl -fsSL https://raw.githubusercontent.com/untoldecay/dop/main/scripts/install.sh | bash
          echo "$HOME/.local/bin" >> $GITHUB_PATH

      - name: Materialize agent key
        env:
          AGENT_KEY_B64: ${{ secrets.DOP_AGENT_KEY_B64 }}
          LOOKUP_ID:     ${{ vars.DOP_LOOKUP_ID }}
        run: |
          mkdir -p ~/.config/dop/agent-keys
          chmod 700 ~/.config/dop/agent-keys
          echo "$AGENT_KEY_B64" | base64 -d > ~/.config/dop/agent-keys/$LOOKUP_ID.key
          chmod 600 ~/.config/dop/agent-keys/$LOOKUP_ID.key

      - name: Clone vault
        run: git clone "${{ secrets.DOP_VAULT_URL }}" ~/.config/dop/vault

      - name: Run the sync
        env:
          DOP_TOKEN: ${{ secrets.DOP_TOKEN }}
        run: dop exec --agent-name gha-notion-sync -- python sync.py
```

The runner proves possession of the private key on every `dop exec`; the bearer in `secrets.DOP_TOKEN` is useless without that file.

## Pattern 2: unbound bearer

If the runner is ephemeral and can't persist a key file — or you just don't want the moving parts — `--no-bind` issues a bearer that works alone:

```bash
dop token issue --grants notion.read \
                --name gha-notion-sync \
                --no-bind \
                --expires 7d
```

No PIN, no agent key, no claim. The bearer in `$DOP_TOKEN` is sufficient. This is a PAT with DOP's audit log and scope wrapping on top — anyone who exfiltrates the secret can use it from anywhere until you revoke. Fine for self-hosted hardened runners with narrow scopes and short expiry; prefer Pattern 1 for anything persistent or privileged.

## Pattern 3: remote claim

A long-lived runner that can hold the vault repo (with push) but has no admin claims by itself: pick **Server** in the TUI's first menu or run `dop init --cache <remote>`, then `dop claim --remote <PIN>` stages the claim in the repo and the admin approves from the TUI or `dop approve-remote`. Same key-type rules as a local claim (`--key-type p256` + `DOP_ALLOW_FILE_KEYS=1` on Linux), and approval seals the env for P-256 keys so direct availability works from the first pull. Walkthrough in [01-onboarding.md › Remote server](01-onboarding.md#remote-server).

## Where the bearer lives

DOP reads the bearer from `$DOP_TOKEN`, then `--token-file <path>`, then `$DOP_TOKEN_FILE`. Where you store it on the way in — GitHub Actions secrets, Vault, Doppler, Nomad variables, Dagger secret mounts — is up to you. The bearer is 36 printable bytes (`tok_1` + 32 hex); any secret store that round-trips strings handles it. Use `--token-file` when your secret manager writes a tmpfs mount; use `$DOP_TOKEN` for env-based delivery.

## Rotation

For bound bearers, three steps and no human on the agent side:

```bash
dop token revoke gha-notion-sync
dop token issue --grants notion.read --name gha-notion-sync \
                --bind-pubkey "$PUBKEY_HEX" --expires 30d
# update the DOP_TOKEN secret in CI
```

Audit log threads revoke → new issue by subject name. Upstream credential rotation (new Notion token in the vault) propagates automatically on the next `dop pull` — no bearer rotation needed.

For P-256-bound bearers (`--key-type p256`), `dop token add-grant` / `remove-grant` / `rotate` propagate in place — the agent picks up changes on its next `dop exec` without a reissue. See [docs/04-secure-elements.md](04-secure-elements.md). Ed25519-bound bearers still need revoke + reissue.

## Threat callback

DOP's model protects you from bearer leak alone (bound private key never leaves the agent machine) and from PIN leak alone (window is minutes). It does not protect you from a same-uid attacker on the runner — anything hostile running as the Actions user reads the key file and the bearer. Secure Enclave helps on macOS laptops; a Linux CI runner has no equivalent. Scope narrowly, expire aggressively, treat the runner as part of your trust boundary.

## What's next

- [Threat model](05-threat-model.md) — what DOP catches, what it doesn't, where same-uid risk bites.
- [CLI reference](07-cli-reference.md) — every flag on `dop token issue`, `dop exec`, `dop whoami`.
