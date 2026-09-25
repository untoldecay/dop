# DOP Recipes

Small, copy-pasteable patterns for the three canonical harnesses.

## Shell / cron

The simplest form. Set `DOP_TOKEN` once in your shell (or in your crontab
env), then wrap any script with `dop exec`.

```bash
# ~/.zshrc — persists across shells on this machine
export DOP_TOKEN="$(security find-generic-password -s dop-token -a "$USER" -w)"
# (or `export DOP_TOKEN=tok_...` in plaintext if you're OK with .zshrc-level trust)

# Now any script inherits scoped upstream tokens via dop exec:
dop exec --agent-name daily-boiler-report -- ./scripts/boiler-nightly.sh
```

Cron equivalent (crontab -e):

```cron
# Load token from Keychain, then run the report at 03:00
0 3 * * *  DOP_TOKEN="$(security find-generic-password -s dop-token -a $USER -w)" \
           /usr/local/bin/dop exec --agent-name cron-boiler-nightly \
             -- /Users/$USER/scripts/boiler-nightly.sh
```

Notes:
- `--agent-name` should be specific enough to grep in `dop log tail`
- The token stays in the process env; child processes see the injected
  `BOILER_TOKEN` / `NOTION_TOKEN` / etc.
- `--clean-env` strips inherited env vars (leaving only PATH/HOME/USER +
  injected secrets). Recommended for cron.

## Claude Code

Install the DOP-CLI skill once:

```bash
# From apps/dop
mkdir -p ~/.claude/skills/dop
cp skills/claude-code/SKILL.md ~/.claude/skills/dop/
```

Then in your shell before launching Claude Code:

```bash
export DOP_TOKEN=tok_...   # the read-only bundle for research
claude
```

Inside a session, tell Claude something like:

> Use the DOP-CLI skill to pull our latest Notion database rows and summarize.

Claude reads the skill file, runs `dop exec --agent-name
claude-notion-research -- ntn api v1/pages...`, and the audit log
captures the operation. The raw bearer never appears in Claude's
context because it lives in the process env, not the prompt.

## Buzz-style cryptographic agents

If your agent already has an age keypair, register the public key in
the vault and use `--sign-with` — no bearer token in env, ever.

Register once (admin op, run manually the first time):

```bash
# 1. Ask the agent for its public key (age recipient string)
# 2. Decrypt vault to a plaintext temp copy
sops --decrypt "$HOME/.config/dop/vault/vault.yaml" > /tmp/vault.plain.yaml

# 3. Append the agent_pubkeys entry
cat >> /tmp/vault.plain.yaml <<'EOF'
agent_pubkeys:
  buzz-alpha:
    pubkey_age: age1xq64yyy2q7s8d6yl2zlutd90qelgl056y6jslq0x7zcnkn4drfkq8z9242
    grants: [boiler.read, notion.read]
    note: "Buzz production research runner"
EOF

# 4. Re-encrypt (P6 will ship an add-agent subcommand for this;
#    for now, do it manually via sops)
sops --encrypt --age "$(dop-your-recipient)" \
     --input-type yaml --output-type yaml \
     --output "$HOME/.config/dop/vault/vault.yaml" /tmp/vault.plain.yaml
rm /tmp/vault.plain.yaml
```

Then the agent invokes:

```bash
dop exec --agent-name buzz-alpha \
         --sign-with /path/to/buzz-alpha.age \
         -- ./run.sh
```

DOP verifies the keyfile's derived recipient matches
`agent_pubkeys.buzz-alpha.pubkey_age`, resolves grants, injects env.
Zero shared-secret exchange required.

## Auditing your own access

```bash
# All operations by a specific agent name
dop log grep agent_name=cron-boiler-nightly

# All denied attempts in the current file
dop log grep outcome=denied

# Last 20 lines across all files
dop log tail --n 20
```
