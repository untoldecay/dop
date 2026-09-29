# Vault Attach & Sync

**Date:** 2026-09-29
**Contracts:** [`03_vault_schema.md`](../_requirements/contracts/03_vault_schema.md), [`12_vault_git_sync.md`](../_requirements/contracts/12_vault_git_sync.md), [`05_signed_record_and_trust.md`](../_requirements/contracts/05_signed_record_and_trust.md)

The vault is a git repository. This doc describes how to attach it (as admin or as agent), keep it in sync, and the working-tree hygiene that lets `dop push` be safe.

---

## Commands

### `dop init --vault <src>`
`apps/dop/cmd/dop/init.go:53`

Attach as an **admin**. Requires `dop admin init` to have run (needs `keys/admin.age.enc`). Clones the source (URL or path) into `<Vault>` (typically `~/Library/Application Support/dop/vault`).

- If `<src>` is a local path that doesn't exist, bootstraps a local bare repo there and clones it — perfect for solo quickstarts.
- After clone, writes `.gitignore` inside the working tree (idempotent).
- If an admin session is unlocked, seeds `admins.trust` with just this admin's entry. **Never overwrites** an existing `admins.trust` — a second admin joining the same vault preserves the first admin's trust entry.

### `dop init --cache <src>`
`init.go:65`

Attach as an **agent**. Refuses to run if `admin.age.enc` already exists on this host (agent installs are keyless). Same clone semantics as `--vault`.

### `dop pull`
`init.go:190`

Fast-forward `git pull` inside the vault dir. Refuses non-ff to avoid silently merging concurrent admin edits — real merges require operator attention (see contract 12, "no merge driver").

### `dop push`
`init.go:200`

Stage everything (`git add -A`), commit if there's a diff, then push. The seeded `.gitignore` keeps staging tempfiles and swap files out.

---

## Vault working-tree contents

After first `dop token issue`, the vault dir looks like:

```
vault.yaml              SOPS-encrypted (age recipients = current admins)
.sops.yaml              creation rules (regenerated on every save)
vault-context.bin       20-byte random HMAC salt (public, used by agents)
admins.trust            JSON list of trusted admin pubkeys (public)
capabilities/
  <lookup_id>.bundle    XChaCha20-Poly1305 AEAD, bearer-locked
  <lookup_id>.record    Signed JSON — the trust proof the agent reads
.gitignore              seeded by dop init --vault
```

The **admin plane** on this machine also holds `<KeysDir>/admin.age.enc` and `<KeysDir>/approval.hash`, but those live under `<Root>` (typically `~/Library/Application Support/dop/`), not inside `<Vault>`, so they never enter git.

---

## The seeded `.gitignore`

`init.go:174` writes:

```
.dop-encrypt-*.yaml
.vault-edit-*.yaml
*.tmp
*.swp
.DS_Store
```

This blocks SOPS staging tempfiles, atomic-rename orphans, editor swap files, and macOS metadata.

---

## Multi-admin flow

1. Admin A: `dop admin init` → `dop init --vault git@host:org/vault.git` → issue tokens as needed.
2. Admin B (on a different machine): `dop admin init` (generates their own key) → shares their `ed25519_pubkey` + `age_recipient` with A.
3. Admin A: `dop team add-key --name B --pubkey age1... --ed25519 <hex>` → `dop push`.
4. Admin B: `dop init --vault <same-remote>` → `dop admin login` → they can now decrypt.

Note: because A already ran `dop token issue`, the remote already has `admins.trust` with A's entry. When B runs `init --vault`, the stat guard preserves A's entry — critical for multi-admin correctness.

---

## Best practices

- Push after every issue / claim / revoke so agents pick up trust changes on their next `dop pull`.
- Never edit `vault.yaml` manually. Use `dop vault edit` — which decrypts, opens `$EDITOR`, re-encrypts, and regenerates any drifted `.record` sidecars.
- Keep the vault repo private. Even though `bundle` files are AEAD-encrypted and `vault.yaml` is SOPS-wrapped, `admins.trust` reveals your admins and `vault-context.bin` reveals the HMAC salt (used to compute lookup IDs).
- Two admins issuing tokens concurrently on the same subject → `dop pull` refuses non-ff. Resolve by running `git reset --hard origin/main`, restarting your session, and re-issuing. A real merge driver is architecture-scope work.

---

## Dependencies

- `git` binary on `$PATH`.
- `sops` binary — invoked from the admin daemon.
- `filippo.io/age` — recipient parsing.
- `gopkg.in/yaml.v3` — vault schema serialization.

---

## Next steps

- Ship a `.gitattributes` with a custom merge driver for `vault.yaml` (semantic merge of admins/integrations/grants/capabilities maps).
- Auto-push toggle for CLI-driven flows.
