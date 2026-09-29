# Token Lifecycle

**Date:** 2026-09-29
**Contracts:** [`04_capability_envelope.md`](../_requirements/contracts/04_capability_envelope.md), [`05_signed_record_and_trust.md`](../_requirements/contracts/05_signed_record_and_trust.md), [`06_pin_claim_binding.md`](../_requirements/contracts/06_pin_claim_binding.md)

Everything an admin does to mint, list, rotate, and revoke bearer tokens. Every command in this doc requires an active admin session.

---

## Commands

### `dop token issue`
`apps/dop/cmd/dop/tokencmd.go:52`

Mints a bearer + the on-disk artifacts that make it usable. Default binding is `pin` — the bearer is worthless without a subsequent `dop claim`.

```bash
dop token issue --grants notion.read,linear.write \
                --name research-agent \
                --expires 72h
```

| Flag | Default | Meaning |
|---|---|---|
| `--grants` | (required) | Comma-separated grant IDs from `vault.yaml` |
| `--name` | random `token-<8hex>` | Human-readable subject label |
| `--expires` | `72h` | Duration; accepts `d` and `w` suffixes |
| `--pin-ttl` | `5m` | How long the emitted PIN stays valid |
| `--bind` | on (default) | Emit PIN; agent must run `dop claim` |
| `--no-bind` | off | Skip PIN; bearer alone runs `dop exec` |
| `--bind-pubkey <hex>` | — | Pre-bind to an agent's ed25519 pubkey (remote server case) |
| `--note` | "" | Free-text metadata (not used yet) |

Outputs (stdout):
```
tok_1<32hex>
XX-XX-XX          # only when --bind is default
```
Human text goes to stderr, so `BEARER=$(dop token issue ... 2>/dev/null | grep -E '^tok_1')` works in scripts.

Side effects:
1. Rolls the subject's generation counter.
2. Writes `capabilities/<lookup_id>.bundle` (AEAD, bearer-locked).
3. Writes `capabilities/<lookup_id>.record` (signed, JSON).
4. Updates `vault.yaml` and `admins.trust`.
5. Emits an `issue` audit event.

On save failure, rolls the bundle back to prevent orphan+gen-collision (see v1.6.4 devlog).

### `dop token list`
`tokencmd.go:227`

Prints every capability record with subject, grants, generation, status, expiry. Reads the vault via the daemon.

### `dop token revoke <subject>`
`tokencmd.go:257`

Marks the matching active capability `revoked`, bumps its generation, deletes its `.bundle` + `.record` sidecars, and re-encrypts the vault. Fails if the subject matches multiple active capabilities (be more specific).

Effect on agents:
- Next `dop pull` gets the new state.
- Local `dop exec` fails immediately because the record is gone.

### `dop token repin --subject <name>`
`tokencmd.go:389`

Regenerates the PIN for an unclaimed PIN-bound capability. Preserves the bearer. Requires the current bearer via `$DOP_TOKEN` or `--token-file` so we can re-encrypt the bundle. Refuses on already-claimed capabilities.

```bash
DOP_TOKEN=$OLD_BEARER dop token repin --subject research-agent --pin-ttl 10m
```

Outputs the new PIN on stdout. Bearer stays the same.

---

## Integration + grant management

### `dop integration add / list / remove`
`cmd/dop/integrationcmd.go` — CRUD for upstream tokens under `vault.yaml`.

```bash
dop integration add --name notion \
  --token read=ntn_abc:read-only \
  --token write=ntn_xyz:write \
  --metadata base_url=https://api.notion.com/v1
```

### `dop grant add / list / remove`
Wire an integration + token to an ACL identifier and env prefix.

```bash
dop grant add --id notion.read --integration notion --token read --env-prefix NOTION
```

Bearers reference grants (never integrations directly), so rotating an upstream token is a `dop integration add` (overwrites) — every issued bearer keeps working.

---

## Data model recap

```
integrations         (raw upstream secrets)
   ↓
grants               (named ACL entries, env prefix mapping)
   ↓
capabilities         (issued bearers, one per subject-per-generation)
   ↓
bundles + records    (on-disk artifacts agents consume)
```

See [`03_vault_schema.md`](../_requirements/contracts/03_vault_schema.md) for the authoritative YAML shape.

---

## Best practices

- Prefer many grants over few. `notion.read` and `notion.write` should be distinct grants — bearers should hold the narrowest set that lets them do their job.
- Set `--expires` conservatively. 24 h for exploratory agents, 7d–14d for long-running jobs, never `∞`.
- Never share raw upstream tokens by pasting them; put them in an integration and issue a bearer.
- Rotate the underlying integration token every time an admin leaves — `dop team remove` prints the checklist automatically.

---

## Dependencies

- `internal/capability` — envelope encryption, PIN, signing.
- `internal/vault` — schema.
- `internal/trust` — sidecar writer.
- `internal/audit` — event emission.

---

## Next steps

- `dop token show <subject>` (full detail view — currently `list` prints one row per record).
- Bulk-revoke by grant (`dop token revoke --grant notion.write`).
- Automatic re-issue on `--expires` window edge for long-running services.
