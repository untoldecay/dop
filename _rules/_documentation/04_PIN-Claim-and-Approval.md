# PIN Claim & Approval

**Date:** 2026-09-29
**Contracts:** [`06_pin_claim_binding.md`](../_requirements/contracts/06_pin_claim_binding.md), [`07_approval_gate.md`](../_requirements/contracts/07_approval_gate.md), [`08_web_approval_flow.md`](../_requirements/contracts/08_web_approval_flow.md)

The chat-handoff story: the admin issues bearer + PIN, the agent runs `dop claim`, and the admin approves the pending claim on their phone (or another device) via a passphrase-gated web page. This is the flow that turns "leaked bearer" into "still useless."

---

## Commands

### `dop claim <PIN>`
`apps/dop/cmd/dop/claimcmd.go:52` — the **agent** side.

Runs on the agent's machine (usually same as the admin's, since the claim needs an active admin session to update the vault + sign records). Blocks up to 5 min while the admin approves out-of-band.

```bash
DOP_TOKEN=tok_1... dop claim ZZ-NR-NY
```

| Flag | Default | Meaning |
|---|---|---|
| `--token-file <path>` | — | Read bearer from file instead of `$DOP_TOKEN` |
| `--skip-approval` | off | Unattended path — bypass the web approval gate |
| `--no-tunnel` | off | LAN-only mode; skip Cloudflare Quick Tunnel |
| `--bind <addr>` | `127.0.0.1` w/ tunnel, `0.0.0.0` w/o | Interface the local HTTP server binds |
| `--shell` | off | After claim, print `export DOP_TOKEN=…` |

What it does, in order:
1. Verify PIN via `capability.VerifyPIN` (constant-time compare against bundle's HMAC).
2. Generate a fresh ed25519 keypair for this agent.
3. Write a pending-claim file to `<Root>/pending-claims/<lookup_id>.json` (0600).
4. Start a local HTTP server on `bind:0` (ephemeral port).
5. If `cloudflared` is on PATH, spawn a Quick Tunnel and parse its `trycloudflare.com` URL from stderr.
6. Print a QR (`qrterminal.GenerateHalfBlock`) + text URL + SAS + LAN fallback + a friendly "the page asks for your passphrase" line.
7. Fire a `claim_pending` audit event → macOS notification.
8. Block until: approve, reject, timeout, or SIGINT / SIGTERM / SIGHUP.
9. On approve: persist agent key at `<Root>/agent-keys/<lookup_id>.key` (0600), rename bundle atomically, write signed record sidecar, save vault.

### `dop pending`
`apps/dop/cmd/dop/approvecmd.go:95`

Lists in-flight claims. Table columns: SAS, subject, state, TTL left, pubkey fingerprint.

### `dop approve <SAS>`
`approvecmd.go:19` — the **admin** side, when the phone / web path isn't available.

Interactive prompt for the approval passphrase, then marks the pending record `approved`. Shares the 8-attempt rate limit with the web endpoint (flock-atomic — see contract 07).

```bash
dop approve 472-913                    # interactive prompt
echo -n "$APPROVAL" | dop approve --passphrase-stdin 472-913
```

### `dop reject <SAS>`
`approvecmd.go:61` — no passphrase required (rejecting is safe; approving is dangerous).

---

## Web approval page

Rendered by `internal/approvalserver`. Mobile-first CSS with `prefers-color-scheme` support, safe-area insets, 44 px tap targets, absolute form actions (`/c/<token>/approve` — v1.6.2 fix), passphrase-only auth.

The URL is worthless without the passphrase: even if an attacker captures the QR / URL from the terminal (or via Cloudflare logs), they can't approve without the 10-char-min argon2id-hashed secret.

### Threat properties

| Attack | Mitigation |
|---|---|
| URL leaks into logs / screen recording | Argon2id + 8-attempt cap makes offline / online brute force infeasible in 5 min |
| Same-uid agent extracts URL + curls it | Passphrase gate blocks; also flock-shared counter with `dop approve` |
| Wrong-wifi phishing of the QR | Trust the QR only from your own laptop |
| Terminal capture of SAS | SAS is not a security token; UX only |

---

## Full happy path

Admin:
```bash
dop admin login
BEARER=$(dop token issue --grants notion.read --name research-agent 2>/dev/null | grep -E '^tok_1')
# Copy bearer + PIN to chat / clipboard.
```

Agent (via chat handoff):
```bash
DOP_TOKEN=$BEARER dop claim <PIN>
# → prints QR + URL + SAS, blocks
```

Admin (on phone):
1. Scan the QR.
2. Enter approval passphrase.
3. Approve.

Agent (previously blocked):
```
dop claim: bound research-agent → pubkey <fp> (gen N)
```

Now `DOP_TOKEN=$BEARER dop exec --agent-name x -- <cmd>` works.

---

## Failure modes

- **`PIN does not match`** — typo, or PIN expired. Ask admin to `dop token repin`.
- **`approval window expired`** — no approve within 5 min. Reissue PIN; try again faster.
- **`claim rejected via web`** — admin denied. Ask why before retrying.
- **`too many failed passphrase attempts — claim aborted`** — 8-attempt cap tripped. Reissue PIN.
- **Cloudflare 502 after approve** — race we fixed in v1.6.2 (write + flush response before shutdown, 1.5 s grace). If still happening, check `cloudflared` version.

---

## Dependencies

- `internal/pendingclaim` — pending file + flock counter.
- `internal/approval` — argon2id verify.
- `internal/approvalserver` — HTTP server + form.
- `internal/tunnel` — cloudflared subprocess.
- `github.com/mdp/qrterminal/v3` — terminal QR.

---

## Next steps

- macOS Touch-ID approval path (`--local`), no phone needed.
- iOS/macOS companion app that receives push and returns a signed approval — replaces the tunnel for well-outfitted setups.
- Cross-host claim (agent on remote, admin on laptop) via signed claim record committed to git — bigger refactor.
