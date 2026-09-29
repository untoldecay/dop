# Admin Lifecycle

**Date:** 2026-09-29
**Contracts:** [`01_two_plane_authority.md`](../_requirements/contracts/01_two_plane_authority.md), [`02_admin_session_daemon.md`](../_requirements/contracts/02_admin_session_daemon.md), [`07_approval_gate.md`](../_requirements/contracts/07_approval_gate.md)

The administrative plane owns the vault. This doc walks through the four commands that get you from "no DOP installed" to "unlocked, ready to issue tokens", plus the two passphrase-management commands.

---

## Commands

### `dop admin init`
`apps/dop/cmd/dop/admincmd.go:51`

One-shot key generation + wrap. Prompts for **two** passphrases: the admin passphrase (unwraps the age + ed25519 key material) and the approval passphrase (used to gate agent-claim approvals — see doc 04).

```bash
dop admin init                                # interactive
printf "pw1\npw2\n" | dop admin init --passphrase-stdin   # tests / scripting
```

| Input | Description |
|---|---|
| Admin passphrase | ≥ 8 chars; wraps `keys/admin.age.enc` via age scrypt (workfactor 18) |
| Approval passphrase | ≥ 10 chars; argon2id-hashed at `keys/approval.hash` |

Writes:
- `<KeysDir>/admin.age.enc` (mode 0600) — the wrapped bundle of both keys
- `<KeysDir>/approval.hash` (mode 0600) — argon2id JSON blob (see contract 07)

Fails if a key already exists unless you pass `--force` (destroys any vault decryption ability tied to the old key — no undo).

### `dop admin login`
`admincmd.go:186`

Reads the admin passphrase from the TTY (or stdin), unwraps the keys in-memory, then forks `dop admin __session-daemon` with a fresh unix socket at `SockPath(paths)`. Waits for the daemon to print `ready\n` on its stdout, then detaches.

Idle-TTL defaults to 15 minutes (`$DOP_ADMIN_TTL`); absolute TTL is 60 min (`$DOP_ADMIN_MAX_TTL`).

### `dop admin logout`
`admincmd.go:270`

Sends `logout` over the socket. The daemon shuts down cleanly and removes the socket file. Idempotent — a second logout with no session prints "no active session" and exits 0.

### `dop admin status`
`admincmd.go:284`

Prints unlocked/locked, admin pubkey, age recipient, and remaining idle + absolute TTL.

### `dop admin set-approval`
`admincmd.go:141`

Rotates the approval passphrase without touching the wrapped admin key. **Requires an active session** — a same-uid attacker without login cannot silently swap it. Confirms the new passphrase twice unless `--passphrase-stdin`.

### `dop admin __session-daemon`
`admincmd.go:315` — internal fork target, not user-facing. Reads the wrapped-key JSON from stdin, starts a `Session` (`internal/admin/session.go`), and blocks on the socket. Enforces `LOCAL_PEERCRED` / `SO_PEERCRED` per contract 02.

---

## Usage flow

Fresh install (single admin):
```bash
dop admin init          # sets both passphrases
dop admin login         # start daemon
dop init --vault ~/dop-vault   # attach vault repo (see doc 02)
dop admin status        # verify unlocked
```

Every-session:
```bash
dop admin login         # only when the daemon isn't already up
# ... do admin work ...
dop admin logout        # when done
```

---

## Best practices

- Keep the admin passphrase strong. It's the only thing between an attacker with filesystem access and your entire vault.
- The approval passphrase should NOT equal the admin passphrase — the approval one gets typed into a phone browser (see doc 04). If they match, a phishing page compromises both.
- Use `dop admin status` to confirm before running admin commands in shell scripts — it exits 0 with `unlocked` on success, `locked` otherwise.
- Never run `dop admin init --force` unless you've verified there is NO capability record signed by the old admin key still in circulation.

---

## Dependencies

- `filippo.io/age` — scrypt-based key wrapping.
- `golang.org/x/crypto/argon2` — approval passphrase hashing.
- `golang.org/x/term` — no-echo passphrase read.
- `golang.org/x/sys/unix` — peer-cred socket verification.
- `sops` binary on `$PATH` — used by the daemon to decrypt/encrypt `vault.yaml`.

---

## Next steps

- Add `dop admin reauth` for in-place passphrase update without a full logout + login cycle.
- Consider OS keychain integration so `login` can unlock via Touch ID as an alternative to the passphrase prompt.
