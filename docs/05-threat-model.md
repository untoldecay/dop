# Threat model

DOP's one-line boundary: **a compromised agent host must not be able to mint or elevate credentials, and a leaked bearer in a chat log must be worthless without a second-factor dance from an admin's phone.** Everything else in this document falls out of that boundary — what it buys you, and what it quietly leaves on the table.

## The posture

Two planes, strictly separated. The **admin plane** holds the wrapped admin key, unlocks the vault, and mints capabilities. The **agent plane** holds a bearer file and a per-agent identity key, and can only run child processes with injected env. The agent plane cannot read `vault.yaml`, cannot reach admin keys, and cannot elevate itself into the admin role — the daemon socket is 0600, admin subcommands refuse without an active session, and `dop init --cache` refuses to run on a host that already carries admin keys.

The trust unit is the OS user account. If something runs as your uid, it inherits the same reach you give your SSH key. DOP does not try to be stronger than that boundary — same posture as `~/.ssh/id_ed25519`.

## What DOP protects well

**Scoped, revocable per-agent credentials.** The raw PAT stays in the sops-encrypted vault. Each agent gets a bearer that resolves to a slice of scopes — `notion.read`, not "the whole Notion token." Revoke the bearer, the agent's next `dop exec` fails cleanly. Rotate the raw PAT in the vault, every agent holding a grant on it picks up the new value on next exec; no agent redeploy.

**Bearers in chat logs are worthless on their own.** Pairing requires a PIN delivered over a Cloudflare quick tunnel, approved via QR on an admin's phone, gated by a second passphrase (argon2id, RFC-9106 params, 10-char min). Eight wrong attempts auto-rejects the claim — shared counter across CLI and web, so an attacker can't get 8 tries on each path. The approval passphrase is distinct from the admin passphrase so a phished approval page doesn't hand over vault access.

**Every use is auditable.** Issue, claim, approve, deny, exec, env, revoke, protect, bypass-attempt — all land in append-only JSONL at `~/.dop/logs/audit.jsonl` with the actor and the lookup id. `dop watch` tails it live; macOS gets notifications for the events that matter. The log never contains bearers, PINs, or passphrases — only fingerprints and metadata.

**Agent identity is bound to the key.** Every record is ed25519-signed by the issuing admin against a vault-wide `admins.trust` file. `dop exec` verifies the signature, the bundle hash, and that the issuing admin is still trusted — all before decrypting a single byte of env. A record copied to a different host with a different agent key fails verification immediately.

**Admin-to-admin "hands off" marker.** The `--protected` flag locks an integration or grant to a specific admin's pubkey. Non-owners trying to mutate it through DOP get a loud refusal, an audit event, and (if they tried a direct daemon write) a server-side revert. Four-admin teams get a workable "this credential is Alice's — Bob, don't rotate it" story without per-record encryption.

## Do agents see the keys?

**Yes, at the moment they use them — but they never hold them.** When an agent runs `dop exec -- <command>`, DOP decrypts the keys and puts them in the environment of that one command. They have to be in plain text there: that's what lets the command call the Notion or GitHub API. They are never written to disk, never placed in the agent's conversation or files, and they're gone when the command ends. What the agent keeps is a bearer — a pass, not a key — limited to its grants, expiring on its own, revocable at once, and audited on every use.

**Printed means sent.** Whatever lands in an agent's terminal goes to its AI provider and stays in the harness history (`~/.claude`, Cursor's sqlite, opencode's db, the hub's log) — out of your reach, so the only remedy is rotating the key. We saw it happen: an agent's `dop env` output became a literal key inside a logged `curl` command. So DOP keeps keys out of what the agent sees: `dop env` is refused for a claimed agent, and `dop exec` replaces any injected key in the command's output with `‹NAME›` before it reaches the screen — pipes and terminals alike, since harnesses like Cursor run commands in a terminal and read it back.

**The limit: DOP is not a proxy.** The command itself holds the real key, so an agent that *wants* it can still smuggle it out (encode it, reverse it, print part of it, send it somewhere) — masking only catches the exact value. And if the model writes a key into its own command, the harness has recorded it before DOP runs; nothing downstream can undo that. The risk DOP removes is the key pasted into a chat, shared between teammates, left in an `.env` file forever, or printed into a transcript by accident — not a malicious agent using a key while it has access.

**To narrow that window:** use reduced-scope keys on the service side (read-only where possible), issue short-lived bearers, have agents reference keys as `$NAME` inside `dop exec -- sh -c '…'` so the model never writes the value, and revoke — and rotate the key — at the first doubt.

## What DOP deliberately doesn't protect

**A same-uid attacker on an admin host.** If malware runs as you while your admin daemon is unlocked, it can ask the daemon to issue bearers, sign records, or decrypt capability env. The daemon socket is 0600; a process running as you can open it. This is the same posture as "same-uid attacker gets your SSH agent" — DOP's countermeasures are an unlocked daemon with a short-lived session and audit entries you can review, not a trust boundary against your own uid.

**A same-uid attacker on an agent host.** On a Mac with a security chip, the agent's key lives in the Secure Enclave: nothing running as you can copy it away, but it can still ask the chip to sign while it runs on that Mac. On Linux, in CI and on older Macs, the key is a 0600 file (`agent-keys/<id>.p256`) — anything running as you can copy it to another machine and run `dop exec` from there. See [Agent keys](04-secure-elements.md).

**Audit log truncation or tampering.** The log is a plain JSONL file, 0600, no hash chain yet. A same-uid attacker can rewrite history. `dop watch` running on a second host would see live events but can't retroactively prove the on-disk log is intact. If you need SOC2-grade retention, ship the log to a central store you own — DOP won't do it for you.

**Concurrent multi-admin races.** Git is the sync layer. Two admins editing the same integration at the same time will produce a merge conflict on push; the loser has to pull, rebase, and re-apply. DOP does not use optimistic locking or a central lock service. Protected credentials narrow the collision surface by convention, but the ultimate serialization comes from `git push`.

**Long-lived bearers you issued "just once for a quick test."** A bearer with no PIN binding and a 90-day TTL that you forgot about is a bearer anyone with a copy can replay for 90 days. DOP's defaults bind every bearer to an agent key via the claim flow; the one-step `--direct` issue path (headless CI) deliberately skips the phone dance. If you use `--direct`, treat the bearer like an SSH key: short TTL, scoped to one job, revoke after use.

**Protected credentials against direct SOPS edits.** `--protected` enforces at the DOP write path. An admin who holds a sops-age key and edits `vault.yaml` with their editor can mutate anything. Every admin on the vault has decrypt rights by definition — protection is a convention + loud audit trail, not a cryptographic barrier. The contract spells this out: *"Any admin can decrypt the SOPS vault with their key and commit a hand-edited yaml outside DOP."*

**Phone approval failure modes.** The Cloudflare quick tunnel is a public URL for ~90 seconds. Anyone who sees your screen during pairing sees the QR. Anyone who intercepts the tunnel URL during that window can submit the approval form — but the approval passphrase is still required, and 8 wrong attempts aborts the claim. The practical attack: shoulder-surfing the QR AND the passphrase simultaneously. Mitigation is operational — don't demo pairing on a shared screen without masking the passphrase entry.

**Admin recovery when the laptop dies.** The admin key is wrapped under your admin passphrase and lives on one machine. There is no server-side escrow. If your laptop is bricked and you never ran `dop team invite` to add a second admin, the vault is readable (sops still works with the age identity) but no new admin sessions can mint capabilities under your name. Two-admin bootstrap is the recovery story — set it up before you need it.

## For the exact rules

The guarantees above are pinned by numbered MUST/MUST-NOT design contracts kept in the maintainers' working notes (not published in this repo). Plane separation (01), capability envelope (04), signed records and trust (05), the approval gate (07), audit shape (10), and protected credentials (15) are the ones most relevant above. If this doc says one thing and a contract says another, the contract wins.

## What's next

[Agent keys](04-secure-elements.md) walks through where each agent's key lives, machine by machine — and what the Secure Enclave still doesn't fix.
