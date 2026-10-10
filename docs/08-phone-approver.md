# The phone as approver

Status: design, 2026-10-10. Nothing here is built yet. The bd epic tracks the work.

## Why

Today every approval is a web page. The machine that needs a yes (a claim, a
request to print keys into a transcript, a protected-grant issue) starts a
small HTTP server, opens a Cloudflare quick tunnel, prints a QR code, and
waits. You scan, the page asks for the approval passphrase, you type it.

Three things are wrong with that:

- **Nothing reaches you.** The QR lands in the agent's terminal. If the agent
  does not relay it, the request times out (dop-5j8).
- **A typed passphrase on a page the agent's machine served** is the one step
  a fake page could imitate. The passphrase is a knowledge factor; it can be
  phished, replayed, or shoulder-read.
- **Every page looks the same** whether an agent is claiming (expected) or a
  command wants to print keys into an AI transcript (the highest-risk action
  dop has). dop-dkj.

The phone fixes all three: it is always with you, it wakes you, and it can
sign.

## Trust model

The phone becomes an **approver device**. Pairing creates a P-256 key in the
Secure Enclave that never leaves the phone. Its public key is recorded in the
vault next to admins and devices, signed by the admin that paired it.

An approval is a **signature** by that key over the request, gated by Face ID
or, when the face is unavailable, by typing the approval passphrase on the
phone. Either way the answer that travels is a signature, never a passphrase.
The requester verifies the signature against the vault, the same way it
verifies admin signatures on capability records today.

What the phone never holds: the admin age key, the vault plaintext, any bearer.
It decides. The Mac executes.

What stays: the approval passphrase typed on the Mac or on the web page. It is
the fallback when the phone is lost, flat, or elsewhere. The policy is
"phone signature **or** passphrase", per approver device. Requiring both is a
per-vault setting for later, not v1.

The relay sees only "something is waiting for this device". It never sees the
question, the subject, the keys or the decision. A compromised relay can send
fake wake-ups; it cannot approve anything.

## Components

```
agent host / admin Mac              relay (Cloudron)               iPhone
──────────────────────              ────────────────               ──────
request record  ──push──▶ vault repo                               (no git here)
  (signed by requester)
request, sealed ───────▶ relay ──APNs──▶ wakes app ──fetch──▶ opens it
to the phone's key       (holds ciphertext                         Face ID
                          until expiry)                            or passphrase
                                                                   signs decision
decision record ◀──────── relay ◀──────────────────────────────── posts it
  (verified against device pubkey;
   also mirrored to vault repo for audit)
```

- **Requester** (dop on the agent host or the admin Mac): writes a signed
  request record to the vault repo under `pending-approvals/` (audit, and
  so other Macs see it), seals the same record to the phone's public key
  and posts the ciphertext to the relay, then polls the relay for a
  decision. Keeps serving the web page and the QR as today, so the
  passphrase path is untouched.
- **Vault repo**: the record of truth for every machine that has git. The
  phone never touches it.
- **Relay**: a small HTTP service on Camille's Cloudron (deployed with the
  Cloudron CLI) holding an APNs auth key. Keeps sealed requests until they
  expire, forwards a push to Apple, hands the ciphertext to the phone when
  it asks, carries the signed decision back. It cannot read a request or
  forge a decision. Rate-limited per device. The paid tier is this relay.
- **App**: native Swift, no git. Fetches sealed requests from the relay,
  opens them with its Secure Enclave key, shows what is at stake, approves
  or rejects with Face ID or the typed passphrase, shows history. Pairs by
  scanning the Device invite QR from the TUI.

## Flows

### Pairing

1. TUI: Add › Device, choose "phone". A QR appears carrying the relay URL, a
   one-time invite PIN and a pairing token for the relay.
2. App scans, creates its Secure Enclave key, posts `{pubkey, name}` to the
   relay signed with the invite PIN. The Mac picks it up and stages
   `devices/<id>.json` in the vault.
3. Admin approves in List › Team › Pending, exactly like a device today. The
   admin's signature over the device record is what every requester trusts.
4. App registers its APNs token with the relay under the device id.

### Approval

1. Requester builds the request record: kind (claim, remote-claim,
   print-bearer, print-keys, protected-grant), subject, agent name, host,
   harness, what-happens-if-yes, expires_at, a nonce, and the requester's
   signature. Stages it in `pending-approvals/` for the record, seals it to
   each registered phone's public key, posts the ciphertexts to the relay.
2. Phone wakes. App fetches, opens the request with its key, lists it with
   a colour and icon per kind (claim: neutral; print keys: red, "keys will
   be shown in an AI transcript"; protected grant: amber).
3. You approve or reject. Face ID, or the passphrase typed on the phone.
   App posts the decision to the relay: decision, device id, timestamp,
   signature over (request_id, nonce, decision).
4. Requester polls the relay, verifies the device signature against the
   vault, proceeds, and writes the decision record to the repo for audit.

The web page and `dop approve <SAS>` keep working in parallel. First valid
answer wins; the others are ignored and logged.

### Fallbacks

- Phone offline: the web page and the Mac passphrase path are unchanged.
- Relay down: the phone path is down with it; the web page and the Mac
  passphrase path still complete every request. The relay is never on the
  critical path of the passphrase flow.
- Lost phone: `dop team remove-device <id>` on the Mac. Every requester
  rejects its signatures from the next pull.

## Record shapes (sketch)

```json
// pending-approvals/<request_id>.json
{"request_id":"…","kind":"print-keys","subject":"hermes-guigz-vision",
 "agent_name":"notion-sync","host":"hermes-vps","harness":"hermes",
 "effect":"keys will be shown in an AI transcript","requested_at":"…",
 "expires_at":"…","nonce":"…","requester_pubkey":"…","signature":"…"}

// pending-approvals/<request_id>.decision.json
{"request_id":"…","nonce":"…","decision":"approve","device_id":"…",
 "decided_at":"…","method":"faceid|passphrase","signature":"…"}
```

Replay protection: the decision binds request_id and nonce; a request is
single-use and expires. Decisions for unknown or expired requests are
dropped.

## v1 scope: control and validation

- Pairing through the existing Device invite.
- Pending list across all five kinds, with per-kind colour and wording.
- Approve / reject, Face ID or passphrase on the phone.
- Push wake-up through the relay.
- History from the audit log.

Not in v1: issuing bearers, grants, integrations, unlocking the Mac. Those
need the admin key and stay on the Mac. Later they can become signed
commands the Mac daemon executes over the same bus.

## Constraints

- **Native Swift.** The Secure Enclave key and Face ID are only reachable
  from a native app.
- **Paid Apple developer account** for push notifications and TestFlight.
  A free account runs the prototype on your own phone (seven-day
  re-install, a few devices) with Face ID and the Secure Enclave working.
- **Build under Camille's own team.** From the next release the dop Mac
  binaries are signed with Camille's identity (chauve.camille@gmail.com,
  8L74UBM58L); Secure Enclave on macOS returns once that account holds a
  Developer ID. The iOS app and the relay's APNs key live there too.
- No git on the phone. Requests reach it sealed through the relay; the
  relay never holds a key that opens them.

## Milestones

1. **Bus and records.** Requesters stage request records and accept
   decision records; `dop approve --device` on a second Mac as the first
   "device" so the protocol is tested without a phone. e2e.
2. **Relay.** Cloudron app (Cloudron CLI), APNs key, sealed-request store
   with expiry, decision hand-back, rate limits.
3. **App prototype.** Pairing, list, Face ID approve, free account on one
   phone.
4. **Per-kind presentation.** dop-dkj resolved on the phone and ported back
   to the web page.
5. **TestFlight** under the paid account; passphrase-on-phone path;
   lost-phone removal.

## Open questions

- Settled 2026-10-10: no git on the phone; the relay carries requests
  sealed to the device key.
- Per-vault policy "phone and passphrase both required" for print-keys?
- Multiple phones per admin, and multiple admins per vault: any registered
  device of any admin may approve, or only the issuing admin's?
