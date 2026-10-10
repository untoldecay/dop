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
agent host / admin Mac              relay (Cloud Run)              iPhone
──────────────────────              ─────────────────              ──────
request record  ──push──▶ vault repo ◀──pull── app
  (signed by requester)                                            Face ID
"pending" ping  ───────▶ relay ──APNs──▶ wakes app                 or passphrase
                                                                   signs decision
decision record ◀──pull── vault repo ◀──push── app
  (verified against device pubkey)
```

- **Requester** (dop on the agent host or the admin Mac): writes a signed
  request record to the vault repo under `pending-approvals/`, pings the
  relay, then polls the repo for a decision. Keeps serving the web page and
  the QR as today, so the passphrase path is untouched.
- **Vault repo**: the bus. Already shared by every machine, already pulled
  by the phone's deploy key (read) and pushed by it (write, decisions only).
  Remote claims already travel this way.
- **Relay**: a small HTTP service on Cloud Run holding an APNs auth key.
  Accepts `{device_id, kind}` from a requester, forwards a push to Apple.
  Rate-limited per device. Stores nothing durable. The paid tier is this
  relay.
- **App**: native Swift. Lists pending requests, shows what is at stake,
  approves or rejects with Face ID or the typed passphrase, shows history
  from the audit log. Pairs by scanning the Device invite QR from the TUI.

## Flows

### Pairing

1. TUI: Add › Device, choose "phone". A QR appears carrying the vault URL, a
   one-time invite PIN and a read/write deploy credential scoped to the repo.
2. App scans, creates its Secure Enclave key, pushes `devices/<id>.json`
   (pubkey, name, created_at) signed with the invite PIN.
3. Admin approves in List › Team › Pending, exactly like a device today. The
   admin's signature over the device record is what every requester trusts.
4. App registers its APNs token with the relay under the device id.

### Approval

1. Requester stages `pending-approvals/<request_id>.json`: kind (claim,
   remote-claim, print-bearer, print-keys, protected-grant), subject,
   agent name, host, harness, what-happens-if-yes, expires_at, a nonce, and
   the requester's signature. Pushes. Pings the relay.
2. Phone wakes. App pulls, lists the request with a colour and icon per
   kind (claim: neutral; print keys: red, "keys will be shown in an AI
   transcript"; protected grant: amber).
3. You approve or reject. Face ID, or the passphrase typed on the phone.
   App writes `pending-approvals/<request_id>.decision.json`: decision,
   device id, timestamp, signature over (request_id, nonce, decision).
   Pushes.
4. Requester sees the decision on its next poll, verifies the device
   signature against the vault, proceeds. Audit event records the device.

The web page and `dop approve <SAS>` keep working in parallel. First valid
answer wins; the others are ignored and logged.

### Fallbacks

- Phone offline: the web page and the Mac passphrase path are unchanged.
- Relay down: no wake-up; the app still shows the request on open. The
  requester never depends on the relay to complete.
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
- **Build under Camille's own team.** The dop Mac binaries must stop being
  signed with the teammate's Developer ID; the iOS app and the relay's
  APNs key live under Camille's account.
- The phone needs push access to the vault repo for decisions. A deploy
  credential scoped to that one repo, issued at pairing.

## Milestones

1. **Bus and records.** Requesters stage request records and accept
   decision records; `dop approve --device` on a second Mac as the first
   "device" so the protocol is tested without a phone. e2e.
2. **Relay.** Cloud Run service, APNs key, ping from requesters, rate
   limits, no durable state.
3. **App prototype.** Pairing, list, Face ID approve, free account on one
   phone.
4. **Per-kind presentation.** dop-dkj resolved on the phone and ported back
   to the web page.
5. **TestFlight** under the paid account; passphrase-on-phone path;
   lost-phone removal.

## Open questions

- Does the phone pull the repo directly (git on iOS is heavy) or does the
  requester also post the request body to the relay encrypted to the
  device's public key? The second keeps the relay blind and makes the app
  simpler, at the cost of the relay carrying ciphertext.
- Per-vault policy "phone and passphrase both required" for print-keys?
- Multiple phones per admin, and multiple admins per vault: any registered
  device of any admin may approve, or only the issuing admin's?
