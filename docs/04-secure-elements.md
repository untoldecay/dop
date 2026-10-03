# Secure elements

Every agent in DOP has a cryptographic identity. The README calls it an "ed25519 identification key" — true, but incomplete. There are up to three kinds of key material in play, and which one you get depends on your platform and your DOP version.

## The default: ed25519 agent keys

On first pairing, the agent generates its own ed25519 keypair. The private key lands at `~/.config/dop/agent-keys/<lookup>.key`, mode 0600, 64 bytes on disk. Every `dop exec` signs a fresh challenge with that key so the admin's issued record knows it's really talking to the agent it claimed.

Keys don't rotate on a schedule. They rotate when you tell them to — via `dop agent migrate <lookup>`, or when an admin revokes the claim and re-pairs the agent. The approval passphrase guards both ends.

**Same-uid risk.** A file at mode 0600 is as safe as your user account. Anything running as you can copy the file to another Mac and `dop exec` from there. That's the attack Secure Enclave kills.

## Secure Enclave on macOS (v1.11, still landing)

Apple's Secure Enclave stores a P-256 private key that **never leaves the chip**. The agent asks the SE to sign exec challenges; the raw key is unreachable, even to code running as your uid. Copy `~/.config/dop` to another Mac and `dop exec` fails — the key didn't come with you.

v1.11 shipped the SE backend with a file-based fallback. What's landing is **production hardening**: the SE path requires a Developer ID-codesigned `dop` binary with the right entitlements. The install script's codesigning hook and `dop doctor` SE check went in during v1.11.1, but if you built from source or installed before that hook, you're on the ed25519 file-backed path until you re-install or migrate.

**Fallback behavior.** On macOS without a usable SE (unsigned binary, old hardware, SE unavailable), new claims refuse by default rather than silently writing an extractable key. Set `DOP_ALLOW_FILE_KEYS=1` to opt in — the risk shows up in `dop doctor` so you can't forget it's on. On Linux and in CI, file-backed keys are the only option; the same opt-in applies.

**Migration.** `dop agent migrate <lookup>` creates a fresh SE-backed P-256 key, re-signs the capability record, and keeps the old file key for 12 hours as an escape hatch before deletion. Admin session + approval passphrase required — this is a real re-enrollment.

**Same-uid risk, revisited.** A same-uid attacker can still ask the daemon to sign on their behalf while your session is unlocked. SE kills *portable* key theft; it doesn't change the same-machine trust model. See the [threat model](05-threat-model.md) for what that means in practice.

## P-256 and ECDH (v1.12, partially shipped)

Once the agent has a P-256 key, admins can do something ed25519 never allowed: send encrypted payloads that **only that specific agent on that specific machine** can open.

The admin generates a one-shot P-256 keypair, runs ECDH against the agent's SE pubkey, and seals a payload with the resulting symmetric key. The agent's SE opens it. The admin's ephemeral private key is thrown away immediately.

What this buys you: **direct scope updates without re-pairing**. Today, changing an agent's grants means revoking and re-issuing — new QR, new PIN dance. With ECDH-sealed env on the record, `dop token add-grant` and `remove-grant` mutate in place; the agent's next `dop exec` picks up the new env. Same mechanism enables transparent bearer rotation.

Shipped: the ECDH primitive (M1 — seal, open, roundtrip tests). In flight: wiring it into the record schema, admin issue path, and exec read path (M2+). Until M2 lands, grant changes still require re-issue. The feature is gated on P-256 bearers; legacy ed25519 agents stay on the current path until they migrate.

## What's next

The [threat model](05-threat-model.md) walks through what each key type protects against — and the attacks that no amount of key hygiene can stop.
