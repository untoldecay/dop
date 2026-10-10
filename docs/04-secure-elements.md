# Agent keys

Every agent in DOP has its own key, made on its own machine when it's paired. That key is its identity: on every `dop exec`, the agent signs a fresh challenge with it, and DOP checks the signature against the record you approved. A bearer copied somewhere else is useless without that key.

So the question that matters is: **can that key be copied?** It depends on the machine.

## Machine by machine

| Machine | Where the key lives | Can it be copied? |
|---|---|---|
| **Mac with a security chip** — every Apple silicon Mac, and Intel Macs with a T2 chip (2018 and later) | inside the Secure Enclave | **No.** The key is created in the chip and never leaves it |
| **Older Intel Mac** (no T2) | a P-256 file in the DOP folder (`agent-keys/<id>.p256`, 0600) | yes, by anything running as that user |
| **Linux server, CI runner, container** | a P-256 file (same as above) | yes, by anything running as that user |
| **Any machine, `--key-type ed25519`** (on purpose, or from an older DOP) | an ed25519 file (`agent-keys/<id>.key`) | yes |

It's automatic: `dop claim` (and `dop claim --remote` on a server) picks the best option the machine has. On a Mac without the chip, it tells you with a warning box.

## How the Secure Enclave key works

The Secure Enclave is a separate processor inside the Mac. It can create a key and use it, but it never hands the key out — not to DOP, not to macOS, not to you.

When an agent is paired on a Mac:

1. DOP asks the chip for a new P-256 key. The private part is created inside the chip and stays there.
2. The chip gives back a **handle** — an encrypted reference that only *this* chip can use. DOP saves it as `agent-keys/<id>.se`.
3. On every `dop exec`, DOP hands the handle back to the chip and asks it to sign. The chip signs; the key never comes out.

**What that means in practice:**

- **Copy the DOP folder to another Mac** — the handle is there, the key isn't. The other Mac's chip can't use it, so `dop exec` fails ("not usable on this Mac").
- **Steal the bearer and the files** — same result: nothing on disk is the key.
- **A program running as you, on this Mac** — it can still ask the chip to sign, just as DOP does. The Secure Enclave stops the key from being *taken away*; it doesn't change who you trust on your own machine. The [threat model](05-threat-model.md) covers that limit.

It works with any build of DOP — official release or built from source. No Apple developer account, no special signature, no keychain entry.

## What each key type can do

| | Secure Enclave | P-256 file | ed25519 file |
|---|---|---|---|
| Prove the agent's identity on every `dop exec` | ✓ | ✓ | ✓ |
| Change its grants without re-pairing | ✓ | ✓ | — |
| Rotate its bearer without a new claim | ✓ | ✓ | — |
| Run without `DOP_TOKEN` (bearer-free `dop exec`) | ✓ | ✓ | — |
| Can't be copied off the machine | ✓ | — | — |

The middle three rows need P-256: the admin seals data that only that agent's key can open (an ECDH exchange). ed25519 can't do that exchange, which is why it's now only kept for older pairings.

## Upgrading an older key

`dop agent migrate <id>` creates a new key the best way the machine allows (Secure Enclave on a Mac that has one), re-signs the agent's record, and keeps the old key file for 12 hours in case something goes wrong. It needs an admin session and the approval passphrase — it's a real re-pairing, done in place.

## Checking

- `dop agent list` — every key on this machine, its type and where it lives (`keychain-darwin` = Secure Enclave, `file` = file).
- `dop doctor` — `secure-enclave` asks the chip for a throwaway key to confirm it answers; `agent:keys` counts how many keys are in the chip vs in files.

## History

Up to v1.18.2, DOP stored its Secure Enclave key as a keychain item, which macOS only allows to apps carrying a special Apple provisioning profile. No DOP build had one — not even the Developer ID-signed releases — so every pairing quietly fell back to an ed25519 file key, and `dop doctor` wrongly reported the Secure Enclave as working. Verified on 2026-10-10:

| Build (≤ v1.18.2) | Agent key after pairing |
|---|---|
| Official release (Developer ID) | ed25519 file (Secure Enclave refused, `-34018`) |
| Apple Development signature | ed25519 file (same) |
| Built from source | ed25519 file (same) |

Since then, DOP keeps only the chip's handle instead of a keychain item, which needs no profile — so every build gets the Secure Enclave. Agents paired before that keep their file key until you run `dop agent migrate`.
