# Secure elements

Every agent in DOP has a cryptographic identity. The README calls it an "ed25519 identification key" — true, but incomplete. There are up to three kinds of key material in play, and which one you get depends on your platform and your DOP version.

## The default: ed25519 agent keys

On first pairing, the agent generates its own ed25519 keypair. The private key lands at `~/.config/dop/agent-keys/<lookup>.key`, mode 0600, 64 bytes on disk. Every `dop exec` signs a fresh challenge with that key so the admin's issued record knows it's really talking to the agent it claimed.

Keys don't rotate on a schedule. They rotate when you tell them to — via `dop agent migrate <lookup>`, or when an admin revokes the claim and re-pairs the agent. The approval passphrase guards both ends.

**Same-uid risk.** A file at mode 0600 is as safe as your user account. Anything running as you can copy the file to another Mac and `dop exec` from there. That's the attack Secure Enclave kills.

## Secure Enclave on macOS — what actually happens today

Apple's Secure Enclave stores a P-256 private key that **never leaves the chip**. The agent asks the SE to sign exec challenges; the raw key is unreachable, even to code running as your uid. Copy the DOP folder to another Mac and `dop exec` fails — the key didn't come with you.

**Up to v1.18.2, no `dop` build reached it.** DOP created its SE key as a permanent keychain item, which macOS only allows to binaries carrying keychain entitlements — and those come only with an Apple provisioning profile. A code signature alone, even Developer ID, isn't enough: key creation failed with `-34018` (`errSecMissingEntitlement`) and the claim fell back to a file key. Verified on 2026-10-10 (bd dop-ccy), fresh vault, PIN bearer, `dop claim` with the default key type:

| Build | Signature | Agent key after claim | Extractable | `exec` with bearer | `exec` without bearer | `dop doctor` |
|---|---|---|---|---|---|---|
| Official v1.18.2 release | Developer ID + hardened runtime | ed25519 file (SE `-34018`) | yes (0600 file) | works | no (needs P-256) | says "SE access should work" — **wrong** |
| v1.18.2 signed with an Apple Development cert | Apple Development + hardened runtime | ed25519 file (SE `-34018`) | yes | works | no | "needs a provisioning profile" — right |
| `go build` from source | ad-hoc | ed25519 file (SE `-34018`) | yes | works | no | "adhoc-signed, SE will fail" — right |

**Since dop-ofn (next release): every build reaches it.** DOP now creates the agent key inside the Secure Enclave *without* a keychain item — the private key stays in the chip, and DOP keeps only its SE-wrapped handle in `agent-keys/<lookup>.se` (0600). That handle is useless on another Mac (the key isn't in it), and needs no entitlement, so signed, Apple Development and plain source builds all get it:

| Build (dop-ofn) | Agent key after claim | Extractable | `exec` with bearer | `exec` without bearer | `dop doctor` |
|---|---|---|---|---|---|
| any (verified on an ad-hoc `go build`) | Secure Enclave P-256, `agent-keys/<lookup>.se` | no — the private key never leaves the chip | works | works | `secure-enclave: available` (real probe) · `agent:keys: all hardened` |

Rotation, re-issue, `dop agent migrate`, revoke clean-up and bearer-free `dop exec` all work with handle keys. A handle copied from another machine (or corrupted) fails with "not usable on this Mac". Same-user processes on *this* Mac can still ask the SE to sign — the same-machine trust model is unchanged. Keys created by an older build stay readable.

**Fallback behavior.** When there's no Secure Enclave to use (Linux, CI, Macs without the chip), a new claim gets a **P-256 file key** (`agent-keys/<lookup>.p256`, 0600 — readable by any process running as you) so rotation, grant edits and bearer-free `dop exec` still work; on macOS this is announced with a warning box. Up to v1.18.2 the fallback was an ed25519 file key, which supports none of those. `--key-type ed25519` still creates one on purpose; `DOP_ALLOW_FILE_KEYS=1` now only silences the warning.

**The way forward (tested).** Apple's CryptoKit can create a Secure Enclave key **without any keychain entitlement**: the key stays in the chip and the program keeps only an encrypted handle that works on that Mac only. A plain, ad-hoc-signed test program created an SE key, reloaded it from its 284-byte handle, signed with it and did ECDH. Switching DOP's macOS backend to that model would give SE-backed agent keys to every build — signed or not — with no Apple Developer account involved.

**Migration.** `dop agent migrate <lookup>` creates a fresh SE-backed P-256 key, re-signs the capability record, and keeps the old file key for 12 hours as an escape hatch before deletion. Admin session + approval passphrase required — this is a real re-enrollment.

**Same-uid risk, revisited.** A same-uid attacker can still ask the daemon to sign on their behalf while your session is unlocked. SE kills *portable* key theft; it doesn't change the same-machine trust model. See the [threat model](05-threat-model.md) for what that means in practice.

## P-256 and ECDH (v1.12, partially shipped)

Once the agent has a P-256 key, admins can do something ed25519 never allowed: send encrypted payloads that **only that specific agent on that specific machine** can open.

The admin generates a one-shot P-256 keypair, runs ECDH against the agent's SE pubkey, and seals a payload with the resulting symmetric key. The agent's SE opens it. The admin's ephemeral private key is thrown away immediately.

What this buys you: **direct scope updates without re-pairing**. Today, changing an agent's grants means revoking and re-issuing — new QR, new PIN dance. With ECDH-sealed env on the record, `dop token add-grant` and `remove-grant` mutate in place; the agent's next `dop exec` picks up the new env. Same mechanism enables transparent bearer rotation.

Shipped: the ECDH primitive (M1 — seal, open, roundtrip tests). In flight: wiring it into the record schema, admin issue path, and exec read path (M2+). Until M2 lands, grant changes still require re-issue. The feature is gated on P-256 bearers; legacy ed25519 agents stay on the current path until they migrate.

## What's next

The [threat model](05-threat-model.md) walks through what each key type protects against — and the attacks that no amount of key hygiene can stop.
