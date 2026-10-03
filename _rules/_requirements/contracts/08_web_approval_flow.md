# Feature Contract — Web Approval Flow

## Scope
- The pending-claim file, the local HTTP server, the Cloudflare Quick Tunnel, the terminal QR, and the rendered mobile-first approval page.

## Purpose
- Move the approval decision to a device the agent cannot reach: the operator's phone (via public tunnel) or another laptop (via LAN).

## Invariants
- MUST default `dop claim` to launch the web server + tunnel + block for approval.
- MUST offer `--skip-approval` for unattended flows and `--no-tunnel` for LAN-only.
- MUST bind `127.0.0.1` by default when a tunnel is in play, `0.0.0.0` when `--no-tunnel`.
- MUST persist pending claims at `<Root>/pending-claims/<lookup_id>.json` mode 0600.
- MUST keep pending-claim TTL at 5 minutes.
- MUST include exactly these fields in a pending record: `sas, lookup_id, capability_id, subject, pubkey, started_at, expires_at, state, decided_at?, failure_count?`.
- MUST use a random 16-hex `display_token` in the URL path (`/c/<token>`).

## Mandatory Behaviors
- MUST render the approval page with mobile-first CSS, `prefers-color-scheme` support, and 44 px minimum tap targets.
- MUST use an absolute form action `/c/<token>/approve` and `/c/<token>/reject` (relative actions have been known to 404 when trailing slash is missing).
- MUST write the HTTP response BEFORE calling `markDecided` (avoids Cloudflare 502 on tunnel teardown).
- MUST hold the tunnel + server open ≥ 1.5 s after the decision before shutting down (grace period for edge response flush).
- MUST emit a `claim_pending` audit event on server-up with `{sas, expires_in, url}`.
- MUST fire a macOS notification for `claim_pending` when `DOP_NO_NOTIFY` is unset.
- MUST fall back to LAN-only mode gracefully if cloudflared is missing.
- MUST resolve a non-loopback IPv4 for the printed URL when `--no-tunnel` (unusable-URL guard).

## Forbidden Behaviors
- MUST NOT reveal whether a `/c/<random>` token exists — unknown token MUST 404.
- MUST NOT accept any request after a decision has been made — a further request MUST 410 Gone.
- MUST NOT trust the URL as authority — the passphrase in the POST body is the only authoritative gate (see contract 07).
- MUST NOT rely on the SAS as a security token (same-machine visibility). SAS is a friendly identifier for `dop pending` / `dop approve`.

## Interfaces
- Inputs: `dop claim <PIN>` with `--no-tunnel`, `--bind`; HTTP GET `/c/<token>`; HTTP POST `/c/<token>/{approve,reject}`.
- Outputs: HTML page; approval marker on the pending file; audit events; SIGHUP-safe defers.
- Events: `claim_pending`, `claim_approved`, `claim_denied` (reasons: `pin_mismatch`, `rejected`, `approval_timeout`, `pin_expired`).
- Dependencies: `net/http`, `github.com/mdp/qrterminal/v3`, `internal/tunnel` (cloudflared subprocess).

## State & Data Rules
- MUST rewrite pending files atomically via tempfile + `os.Rename`.
- MUST hold a `LOCK_EX` flock on the per-claim lockfile during `SetState` / `BumpFailure`.
- MUST clean up the pending JSON + lockfile via `pendingclaim.Delete` on decision / expiry / signal.

## Acceptance Criteria
- PASS if `dop claim --no-tunnel` prints a URL, exposes the pending record via `dop pending`, and blocks until approve/reject/expiry.
- PASS if a correct passphrase POST unblocks `dop claim` with the "Approved" page rendered cleanly (no 502).
- PASS if `SIGHUP` cleans up the pending file and stops cloudflared.
- FAIL if the URL alone can approve without a passphrase.

## Regression Checks
- `v1_web_approval.sh` covers page render, wrong passphrase, correct passphrase unblocks, 410 after decision, unknown token 404s.
- `v1_sas_approval.sh` covers CLI approve/reject with tests for audit + pending listing.

## Open Questions
- Should we ship a native "companion approve" macOS app (Touch ID gate) so the phone-and-tunnel dance becomes optional?
