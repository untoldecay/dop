# Feature Contract — Two-Plane Authority

## Scope
- Separation between the administrative plane (unlocks the vault, mints capabilities) and the execution plane (uses a bearer to run child processes).

## Purpose
- Contain blast radius: a compromised execution host must not be able to mint or elevate credentials.

## Invariants
- MUST split authority into exactly two planes: administrative and execution.
- MUST require an active admin session (unlocked keys held by the local daemon) for every mutation of `vault.yaml`.
- MUST NOT require any admin key material on a machine that only executes bearers.
- MUST prevent the execution plane from reading `vault.yaml`, admin keys, or the approval passphrase.
- MUST let both planes coexist on one host without opening a privilege-escalation path from execution to administrative.

## Mandatory Behaviors
- MUST refuse admin subcommands (`token issue`, `token revoke`, `token repin`, `token portable`, `token rotate`, `token reseal`, `token add-grant` / `remove-grant`, `admin set-approval`, `integration *`, `grant *`, `team *`, `vault edit`, `trust list`, `trust revoke`, `use`) unless the caller can reach an active daemon socket.
- MUST provide agent-only subcommands (`dop exec`, `dop whoami`, `dop env`, `dop claim`, `dop pending`, `dop approve`, `dop reject`, `dop watch`) that never open `vault.yaml`.
- v1.14.0 — cross-plane subcommands (don't require daemon or admin keys): `dop update` (fetches from GitHub, replaces binary; see contract 21), `dop skill install` + `dop skill show` + `dop skill show-command` (writes templates; `claude plugin` registration is best-effort; see contract 22), `dop version`, `dop help`, `dop doctor`.
- MUST detect the plane at install time (`admin.KeyFileExists`) and refuse `dop init --cache` on a host that already carries admin keys.
- SHOULD surface which plane a host is on via `dop doctor` / `dop admin status`.

## Forbidden Behaviors
- MUST NOT ship an operation that both requires admin key material and runs on an agent-only host.
- MUST NOT let an admin subcommand fall back to a non-daemon path that reads admin keys directly from disk after `dop admin init`.
- MUST NOT publish agent private keys (`agent-keys/`) into the vault repo.

## Interfaces
- Inputs: `dop admin init --passphrase-stdin`, `dop admin login`, `dop init --vault | --cache`.
- Outputs: presence of `keys/admin.age.enc` and daemon socket determine plane state.
- Events: `admin_login`, `admin_logout` audit events; presence of unix socket at `SockPath`.
- Dependencies: `internal/admin`, `internal/config` for paths.

## State & Data Rules
- MUST store the wrapped admin key at `keys/admin.age.enc` mode 0600 on admin hosts.
- MUST NOT create `keys/` at all on agent installs (see `initAsAgent`).
- MUST keep the daemon socket at `SockPath(paths)` mode 0600 inside a 0700 parent.

## Acceptance Criteria
- PASS if `dop init --cache` on a fresh host refuses when `admin.age.enc` is present.
- PASS if any admin command exits non-zero with "no active admin session" when the daemon isn't running.
- FAIL if an agent-only host can execute `dop token issue`.
- FAIL if `dop exec` opens `vault.yaml` on any code path.

## Regression Checks
- Verify `dop init --cache` refuses on an admin install (see `v1_admin_session.sh`, `v1_tui_gates.sh`).
- Verify `dop token issue` fails after `dop admin logout` (`v1_issue_and_persist.sh` step 8).
- Verify `dop exec` succeeds on an agent install that carries only `capabilities/` + `vault-context.bin` + `admins.trust`.

## Open Questions
- Should a machine ever hold BOTH `admin.age.enc` AND a delivered agent bearer file? Current design permits it; policy is out-of-band.
