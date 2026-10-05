# Feature Contract — Agent Exec + Env Hardening

## Scope
- `dop exec` and its siblings `dop whoami` / `dop env`: bearer resolution, binding proof, env injection, child-process hardening.

## Purpose
- Run a child process with only the env vars that the bearer's grants unlock, with no vault access and no ambient credential leakage.

## Invariants
- MUST resolve the bearer from `$DOP_TOKEN`, `--token-file`, or `$DOP_TOKEN_FILE` in that order.
- MUST derive `lookup_id = HMAC-SHA256(vault_context, bearer)[:20]` and read the bundle at `<Vault>/capabilities/<lookup_id>.bundle`.
- MUST call `verifySignedRecord` BEFORE `capability.Read` on every exec/whoami/env.
- MUST verify `binding.pubkey` matches the local agent key file (constant-time compare) when the binding is `pin`+claimed or `pubkey`.
- MUST reject an unclaimed `pin` binding with "requires a PIN claim first".
- MUST reject a bound bearer without a matching agent key with "no agent key on this machine".
- **Portable-owner bypass (v1.14.0-rc3)**: MUST skip the binding/agent-key check when the bearer is admin-owned portable (record has `PortableWrapped != ""` AND an active admin session exists AND `rec.IssuedBy == session.AdminPubkey`). Signature + generation + expiry + scope checks still apply. Emits `exec` with `extra.portable_owner="yes"`.

## Mandatory Behaviors
- `dop exec` MUST emit an `EventExec` audit event on success (subject, lookup_id, agent_name, generation, env_keys, child basename).
- MUST inject the env vars from the bundle into the child, sorted for determinism.
- MUST support `--clean-env` to strip inherited env except `PATH, HOME, USER, SHELL, TERM, LANG`.
- MUST harden `git` children: strip `GIT_SSH_COMMAND, GIT_EXTERNAL_DIFF, GIT_ASKPASS`; set `GIT_TERMINAL_PROMPT=0, GIT_CONFIG_NOSYSTEM=1`; force `core.hooksPath=/dev/null` and `protocol.ext.allow=never` via `GIT_CONFIG_COUNT` / `GIT_CONFIG_KEY_*`.
- MUST warn on a corrupt gen-cache file and treat it as generation 0 (never fail-open exec on parse error).
- `dop whoami` MUST surface `bearer` prefix, subject, generation, expires_at, and binding status.
- `dop env` MUST print `export KEY='VALUE'` lines (sorted, no shell interpolation of value).

## Forbidden Behaviors
- MUST NOT open `vault.yaml` on any exec path.
- MUST NOT print the bearer, agent private key, or upstream token value to stderr.
- MUST NOT allow a lower-generation bundle to override a higher-generation cache entry (rollback replay).
- MUST NOT skip the signature verification even when `admins.trust` is present but empty — that is a hard-fail.

## Interfaces
- Inputs: bearer + agv `-- CMD [args]`; env `$DOP_TOKEN`; optional `--token-file`, `--agent-name`, `--clean-env`, `--no-pull`.
- Outputs: child process replaced via `syscall.Exec`; env vars set in the child's environment.
- Events: `exec` audit event.
- Dependencies: `internal/capability` (Read + LookupID), `internal/trust`, `internal/audit`.

## State & Data Rules
- MUST persist the highest seen generation per lookup_id under `<Root>/gen-cache/<lookup_id>`, mode 0600 in a 0700 dir.
- MUST NOT persist bearers or bundle plaintext.
- MUST load the agent private key from `<Root>/agent-keys/<lookup_id>.key` and refuse mode > 0600.

## Acceptance Criteria
- PASS if a bound bearer with a matching local key runs the child with only the granted env vars.
- PASS if the same bearer fails when the agent key file is removed.
- PASS if `dop exec -- git ...` inherits none of `GIT_SSH_COMMAND`, `GIT_ASKPASS`, or `GIT_CONFIG_GLOBAL` semantics from the parent.
- FAIL if `dop exec` succeeds when `.record` is missing.

## Regression Checks
- `v1_exec_flow.sh` (env injection, revoked, expired, tampered).
- `v1_signature_verify.sh` (record verification gate).
- `v1_pin_claim.sh` (binding enforcement after claim).

## Open Questions
- Should env-hardening extend to `docker`, `kubectl`, `ssh`? Each has its own env-var footprint; currently only git is covered.
