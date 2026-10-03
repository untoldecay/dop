# Contract Index

Short, scannable list of every feature contract. Each contract pins the invariants a feature MUST honor across releases.

| # | Contract | One-liner |
|---|---|---|
| 01 | [Two-plane Authority](01_two_plane_authority.md) | Admin plane mints capabilities; execution plane spends bearers. No crossover. |
| 02 | [Admin Session Daemon](02_admin_session_daemon.md) | Forked session process holds admin keys so commands don't re-prompt. |
| 03 | [Vault Schema](03_vault_schema.md) | `schema_version: v1`; integrations/grants/capabilities/admins/generations shape. Includes Protected (rc12), Kind (rc13) fields. |
| 04 | [Capability Envelope](04_capability_envelope.md) | Encrypted bundle delivered to the bearer. v1.12 ECDH direct-availability (EnvWrapped, BearerWrapped). Way B bearer-free resolve (rc11). |
| 05 | [Signed Record + Trust](05_signed_record_and_trust.md) | Per-capability record signed by an admin in `admins.trust`. |
| 06 | [PIN Claim Binding](06_pin_claim_binding.md) | Short-lived PIN binds a bearer to an agent's keypair. |
| 07 | [Approval Gate](07_approval_gate.md) | Approval passphrase + 8-attempt rate limit as the second factor. |
| 08 | [Web Approval Flow](08_web_approval_flow.md) | Pending-claim HTTP + Cloudflare Quick Tunnel + QR + mobile approval. |
| 09 | [Agent Exec](09_agent_exec.md) | `dop exec`/`env`/`whoami` — bearer resolution, binding proof, env injection. |
| 10 | [Audit Log + Notifications](10_audit_log.md) | Append-only JSONL + `dop watch` + macOS notifications. All event kinds listed. |
| 11 | [Team Lifecycle](11_team_lifecycle.md) | Multi-admin add / list / remove with trust + revocation guarantees. |
| 12 | [Vault Git Sync](12_vault_git_sync.md) | `dop init --vault|--cache`, `pull`/`push`, gitignore, working-tree hygiene. |
| 13 | [Handoff Text Shape](13_handoff_text_shape.md) | Pasted bearer+PIN handoff MUST contain only the command — no imperative prose. |
| 14 | [TUI Patterns](14_tui_patterns.md) | lipgloss conventions, preset pickers, multi-select, confirmation, help legends. |
| 15 | [Protected Credentials](15_protected_credentials.md) | Owner-locked integrations + grants (Shape B + daemon revert). |
| 16 | [Integration Kinds](16_integration_kinds.md) | `api`/`cli`/`mcp`/`other` + canonical env-key promotion. |
| 17 | [Endpoints Discovery Probe](17_endpoints_probe.md) | Opt-in probe at `integration add` time. OpenAPI path order + MCP tools/list. |
| 18 | [Token Lifecycle](18_token_lifecycle.md) | `integration set-token` (rotate value / edit scope). TUI token drill-down parity with grants. |
| 19 | [`dop use`](19_dop_use.md) | Admin's shortcut: `token issue --for-admin-use` stashes bearer; `dop use <subject>` emits export line via daemon unwrap. |

## Status

- 01-12 are foundational (pre-v1.13). Updated in-place as features landed.
- 13-18 are v1.13 additions. Written against the `generate-contract.md` prompt.
- 19+ are v1.14 additions.

## When to add a new contract

- A new user-visible feature with observable invariants (schema fields, event kinds, UI patterns, protocol shape).
- A pattern that's been reused ≥ 3 times and now needs to be pinned so future features don't reinvent it.

## When to update an existing contract

- Prefer updates over new numbers when the new feature extends an existing scope.
- When a contract is extended with a new section, link forward to the new contract that owns the detail (e.g. 03 points at 15 + 16).

## Review cadence

Before shipping any `rcN` release, scan the index + the touched contracts. If the code drifted from the contract, update the contract (if the code is right) OR fix the code (if the contract is still right).
