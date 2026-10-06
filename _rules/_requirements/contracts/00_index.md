# Contract Index

Short, scannable list of every feature contract. Each contract pins the invariants a feature MUST honor across releases.

| # | Contract | One-liner |
|---|---|---|
| 01 | [Two-plane Authority](01_two_plane_authority.md) | Admin plane mints capabilities; execution plane spends bearers. No crossover. |
| 02 | [Admin Session Daemon](02_admin_session_daemon.md) | Forked session process holds admin keys. `SessionActive` = unlocked; live `set_ttl`; idle never lifts the absolute cap. |
| 03 | [Vault Schema](03_vault_schema.md) | `schema_version: v1`; integrations/grants/capabilities/admins/generations shape. Includes Protected (rc12), Kind (rc13) fields. |
| 04 | [Capability Envelope](04_capability_envelope.md) | Encrypted bundle delivered to the bearer. v1.12 ECDH direct-availability (EnvWrapped, BearerWrapped). Way B bearer-free resolve (rc11). |
| 05 | [Signed Record + Trust](05_signed_record_and_trust.md) | Per-capability record signed by an admin in `admins.trust`. |
| 06 | [PIN Claim Binding](06_pin_claim_binding.md) | Short-lived PIN binds a bearer to an agent's keypair. Repin re-issues bearer + PIN. |
| 07 | [Approval Gate](07_approval_gate.md) | Approval passphrase + 8-attempt rate limit as the second factor. |
| 08 | [Web Approval Flow](08_web_approval_flow.md) | Pending-claim HTTP + Cloudflare Quick Tunnel + QR + mobile approval. |
| 09 | [Agent Exec](09_agent_exec.md) | `dop exec`/`env`/`whoami` — bearer resolution, binding proof, env injection. |
| 10 | [Audit Log + Notifications](10_audit_log.md) | Append-only JSONL + `dop watch` + macOS notifications. Every `internal/audit` event kind listed (incl. `portable`). |
| 11 | [Team Lifecycle](11_team_lifecycle.md) | Multi-admin add / list / remove with trust + revocation guarantees. |
| 12 | [Vault Git Sync](12_vault_git_sync.md) | `dop init --vault|--cache`, `pull`/`push`, gitignore, working-tree hygiene. |
| 13 | [Handoff Text Shape](13_handoff_text_shape.md) | Pasted bearer+PIN handoff MUST contain only the command. Done-screen `useGuidance` block shape. |
| 14 | [TUI Patterns](14_tui_patterns.md) | One frame, short footer + `?` help, status line, tabs, wizards, dense forms, pickers, theme, glyphs, vocabulary, Esc, session guard. |
| 15 | [Protected Credentials](15_protected_credentials.md) | Owner-locked integrations + grants (Shape B + daemon revert). TUI shows the word `protected`. |
| 16 | [Integration Kinds](16_integration_kinds.md) | `api`/`cli`/`mcp`/`other`, 13 promoted env keys, Add integration dense form (integration vs credential fields, env prefix default). |
| 17 | [Endpoints Discovery Probe](17_endpoints_probe.md) | Opt-in probe at `integration add` time. OpenAPI path order + MCP tools/list. |
| 18 | [Credential + Bearer Lifecycle](18_token_lifecycle.md) | `integration set-token`, integration Credentials tab, `dop token` subcommands, stash kept on every record rewrite. |
| 19 | [`dop use`](19_dop_use.md) | Portable stash via `token issue --portable` or `token portable --on` (re-issue); `--off` clears it; `dop use <subject>` emits the export line via daemon unwrap. |
| 20 | [Trust Context Cache + Harness Adapters](20_trust_context_cache.md) | Daemon-held approval cache keyed on `(ContextKind, ContextValue, Subject)` with idle TTL. Resolver precedence: `DOP_SESSION_ID` → recognized harness env → tty → sid → ppid. |
| 21 | [Self-Update](21_update_cli.md) | `dop update` CLI: GitHub release fetch + SHA256 verify + atomic rename + rollback dir. TUI `c` flips channel, also from a nothing-installed done screen. |
| 22 | [Claude Code Plugin + Slash Command](22_claude_plugin.md) | `dop skill install` writes loose files + plugin bundle; `/dop-use` bundled; done-screen guidance points at it. `reset --purge` tears both down. |
| 23 | [Admin Invite Lifecycle](23_invite_lifecycle.md) | Fire-and-forget `dop team invite` + `approve-invite` + `cancel-invite`. TUI Team tabs Members / Pending, `a` approve, `d` delete. |
| 24 | [TUI Screen Walk](24_tui_screen_walk.md) | `TestWalkScreens` dumps every screen; `index.txt` + tags; one-key connectivity; check rules; lab / compare review. |
| 25 | [Bearer Re-issue](25_bearer_reissue.md) | One re-issue path for repin, `portable --on`, rotate: eligibility by binding, old record fate, stash carry-over, passphrase, output, audit. |

## Status

- 01-12 are foundational (pre-v1.13). Updated in-place as features landed.
- 13-18 are v1.13 additions. Written against the `generate-contract.md` prompt.
- 19 is v1.14.0-rc1 (`dop use` + portable).
- 20-23 are v1.14.0+ (rc6–rc7p). TrustContext cache, update CLI, plugin packaging, fire-and-forget invite.
- 24-25 are v1.14 `feature/tui-flow-v2` (TUI distill + portable toggle). 14 rewritten for the distilled TUI; 02, 06, 10, 13, 15-19, 21-23 updated in the same audit.
- Last audit: TUI distill / portable toggle / repin re-issue (after `ca3bb04`).

## When to add a new contract

- A new user-visible feature with observable invariants (schema fields, event kinds, UI patterns, protocol shape).
- A pattern that's been reused ≥ 3 times and now needs to be pinned so future features don't reinvent it.

## When to update an existing contract

- Prefer updates over new numbers when the new feature extends an existing scope.
- When a contract is extended with a new section, link forward to the new contract that owns the detail (e.g. 03 points at 15 + 16).

## Review cadence

Before shipping any `rcN` release, scan the index + the touched contracts. If the code drifted from the contract, update the contract (if the code is right) OR fix the code (if the contract is still right).
