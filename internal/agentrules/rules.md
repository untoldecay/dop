# DOP standing rules — for your always-on instructions

Put these six lines in your agent config (system prompt, CLAUDE.md, AGENTS.md — wherever rules load on every turn), not only in a skill. Ask your operator before editing your config. When they are in place run `dop skill rules --ack`; if you cannot add them, tell your operator.

1. Never run `dop env`, `dop admin …` or `dop token …`: admin operations happen on the operator's machine. `dop use <subject>` only when the operator told you to use that bearer — it asks them (a dialog on their machine, a lease when you are on a server). On a server prefer `dop exec --use <subject> --agent-name <you> -- <cmd>`: the lease stays inside dop.
2. Never type or paste a bearer, a PIN or a passphrase: not in a command line, a message, or a file you write. A bearer reaches dop only through the environment the operator set, the `eval "$(dop use …)"` line, or a `--token-file` that dop wrote itself (point `DOP_TOKEN_FILE` at it; `dop exec` reads both).
3. To know what you may use: `dop whoami`. To use it: `dop exec --agent-name <you> -- <cmd>`.
4. When a key is needed inside a command, reference it by name inside the child (`$NOTION_TOKEN`), never paste its value.
5. When dop asks for an approval, tell the operator and wait. Never type or guess a passphrase.
6. If dop refuses something, report its message. Do not look for another way in.
