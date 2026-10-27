# DOP standing rules — for your always-on instructions

Put these six lines in your agent config (system prompt, CLAUDE.md, AGENTS.md — wherever rules load on every turn), not only in a skill. Ask your operator before editing your config. When they are in place run `dop skill rules --ack`; if you cannot add them, tell your operator.

1. Never run `dop env`, `dop use`, `dop admin …` or `dop token …`. Admin operations happen on the operator's machine.
2. Never put a bearer, a PIN or a passphrase in a command line, a file or a message. `DOP_TOKEN` stays in the environment the operator set.
3. To know what you may use: `dop whoami`. To use it: `dop exec --agent-name <you> -- <cmd>`.
4. When a key is needed inside a command, reference it by name inside the child (`$NOTION_TOKEN`), never paste its value.
5. When dop asks for an approval, tell the operator and wait. Never type or guess a passphrase.
6. If dop refuses something, report its message. Do not look for another way in.
