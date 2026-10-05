---
description: Activate a DOP portable bearer (leak-safe) and run a credentialed task with it
argument-hint: <bearer-subject> [task to run]
---

Activate the DOP portable bearer **$1** and carry out the task below with it.

Task: $ARGUMENTS
(The first token is the bearer subject `$1`; the rest is the task to perform.)

Follow the DOP credential-access safety protocol exactly:

- **Never** run bare `! dop use $1` — its stdout is `export DOP_TOKEN=…`, which would leak the bearer into the transcript on disk.
- Shell state does **not** persist across tool calls, so in **every** Bash call that needs credentials, inline the activation:
  ```bash
  eval "$(dop use $1)" && <your command>
  ```
- Run the actual credentialed command through `dop exec --agent-name <specific-task-label> -- <command>` so the scoped env is injected only into the child process.
- First confirm what the bearer unlocks:
  ```bash
  eval "$(dop use $1)" && dop whoami
  ```
- If the auto-mode classifier blocks `dop use`/`dop exec`, stop and ask the user to approve (or to add a Bash allow-rule for `dop use` / `dop exec`). Do not try to work around it.
- Do not print `DOP_TOKEN` or any bearer value into chat or logs.
