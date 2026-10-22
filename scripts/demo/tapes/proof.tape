# Reply clip: the key is really in the process; revoke is one line.
# Needs an active admin session (stage.sh leaves one). Revokes buzz-reader:
# run stage.sh again before any other tape that uses the agent.
Output dop-exec-proof-light.mp4
Output dop-exec-proof-light.gif
Source common.tape
Env DOP_NO_TUI "1"
Hide
Type "clear"
Enter
Sleep 300ms
Show
Sleep 700ms
Type "# Is the key really there?"
Sleep 400ms
Enter
Type "# Ask the process, not the transcript:"
Sleep 600ms
Enter
Sleep 300ms
Type `dop exec --agent-name buzz-reader \`
Enter
Type `  -- sh -c 'echo len: ${#NOTION_TOKEN}'`
Sleep 600ms
Enter
Sleep 3200ms
Type "# Done with that agent:"
Sleep 600ms
Enter
Sleep 300ms
Type "dop token revoke buzz-reader"
Sleep 600ms
Enter
Sleep 3800ms
