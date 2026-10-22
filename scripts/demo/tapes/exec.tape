# Main clip: the agent runs with the key, the transcript sees a mask.
Output dop-exec-light.mp4
Output dop-exec-light.gif
Source common.tape
Env DOP_NO_TUI "1"
Hide
Type "clear"
Enter
Sleep 300ms
Show
Sleep 700ms
Type "# The agent gets the Notion key."
Sleep 400ms
Enter
Type "# The transcript gets this:"
Sleep 600ms
Enter
Sleep 300ms
Type `dop exec --agent-name buzz-reader \`
Enter
Type "  -- env | grep NOTION_TOKEN"
Sleep 600ms
Enter
Sleep 3800ms
Type "clear"
Sleep 300ms
Enter
Sleep 500ms
Type "# What does this mean?"
Sleep 400ms
Enter
Type "# Your key never touched the transcript."
Sleep 400ms
Enter
Type "# dop injected it into the process,"
Enter
Type "# and masked it on the way out."
Sleep 3200ms
Enter
Type "clear"
Sleep 300ms
Enter
Sleep 500ms
Type "# This is dop."
Sleep 500ms
Enter
Type "# github.com/untoldecay/dop"
Sleep 3500ms
