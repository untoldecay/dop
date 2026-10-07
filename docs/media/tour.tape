# Tour — one agent's whole lifecycle in five titled sections (README hero).
#
#   docs/media/record.sh tour     # resets /tmp/dop-demo, then records
# Guide: _rules/_requirements/vhs_recording_guide.md
#
# Story: add Slack → issue research-agent (portable) → the agent runs a
# command with only its grants → add a grant → revoke it.
# Navigation is shown key by key (no number shortcuts) so viewers can follow.
# Section cards: docs/media/title.sh (TUI title style), held until a key.
# Note: the issue success screen copies the demo handoff to your clipboard.

Output "docs/media/out/tour.gif"

Require dop

Set Shell "bash"
Set FontSize 14
Set Width 740
Set Height 520
Set Padding 20
Set TypingSpeed 45ms
Set CursorBlink false
# Plays 1.4× faster than recorded: ~60 s total. Card holds are sized for it.
Set PlaybackSpeed 1.4

Env DOP_HOME "/tmp/dop-demo"
Env DOP_RECORDING "1"
# Demo approval passphrase (setup-demo.sh) — `dop use` asks for approval once per session.
Env DOP_APPROVAL_PASSPHRASE "demo-approve-passphrase"

Hide
Type "export PS1='$ '; clear" Enter
Sleep 300ms

# ── 1 · Add a service ─────────────────────────────────────────────
Type "docs/media/title.sh 'Add a service' '1 of 5' 'Store the key once, in your encrypted git vault.'" Enter
Sleep 500ms
Show
Sleep 2.4s
Hide
Type " "
Type "dop" Enter
Sleep 2s
Show

Sleep 800ms
# Menu: cursor already on Add.
Enter
Sleep 900ms
# Add › Integration.
Enter
Sleep 1.5s
# New integration.
Enter
Sleep 1s
# Integration: name.
Enter
Type "slack"
Enter
Sleep 500ms
Down Down Down Down Down
Sleep 400ms
Enter
Sleep 1.2s
# Credential: rename to bot, paste the key (masked).
Enter
Backspace 10
Type "bot"
Enter
Sleep 300ms
Enter
Type "xoxb-demo-0000-not-a-real-token"
Enter
Sleep 700ms
Down Down Down Down Down
Sleep 300ms
Enter
Sleep 1.5s
# Grant: auto-named slack.read-only → Review.
Down Down Down Down Down Down Down Down
Sleep 300ms
Enter
Sleep 1.8s
# Save.
Enter
Sleep 2.8s

Hide
Enter
Sleep 800ms
Type "q"
Sleep 800ms

# ── 2 · Issue a scoped bearer ─────────────────────────────────────
Type "docs/media/title.sh 'Issue a scoped bearer' '2 of 5' 'Only the grants it needs, for as long as it needs them.'" Enter
Sleep 500ms
Show
Sleep 2.4s
Hide
Type " "
Type "dop" Enter
Sleep 2s
Show

Sleep 800ms
Down
Sleep 700ms
Enter
Sleep 1.5s
Type "research-agent"
Sleep 400ms
Enter
Sleep 1.2s
# Grants: notion.read + slack.read-only.
Down
Sleep 250ms
Down
Sleep 250ms
Down
Sleep 400ms
Space
Sleep 500ms
Down
Sleep 250ms
Down
Sleep 400ms
Space
Sleep 900ms
Enter
Sleep 1.2s
# Expiry: default.
Enter
Sleep 1s
# Portable: yes (lets you use it from any shell, and edit its grants later).
Down
Sleep 700ms
Enter
Sleep 1.5s
# Review → issue.
Enter
Sleep 3.2s

Hide
Enter
Sleep 800ms
Type "q"
Sleep 800ms

# ── 3 · Hand it to your agent ─────────────────────────────────────
Type "docs/media/title.sh 'Hand it to your agent' '3 of 5' 'The command sees its scoped keys. Nothing else.'" Enter
Sleep 500ms
Show
Sleep 2.4s
Hide
Type " "
Sleep 300ms
Show

Sleep 600ms
Type 'eval "$(dop use research-agent)"'
Sleep 400ms
Enter
Sleep 1.2s
Type "dop exec -- printenv SLACK_BOT_TOKEN"
Sleep 400ms
Enter
Sleep 2s
Type "dop exec -- printenv GITHUB_TOKEN || echo '(not granted)'"
Sleep 400ms
Enter
Sleep 2.8s

Hide
Type "clear" Enter
Sleep 300ms

# ── 4 · Grow its access ───────────────────────────────────────────
Type "docs/media/title.sh 'Grow its access' '4 of 5' 'Add or remove grants. No new bearer to hand over.'" Enter
Sleep 500ms
Show
Sleep 2.4s
Hide
Type " "
Type "dop" Enter
Sleep 2s
Show

Sleep 800ms
# List.
Down
Sleep 300ms
Down
Sleep 500ms
Enter
Sleep 900ms
# List › Bearers.
Down
Sleep 300ms
Down
Sleep 500ms
Enter
Sleep 2.5s
# research-agent.
Down
Sleep 600ms
Enter
Sleep 1.5s
# Grants tab → add.
Tab
Sleep 1.2s
Type "a"
Sleep 1.2s
# linear.read.
Down
Sleep 250ms
Down
Sleep 400ms
Space
Sleep 700ms
Enter
Sleep 3s

Hide
Enter
Sleep 1.2s
Escape
Sleep 600ms
Type "q"
Sleep 800ms

# ── 5 · Revoke it ─────────────────────────────────────────────────
Type "docs/media/title.sh 'Revoke it' '5 of 5' 'One key. It fails on its next call.'" Enter
Sleep 500ms
Show
Sleep 2.4s
Hide
Type " "
Type "dop" Enter
Sleep 2s
Show

Sleep 800ms
Down
Sleep 300ms
Down
Sleep 500ms
Enter
Sleep 900ms
Down
Sleep 300ms
Down
Sleep 500ms
Enter
Sleep 2.5s
# research-agent.
Down
Sleep 600ms
Enter
Sleep 1.8s
# Actions: Reseal env · Repin · Portable · Revoke.
Down
Sleep 300ms
Down
Sleep 300ms
Down
Sleep 700ms
Enter
Sleep 1.8s
# Confirm.
Enter
Sleep 2.2s
# Back to the list: research-agent gone, Revoked 1.
Enter
Sleep 3.5s
