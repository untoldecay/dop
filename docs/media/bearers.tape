# GIF 4 — see and revoke: open List › Bearers, revoke one (README).
#
#   docs/media/record.sh bearers  # resets /tmp/dop-demo, then records
# Guide: _rules/_requirements/vhs_recording_guide.md

Output "docs/media/out/bearers.gif"

Require dop

Set Shell "bash"
Set FontSize 14
Set Width 740
Set Height 520
Set Padding 20
Set TypingSpeed 70ms
Set CursorBlink false

Env DOP_HOME "/tmp/dop-demo"
Env DOP_RECORDING "1"

Hide
Type "dop" Enter
Sleep 2s
Show

Sleep 1.2s

# 3 = List, 3 = Bearers.
Type "3"
Sleep 800ms
Type "3"
Sleep 2s

# Open triage-bot.
Down
Sleep 600ms
Enter
Sleep 2s

# Actions: Reseal env · Portable · Revoke.
Down
Sleep 400ms
Down
Sleep 800ms
Enter
Sleep 2s

# Confirm.
Enter
Sleep 2.5s

# Back to the list: Active 1 · Revoked 1.
Enter
Sleep 3s
