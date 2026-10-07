# GIF 0 — hero: issue a scoped bearer to an agent (README).
#
# Records the real TUI against the throwaway install (contract 26):
#   docs/media/record.sh issue    # resets /tmp/dop-demo, then records
# Guide: _rules/_requirements/vhs_recording_guide.md
#
# Needs `dop` ≥ v1.17 on PATH (DOP_HOME + DOP_RECORDING).
# Note: the success screen copies the demo handoff to your clipboard.

Output "docs/media/out/issue.gif"

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

# Launch off-camera.
Hide
Type "dop" Enter
Sleep 2s
Show

Sleep 1.2s

# 2 = Issue (pulls the team vault first).
Type "2"
Sleep 1.5s

Type "research-agent"
Sleep 600ms
Enter
Sleep 1.2s

# Grants: linear.read + notion.read.
Down
Sleep 300ms
Down
Sleep 300ms
Space
Sleep 500ms
Down
Sleep 300ms
Space
Sleep 1s
Enter
Sleep 1.2s

# Expiry: default preset.
Enter
Sleep 1s

# Portable: no.
Enter
Sleep 1.5s

# Review → issue.
Enter
Sleep 4s
