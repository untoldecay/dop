#!/usr/bin/env bash
# Section title card for stitched tapes (tour.tape). Draws a screen in the
# TUI's own frame style so cards blend with the recording:
#   row 1: title in titleSt (bold, #5c5c5c) · "N of M" in mutedSt (#404040),
#          right-aligned like a screen's context
#   row 3: optional subtitle in bodySt (#5c5c5c)
# Colors mirror internal/tui/tui.go (fg, muted) — keep them in sync.
#
#   docs/media/title.sh "Issue a scoped bearer" "2 of 5" "Only the grants it needs."

title="$1" ctx="${2:-}" sub="${3:-}"
cols=$(stty size </dev/tty 2>/dev/null | cut -d" " -f2); cols=${cols:-80}

fg=$'\e[38;2;92;92;92m'      # #5c5c5c — fg / titleSt / bodySt
muted=$'\e[38;2;64;64;64m'   # #404040 — mutedSt
bold=$'\e[1m' reset=$'\e[0m'

pad=$(( cols - ${#title} - ${#ctx} ))
(( pad < 2 )) && pad=2

printf '\e[2J\e[H\e[?25l'    # clear, home, hide cursor
printf '%s%s%s%s%*s%s%s%s\n' "$bold" "$fg" "$title" "$reset" "$pad" "" "$muted" "$ctx" "$reset"
[[ -n "$sub" ]] && printf '\n%s%s%s\n' "$fg" "$sub" "$reset"

# Hold the card until the tape sends a key (off-camera), then restore.
read -rsn1 _ </dev/tty 2>/dev/null || sleep 5
printf '\e[?25h\e[2J\e[H'
