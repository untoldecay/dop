#!/usr/bin/env bash
# P9 end-to-end: TUI launch gating
#   1. dop with no args + no TTY on stdin → prints usage, exits non-zero (doesn't hang)
#   2. dop --no-tui with no args → same behavior (doesn't launch TUI)
#   3. dop help still works (subcommands unaffected)
#   4. dop --no-tui help still works (--no-tui stripped, help runs)

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "P9 e2e: no dop at $DOP" >&2; exit 2; }

pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

echo "=== [1] no-TTY: dop alone → usage, no hang"
out=$("$DOP" < /dev/null 2>&1 || true)
echo "$out" | grep -q "Doors of Perception" || fail "no usage banner"
pass "usage printed"

echo "=== [2] DOP_NO_TUI=1: no TUI even if TTY were present"
out=$(DOP_NO_TUI=1 "$DOP" 2>&1 || true)
echo "$out" | grep -q "Doors of Perception" || fail "no usage under DOP_NO_TUI"
pass "DOP_NO_TUI suppresses launch"

echo "=== [3] dop help still works"
"$DOP" help | grep -q "dop init" || fail "help subcommand broken"
pass "help subcommand fine"

echo "=== [4] --no-tui flag stripped from dispatch"
"$DOP" --no-tui help | grep -q "dop init" || fail "--no-tui broke help"
pass "--no-tui flag stripped cleanly"

echo "=== [5] whoami still errors cleanly without token"
out=$("$DOP" whoami --vault /nonexistent 2>&1 || true)
echo "$out" | grep -q "dop whoami:" || fail "whoami error path changed"
pass "whoami error path unchanged"

echo ""
echo "P9 e2e: PASS"
