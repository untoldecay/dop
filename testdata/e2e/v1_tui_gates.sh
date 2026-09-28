#!/usr/bin/env bash
# V1 TUI gating tests. The interactive Bubble Tea flow isn't driven here
# (that requires teatest); this covers the launch decision.

set -euo pipefail
DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "no dop"; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

echo "=== [1] no TTY on stdin → prints usage, no hang"
out=$("$DOP" < /dev/null 2>&1 || true)
echo "$out" | grep -q "Doors of Perception" || fail "no usage banner"
pass "usage printed without hang"

echo "=== [2] DOP_NO_TUI=1 prevents launch even on TTY"
out=$(DOP_NO_TUI=1 "$DOP" 2>&1 || true)
echo "$out" | grep -q "Doors of Perception" || fail "no usage banner under DOP_NO_TUI"
pass "DOP_NO_TUI suppresses"

echo "=== [3] --help still works"
"$DOP" help | grep -q "dop admin login" || fail "help missing"
pass "help subcommand intact"

echo ""
echo "V1 TUI gates e2e: PASS"
