#!/usr/bin/env bash
# Batch 3: integration + grant list/remove.

set -euo pipefail
DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "no dop"; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v1-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
mkdir -p "$HOME"
export DOP_NO_TUI=1
PASS="the-passphrase-15chars"

echo "=== [1] setup + seed"
printf "%s\n%s\n" "$PASS" "$PASS-approve" | "$DOP" admin init --passphrase-stdin >/dev/null
"$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null
"$DOP" integration add --name notion --base-url "https://api.notion.com/v1" \
    --token "read=ntn_ro:read-only" --token "write=ntn_rw:read+write" >/dev/null 2>&1
"$DOP" integration add --name boiler --token "read=blr_ro:read-only" >/dev/null 2>&1
"$DOP" grant add --id notion.read --integration notion --token read >/dev/null 2>&1
"$DOP" grant add --id boiler.read --integration boiler --token read >/dev/null 2>&1

echo "=== [2] integration list"
out=$("$DOP" integration list 2>/dev/null)
echo "$out" | grep -q "notion" || fail "notion missing"
echo "$out" | grep -q "boiler" || fail "boiler missing"
# Values NOT shown
if echo "$out" | grep -q "ntn_ro"; then fail "token values leaked!"; fi
pass "list works, no value leak"

echo "=== [3] grant list"
"$DOP" grant list | grep -q "notion.read" || fail "grant missing"
pass "grant list works"

echo "=== [4] integration remove without --force → refused (grants reference it)"
out=$("$DOP" integration remove --name notion 2>&1 || true)
echo "$out" | grep -q "grants still reference" || fail "should have refused"
pass "protective refusal"

echo "=== [5] integration remove --force cascades to grants"
"$DOP" integration remove --name notion --force >/dev/null 2>&1
"$DOP" integration list | grep -q "notion" && fail "notion still there"
"$DOP" grant list | grep -q "notion.read" && fail "grant not cascade-removed"
pass "force cascade worked"

echo "=== [6] grant remove"
"$DOP" grant remove --id boiler.read >/dev/null 2>&1
"$DOP" grant list | grep -q "boiler.read" && fail "grant still there"
pass "grant remove worked"

echo "=== [7] logout"
"$DOP" admin logout >/dev/null 2>&1
sleep 0.3

echo ""
echo "V1 lifecycle ops e2e: PASS"
