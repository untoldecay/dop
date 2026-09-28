#!/usr/bin/env bash
# Batch 1: `dop integration add` + `dop grant add` end-to-end.

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

echo "=== [1] setup"
echo -n "$PASS" | "$DOP" admin init --passphrase-stdin >/dev/null
"$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null

echo "=== [2] integration add"
"$DOP" integration add \
    --name notion \
    --base-url "https://api.notion.com/v1" \
    --description "Notion" \
    --token "read=ntn_ro_XXX:read-only" \
    --token "write=ntn_rw_YYY:read+write" 2>&1 | tail -3
pass "add succeeded"

echo "=== [3] second add (update-in-place)"
"$DOP" integration add \
    --name notion \
    --base-url "https://api.notion.com/v1" \
    --token "read=ntn_ro_NEW:read-only" 2>&1 | grep -q "updated" || fail "second add didn't say 'updated'"
pass "in-place update"

echo "=== [4] grant add"
"$DOP" grant add --id notion.read --integration notion --token read 2>&1 | tail -3
pass "grant added"

echo "=== [5] grant add with unknown token → clean error"
out=$("$DOP" grant add --id bad --integration notion --token missing 2>&1 || true)
echo "$out" | grep -q "no token" || fail "unknown token error message wrong: $out"
pass "unknown token errored"

echo "=== [6] grant add with unknown integration → clean error"
out=$("$DOP" grant add --id bad --integration missing --token read 2>&1 || true)
echo "$out" | grep -q "unknown integration" || fail "unknown integration error wrong: $out"
pass "unknown integration errored"

echo "=== [7] issue against the fresh integration + grant"
BEARER=$("$DOP" token issue --grants notion.read --name test 2>/dev/null)
[[ "$BEARER" == tok_1* ]] || fail "no bearer"
env_out=$(DOP_TOKEN="$BEARER" "$DOP" exec --agent-name t -- env 2>/dev/null)
echo "$env_out" | grep -q "NOTION_TOKEN=ntn_ro_NEW" || fail "wrong token value in env"
pass "issue + exec end-to-end"

echo "=== [8] logout"
"$DOP" admin logout >/dev/null 2>&1
sleep 0.3

echo "=== [9] integration add refused without session"
out=$("$DOP" integration add --name x --token "y=z:read-only" 2>&1 || true)
echo "$out" | grep -q "no active admin session" || fail "session-required not enforced: $out"
pass "session-required enforced"

echo ""
echo "V1 integration/grant e2e: PASS"
