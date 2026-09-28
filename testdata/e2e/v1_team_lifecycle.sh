#!/usr/bin/env bash
# Batch 2: dop team add-key / list / remove with rotation checklist.

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

echo "=== [1] setup + seed integration"
printf "%s\n%s\n" "$PASS" "$PASS-approve" | "$DOP" admin init --passphrase-stdin >/dev/null
"$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null
"$DOP" integration add --name notion --token "read=ntn_ro_X:read-only" >/dev/null 2>&1

echo "=== [2] team add-key"
TEAM_KEY="$WORKROOT/teammate.age"
age-keygen -o "$TEAM_KEY" 2>/dev/null
TEAM_PUB=$(grep '^# public key:' "$TEAM_KEY" | awk '{print $NF}')
"$DOP" team add-key --name teammate --pubkey "$TEAM_PUB" --note "e2e test" 2>&1 | tail -3
pass "add-key succeeded"

echo "=== [3] team list shows both admins"
out=$("$DOP" team list 2>/dev/null)
echo "$out" | grep -q "teammate" || fail "teammate missing"
count=$(echo "$out" | grep -c "^-" || true)
[[ "$count" -ge 2 ]] || fail "expected ≥ 2 admins, got $count"
pass "team list works"

echo "=== [4] team remove (dry run) prints checklist"
out=$("$DOP" team remove --name teammate 2>&1)
echo "$out" | grep -qi "rotation required\|rotate" || fail "no rotation warning"
echo "$out" | grep -q "notion.tokens.read" || fail "checklist missing notion token"
echo "$out" | grep -qi "dry run" || fail "not marked as dry run"
# Confirm nothing changed.
"$DOP" team list 2>/dev/null | grep -q "teammate" || fail "dry-run actually removed!"
pass "dry-run printed checklist, no changes"

echo "=== [5] team remove --force actually removes"
"$DOP" team remove --name teammate --force >/dev/null 2>&1
"$DOP" team list 2>/dev/null | grep -q "teammate" && fail "still listed after --force"
pass "force-remove worked"

echo "=== [6] logout"
"$DOP" admin logout >/dev/null 2>&1
sleep 0.3

echo ""
echo "V1 team lifecycle e2e: PASS"
