#!/usr/bin/env bash
# V1.12 e2e (M4): transparent bearer rotation.
# Prove `dop token rotate` produces a new bearer, wraps it via ECDH
# to the agent's P-256 pubkey on the OLD record, and the agent's next
# `dop exec --token-file` decrypts + auto-migrates transparently.

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "V1.12 e2e: no dop at $DOP" >&2; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v1210-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
mkdir -p "$HOME"
export DOP_NO_TUI=1
export DOP_NO_KEYCHAIN=1
export DOP_ALLOW_FILE_KEYS=1

PASS="pass-word-long-enough"
CFG_ROOT="$HOME/Library/Application Support/dop"
VAULT_DIR="$CFG_ROOT/vault"

echo "=== [1] setup + seed"
printf "%s\n%s\n" "$PASS" "$PASS-approve" | "$DOP" admin init --passphrase-stdin >/dev/null
"$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null
cat > "$VAULT_DIR/vault.yaml" <<'EOF'
schema_version: v1
integrations:
  slack: {metadata: {}, tokens: {bot: {value: "xoxb-value"}}}
grants:
  slack.bot: {integration: slack, token: bot, env_prefix: SLACK}
EOF
pass "seeded"

echo "=== [2] issue + claim P-256, write bearer to a token file"
TOKFILE="$WORKROOT/bearer.tok"
OUT=$("$DOP" token issue --grants slack.bot --name rotator 2>&1)
BEARER=$(echo "$OUT" | grep -E '^tok_1' | head -1)
PIN=$(echo "$OUT" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
[[ -n "$BEARER" && -n "$PIN" ]] || fail "no bearer/PIN"
echo -n "$BEARER" > "$TOKFILE"
chmod 600 "$TOKFILE"
"$DOP" claim --token-file "$TOKFILE" --skip-approval --key-type p256 "$PIN" >/dev/null 2>&1 \
  || fail "claim failed"
pass "issued + claimed to $TOKFILE"

echo "=== [3] exec via token-file — baseline env"
"$DOP" env --token-file /dev/null 2>&1 >/dev/null || true # sanity: env cmd doesn't take --token-file
# Just use DOP_TOKEN for baseline env check (env cmd defaults from DOP_TOKEN)
E1=$(DOP_TOKEN="$BEARER" "$DOP" env 2>&1)
echo "$E1" | grep -q "SLACK_TOKEN='xoxb-value'" || fail "baseline env missing: $E1"
pass "baseline SLACK_TOKEN visible"

echo "=== [4] admin runs dop token rotate"
OUT_ROT=$("$DOP" token rotate rotator 2>&1)
echo "$OUT_ROT" | grep -q "rotated rotator" || fail "rotate output missing: $OUT_ROT"
echo "$OUT_ROT" | grep -q "BearerWrapped attached" || fail "rotate didn't say BearerWrapped: $OUT_ROT"
pass "admin rotate succeeded"

echo "=== [5] token show now sees NEW record for the subject (active)"
SHOW=$("$DOP" token show rotator --json 2>&1)
NEW_LOOKUP=$(echo "$SHOW" | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['lookup_id'])")
[[ -n "$NEW_LOOKUP" ]] || fail "no new lookup in token show: $SHOW"
pass "new lookup: ${NEW_LOOKUP:0:12}"

echo "=== [6] agent exec via --token-file: auto-decrypts BearerWrapped + rewrites file"
# Use dop exec (not env) with --token-file to trigger the rotation path.
set +e
OUT_EXEC=$("$DOP" exec --inherit-env --token-file "$TOKFILE" --agent-name rot-driver -- sh -c 'echo "GOT=$SLACK_TOKEN"' 2>&1)
EX_EXEC=$?
set -e
echo "$OUT_EXEC" | grep -q "wrote rotated bearer to" || fail "exec didn't announce rotation (exit $EX_EXEC): $OUT_EXEC"
echo "$OUT_EXEC" | grep -q "GOT=xoxb-value" || fail "exec didn't get env after rotation (exit $EX_EXEC): $OUT_EXEC"
pass "auto-rotation ran end-to-end, env delivered"

echo "=== [7] token file now contains the NEW bearer (different from BEARER)"
NEW_BEARER=$(cat "$TOKFILE")
[[ "$NEW_BEARER" != "$BEARER" ]] || fail "token file NOT updated (still holds old bearer)"
[[ "${NEW_BEARER:0:5}" == "tok_1" ]] || fail "new bearer has wrong shape: $NEW_BEARER"
pass "token file rotated: ${NEW_BEARER:0:12}…"

echo "=== [8] the OLD bearer is stale — a second exec with old bearer stalls out"
# The .p256 file has been migrated to NEW_LOOKUP. Attempting exec with the OLD
# bearer would compute the OLD lookup id, find the rotated record, try to open
# BearerWrapped — but the SE/file key is gone from the old lookup id → fail.
if DOP_TOKEN="$BEARER" "$DOP" env 2>&1 | grep -q "SLACK_TOKEN"; then
  fail "OLD bearer should NOT produce env after rotation (key migrated)"
fi
pass "old bearer is stale (as expected)"

echo "=== [9] the NEW bearer works cleanly (from token file OR env)"
E2=$(DOP_TOKEN="$NEW_BEARER" "$DOP" env 2>&1)
echo "$E2" | grep -q "SLACK_TOKEN='xoxb-value'" || fail "new bearer failed: $E2"
pass "NEW bearer serves env fine"

echo "=== [10] DOP_TOKEN env rotation warns cleanly (can't rewrite parent env)"
# Rotate again so there's a fresh BearerWrapped.
"$DOP" token rotate rotator >/dev/null 2>&1
# Now try to use the (now-old) NEW_BEARER via env-var — should hit the
# rotation detect, print the new bearer to stderr, and exit non-zero.
if OUT_WARN=$(DOP_TOKEN="$NEW_BEARER" "$DOP" env 2>&1); then
  fail "env-var rotation should have exited non-zero: $OUT_WARN"
fi
echo "$OUT_WARN" | grep -q "Bearer was rotated by admin" || fail "warning missing: $OUT_WARN"
echo "$OUT_WARN" | grep -qE "tok_1[a-f0-9]" || fail "new bearer not printed: $OUT_WARN"
pass "DOP_TOKEN env mode: clear warning + printed new bearer"

echo
echo "V1.12 M4 e2e: ALL PASS — transparent bearer rotation confirmed"
