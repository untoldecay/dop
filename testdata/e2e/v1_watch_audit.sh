#!/usr/bin/env bash
# V1.4 e2e: audit log + `dop watch` --no-follow backfill.
# We don't test the follow loop or macOS notifications — those are
# manual verifications.

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "V1.4 e2e: no dop at $DOP" >&2; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v14-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
mkdir -p "$HOME"
export DOP_NO_TUI=1
export DOP_NO_NOTIFY=1   # skip macOS banners in tests

PASS="pass-word-long-enough"
CFG_ROOT="$HOME/Library/Application Support/dop"
VAULT_DIR="$CFG_ROOT/vault"
LOG="$CFG_ROOT/logs/audit.jsonl"

echo "=== [1] setup"
printf "%s\n%s\n" "$PASS" "$PASS-approve" | "$DOP" admin init --passphrase-stdin >/dev/null
"$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null
cat > "$VAULT_DIR/vault.yaml" <<'EOF'
schema_version: v1
integrations:
  notion:
    metadata: {base_url: "https://api.notion.com/v1"}
    tokens: {read: {value: "ntn_xxx"}}
grants:
  notion.read: {integration: notion, token: read, env_prefix: NOTION}
EOF

echo "=== [2] issue → audit log entry"
issue_out=$("$DOP" token issue --grants notion.read --name auditagent 2>&1)
BEARER=$(echo "$issue_out" | grep -E '^tok_1' | head -1)
PIN=$(echo "$issue_out" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
[[ -f "$LOG" ]] || fail "audit log not created"
grep -q '"event":"issue"' "$LOG" || fail "issue event missing"
grep -q '"subject":"auditagent"' "$LOG" || fail "subject missing"
pass "issue logged"

echo "=== [3] claim → audit log entry"
DOP_TOKEN="$BEARER" "$DOP" claim --skip-approval "$PIN" >/dev/null 2>&1 || fail "claim failed"
grep -q '"event":"claim"' "$LOG" || fail "claim event missing"
pass "claim logged"

echo "=== [4] wrong PIN → claim_denied entry"
issue2=$("$DOP" token issue --grants notion.read --name auditB 2>&1)
B2=$(echo "$issue2" | grep -E '^tok_1' | head -1)
DOP_TOKEN="$B2" "$DOP" claim --skip-approval WRONG-XX-YZ 2>/dev/null || true
grep -q '"event":"claim_denied"' "$LOG" || fail "claim_denied missing"
grep -q '"reason":"pin_mismatch"' "$LOG" || fail "reason missing"
pass "denied logged"

echo "=== [5] revoke → audit log entry"
"$DOP" token revoke auditagent >/dev/null 2>&1
grep -q '"event":"revoke"' "$LOG" || fail "revoke event missing"
pass "revoke logged"

echo "=== [6] dop watch --follow=false backfills"
out=$("$DOP" watch --follow=false --all --no-color 2>&1)
echo "$out" | grep -q "issue" || { echo "$out"; fail "watch didn't show issue"; }
echo "$out" | grep -q "claim" || fail "watch didn't show claim"
echo "$out" | grep -q "revoke" || fail "watch didn't show revoke"
pass "watch backfill works"

echo "=== [7] dop watch --filter=claim only shows claim events"
out=$("$DOP" watch --follow=false --all --no-color --filter=claim 2>&1)
echo "$out" | grep -q " claim " || fail "filter=claim should include claim"
if echo "$out" | grep -q " issue "; then
    fail "filter=claim leaked issue event"
fi
pass "filter works"

echo ""
echo "V1.4 watch/audit e2e: PASS"
