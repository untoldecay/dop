#!/usr/bin/env bash
# V1.9.7 e2e: `dop env` must enforce the same binding gate as `dop exec`.
# Before v1.9.7, an unclaimed bearer could `dop env` and read plaintext
# secrets — bypassing the whole point of PIN-claim binding.

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "V1.9.7 e2e: no dop at $DOP" >&2; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v197-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
mkdir -p "$HOME"
export DOP_NO_TUI=1
export DOP_NO_KEYCHAIN=1
export DOP_NO_NOTIFY=1

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
    tokens: {read: {value: "SECRET_VALUE_DO_NOT_LEAK"}}
grants:
  notion.read: {integration: notion, token: read, env_prefix: NOTION}
EOF

echo "=== [2] issue a PIN-bound token (default)"
issue_out=$("$DOP" token issue --grants notion.read --name envtest 2>&1)
BEARER=$(echo "$issue_out" | grep -E '^tok_1' | head -1)
[[ -n "$BEARER" ]] || fail "no bearer"
pass "issued bearer=${BEARER:0:16}…"

echo "=== [3] BEFORE claim: dop env must REFUSE and NOT print the secret"
env_out=$(DOP_TOKEN="$BEARER" "$DOP" env 2>&1 || true)
if echo "$env_out" | grep -q "SECRET_VALUE_DO_NOT_LEAK"; then
    echo "=== LEAK ==="
    echo "$env_out"
    fail "dop env printed the plaintext secret without a completed claim"
fi
if ! echo "$env_out" | grep -qi "requires a PIN claim\|bearer requires\|binding"; then
    echo "$env_out"
    fail "dop env did not surface a binding-required error"
fi
pass "dop env refused unclaimed bearer + did NOT leak the secret"

echo "=== [4] audit log records the denial"
grep -q '"event":"env_denied"' "$LOG" 2>/dev/null || fail "no env_denied audit event"
pass "env_denied audit event present"

echo "=== [5] complete the claim (skip approval for the test)"
PIN=$(echo "$issue_out" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
DOP_TOKEN="$BEARER" "$DOP" claim --skip-approval "$PIN" >/dev/null 2>&1 || fail "claim failed"
pass "claim complete"

echo "=== [6] AFTER claim: dop env succeeds and prints the value"
env_out=$(DOP_TOKEN="$BEARER" "$DOP" env 2>&1)
echo "$env_out" | grep -q "SECRET_VALUE_DO_NOT_LEAK" || { echo "$env_out"; fail "post-claim env didn't print value"; }
pass "post-claim env prints the value"

echo "=== [7] env audit event recorded"
grep -q '"event":"env"' "$LOG" 2>/dev/null || fail "no env audit event after successful call"
pass "env audit event present"

pkill -9 -f "dop admin __session-daemon" 2>/dev/null || true
echo "V1.9.7 env-binding e2e: PASS"
