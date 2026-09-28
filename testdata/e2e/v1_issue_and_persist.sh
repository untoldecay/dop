#!/usr/bin/env bash
# V1 Phase 3 e2e: admin session issues a capability; vault + bundle land on disk.

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "V1 e2e: no dop at $DOP" >&2; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v1-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
mkdir -p "$HOME"
export DOP_NO_TUI=1

PASS="pass-word-with-length"
CFG_ROOT="$HOME/Library/Application Support/dop"
VAULT_DIR="$CFG_ROOT/vault"

echo "=== [1] admin init"
echo -n "$PASS" | "$DOP" admin init --passphrase-stdin >/dev/null

echo "=== [2] init --vault (local bare bootstrap)"
BARE="$WORKROOT/bare"
"$DOP" init --vault "$BARE" >/dev/null 2>&1
[[ -d "$VAULT_DIR" ]] || fail "vault dir missing"

echo "=== [3] admin login"
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null

echo "=== [4] seed integrations into the vault (via dop vault edit is Phase 5; write directly for now)"
# Provide a plaintext vault.yaml so token issue has grants to resolve.
# The next admin op will re-encrypt it.
cat > "$VAULT_DIR/vault.yaml" <<'EOF'
schema_version: v1
integrations:
  notion:
    description: "test"
    metadata:
      base_url: "https://api.notion.com/v1"
    tokens:
      read:
        value: "ntn_secret_ro"
        scope_note: "read-only"
grants:
  notion.read:
    integration: notion
    token: read
    env_prefix: NOTION
EOF

echo "=== [5] token issue (admin required)"
BEARER=$("$DOP" token issue --grants notion.read --name test-agent 2>/dev/null || true)
if [[ -z "$BEARER" ]]; then
    # Re-run capturing stderr to diagnose
    "$DOP" token issue --grants notion.read --name test-agent 2>&1 | tail -5
    fail "no bearer emitted"
fi
[[ "$BEARER" == tok_1* ]] || fail "bearer wrong shape: $BEARER"
pass "bearer issued: $BEARER"

echo "=== [6] vault re-encrypted"
grep -q "^sops:" "$VAULT_DIR/vault.yaml" || fail "vault not encrypted after issue"
grep -q "ENC\\[AES256" "$VAULT_DIR/vault.yaml" || fail "no ENC values"
pass "vault SOPS-wrapped"

echo "=== [7] capability bundle exists"
ls "$VAULT_DIR/capabilities" >/dev/null 2>&1 || fail "no capabilities dir"
BUNDLES=$(ls "$VAULT_DIR/capabilities" | wc -l | tr -d ' ')
[[ "$BUNDLES" == "1" ]] || fail "expected 1 bundle, got $BUNDLES"
pass "bundle written"

echo "=== [8] token list shows the capability"
"$DOP" token list 2>/dev/null | grep -q "test-agent" || fail "list didn't show subject"
pass "list works"

echo "=== [9] token revoke marks it revoked and deletes bundle"
"$DOP" token revoke test-agent 2>/dev/null
BUNDLES=$(ls "$VAULT_DIR/capabilities" 2>/dev/null | wc -l | tr -d ' ')
[[ "$BUNDLES" == "0" ]] || fail "bundle not deleted"
"$DOP" token list 2>/dev/null | grep -q "revoked" || fail "list didn't show revoked status"
pass "revoke worked"

echo "=== [10] admin logout"
"$DOP" admin logout >/dev/null
sleep 0.3   # daemon has a 50ms grace period after OK before Shutdown

echo "=== [11] issuing without an active session fails"
if "$DOP" token issue --grants notion.read --name after-logout 2>/dev/null; then
    fail "issue without session should have failed"
fi
pass "unlocked issue refused"

echo ""
echo "V1 Phase 3 e2e: PASS"
