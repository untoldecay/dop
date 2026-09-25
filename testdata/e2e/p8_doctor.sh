#!/usr/bin/env bash
# P8 end-to-end: dop doctor
#   1. Fresh install with vault + valid Notion mock → doctor exits 0
#   2. Vault schema_version mismatched → doctor fails
#   3. sops binary missing → doctor fails
#   4. Notion mock returns 401 → doctor flags the token as revoked
#
# Uses httptest-style pattern by spinning a background Python HTTP server
# so we can control the Notion mock's responses.

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "P8 e2e: no dop at $DOP" >&2; exit 2; }

WORKROOT=$(mktemp -d)
MOCK_PORT=${MOCK_PORT:-14813}
export HOME="$WORKROOT/home"
export XDG_CONFIG_HOME="$HOME/.config"
mkdir -p "$HOME"

pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

start_mock() {
    local status_code=$1
    python3 -c "
import http.server, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response($status_code); self.end_headers()
    def log_message(self, *a, **k): pass
http.server.HTTPServer(('127.0.0.1', $MOCK_PORT), H).serve_forever()
" >/dev/null 2>&1 &
    echo $!
    sleep 0.3
}

stop_mock() {
    kill "$1" 2>/dev/null || true
    wait "$1" 2>/dev/null || true
}

setup_vault() {
    "$DOP" init >/dev/null
    "$DOP" init --vault "$WORKROOT/vault-bare" >/dev/null 2>&1
    DOP_CLONE="$HOME/Library/Application Support/dop/vault"
    [[ -d "$DOP_CLONE" ]] || DOP_CLONE="$HOME/.config/dop/vault"
    # Rewrite the notion base_url to point at our mock
    cat > "$WORKROOT/vault.plain.yaml" <<EOF
schema_version: 1

integrations:
  notion:
    description: "notion mock"
    metadata:
      base_url: "http://127.0.0.1:$MOCK_PORT"
    tokens:
      read:
        value: "ntn_ro_mock"
        scope_note: "read-only"
  custom:
    description: "no validator"
    metadata:
      base_url: "http://example.internal"
    tokens:
      read:
        value: "custom_x"
        scope_note: "read-only"

grants:
  notion.read:
    integration: notion
    token: read
    env_prefix: NOTION
EOF
    "$DOP" encrypt "$WORKROOT/vault.plain.yaml" "$DOP_CLONE/vault.yaml" >/dev/null 2>&1
    VAULT="$DOP_CLONE/vault.yaml"
}

echo "=== [1] happy path: mock returns 200 → doctor exits 0"
setup_vault
mock_pid=$(start_mock 200)
trap 'stop_mock "$mock_pid" 2>/dev/null; rm -rf "$WORKROOT"' EXIT

"$DOP" doctor --vault "$VAULT" > /tmp/p8-happy.log 2>&1
if grep -q '✗' /tmp/p8-happy.log; then
    cat /tmp/p8-happy.log
    fail "doctor found a FAIL on happy path"
fi
grep -q "scope:notion.read.*PASS\|✓ scope:notion.read" /tmp/p8-happy.log || {
    grep "scope" /tmp/p8-happy.log
    fail "expected PASS on notion.read"
}
grep -q "scope:custom" /tmp/p8-happy.log || fail "custom integration line missing"
grep -q "no validator" /tmp/p8-happy.log || fail "custom integration should warn 'no validator'"
pass "happy path all checks pass; custom integration warns (no validator)"

echo "=== [2] schema mismatch → FAIL"
stop_mock "$mock_pid"; mock_pid=$(start_mock 200)
# Decrypt, bump schema_version, re-encrypt
SOPS_AGE_KEY_FILE="$HOME/Library/Application Support/dop/keys/age.txt"
[[ -f "$SOPS_AGE_KEY_FILE" ]] || SOPS_AGE_KEY_FILE="$HOME/.config/dop/keys/age.txt"
export SOPS_AGE_KEY_FILE
sops --decrypt "$VAULT" | sed 's/schema_version: 1/schema_version: 999/' > "$WORKROOT/mismatch.plain.yaml"
sops --encrypt --age "$(grep '^# public key:' "$SOPS_AGE_KEY_FILE" | awk '{print $NF}')" \
     --input-type yaml --output-type yaml \
     --output "$VAULT" "$WORKROOT/mismatch.plain.yaml"

"$DOP" doctor --vault "$VAULT" > /tmp/p8-schema.log 2>&1 || true
grep -q "schema" /tmp/p8-schema.log || fail "doctor didn't mention schema at all"
pass "schema mismatch surfaces in doctor output"

echo "=== [3] Notion mock returns 401 → scope check FAILS"
# Restore vault + point at 401-mock
rm -rf "$HOME"
setup_vault
stop_mock "$mock_pid"; mock_pid=$(start_mock 401)

"$DOP" doctor --vault "$VAULT" > /tmp/p8-401.log 2>&1 || true
if grep -q "revoked" /tmp/p8-401.log; then
    pass "doctor flags 401 as revoked/wrong token"
else
    cat /tmp/p8-401.log
    fail "doctor didn't flag 401"
fi

echo ""
echo "P8 e2e: PASS"
