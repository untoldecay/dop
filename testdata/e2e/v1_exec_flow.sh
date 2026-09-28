#!/usr/bin/env bash
# V1 Phase 4 e2e: agent execution path.
# End-to-end: admin issues → agent (same machine, DOP_TOKEN in env) execs.
# Then test the tamper/expired/revoked paths.

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

PASS="pass-word-long-enough"
CFG_ROOT="$HOME/Library/Application Support/dop"
VAULT_DIR="$CFG_ROOT/vault"

echo "=== [1] admin init + init --vault + login + seed"
echo -n "$PASS" | "$DOP" admin init --passphrase-stdin >/dev/null
"$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null
cat > "$VAULT_DIR/vault.yaml" <<'EOF'
schema_version: v1
integrations:
  notion:
    metadata: {base_url: "https://api.notion.com/v1"}
    tokens:
      read:
        value: "ntn_secret_ro_value"
        scope_note: "read-only"
grants:
  notion.read:
    integration: notion
    token: read
    env_prefix: NOTION
EOF

echo "=== [2] issue a bearer"
BEARER=$("$DOP" token issue --grants notion.read --name research 2>/dev/null)
[[ "$BEARER" == tok_1* ]] || fail "bad bearer"

echo "=== [3] dop exec — env visible in child"
env_out=$(DOP_TOKEN="$BEARER" "$DOP" exec --agent-name r1 -- env 2>/dev/null)
echo "$env_out" | grep -q "NOTION_TOKEN=ntn_secret_ro_value" || { echo "$env_out"; fail "NOTION_TOKEN not injected"; }
echo "$env_out" | grep -q "NOTION_BASE_URL=https://api.notion.com/v1" || fail "NOTION_BASE_URL not injected"
pass "env injected correctly"

echo "=== [4] whoami shows the subject"
who=$(DOP_TOKEN="$BEARER" "$DOP" whoami 2>&1)
echo "$who" | grep -q "subject:.*research" || { echo "$who"; fail "subject not shown"; }
pass "whoami works"

echo "=== [5] env prints exports"
DOP_TOKEN="$BEARER" "$DOP" env | grep -q "export NOTION_TOKEN=" || fail "env export missing"
pass "env exports"

echo "=== [6] --token-file also works"
tokenfile=$(mktemp)
echo "$BEARER" > "$tokenfile"
DOP_TOKEN="" env_out=$("$DOP" exec --token-file "$tokenfile" --agent-name r2 -- env 2>/dev/null)
echo "$env_out" | grep -q "NOTION_TOKEN=" || fail "token-file didn't work"
pass "--token-file works"

echo "=== [7] revoke → exec fails"
"$DOP" token revoke research 2>/dev/null
if DOP_TOKEN="$BEARER" "$DOP" exec --agent-name r3 -- true 2>/dev/null; then
    fail "revoked bearer still exec'd"
fi
pass "revoked bearer rejected"

echo "=== [8] wrong bearer fails"
if DOP_TOKEN="tok_1deadbeef" "$DOP" exec --agent-name w -- true 2>/dev/null; then
    fail "unknown bearer should fail"
fi
pass "wrong bearer rejected"

echo "=== [9] no bearer → clean error"
if unset DOP_TOKEN; "$DOP" exec --agent-name x -- true 2>/dev/null; then
    fail "no bearer should error"
fi
pass "missing bearer errored"

echo "=== [10] issue a fresh bearer with 1s TTL, wait, exec fails"
FRESH=$("$DOP" token issue --grants notion.read --name shortlived --expires 1s 2>/dev/null)
sleep 2
if DOP_TOKEN="$FRESH" "$DOP" exec --agent-name f -- true 2>/dev/null; then
    fail "expired bearer should fail"
fi
pass "expired bearer rejected"

echo "=== [11] tamper the bundle → exec fails"
BUNDLE=$(ls "$VAULT_DIR/capabilities" | head -1)
if [[ -z "$BUNDLE" ]]; then
    fail "no bundle to tamper (unexpected — all bundles deleted)"
fi
# Actually, our revoke deleted the one bundle. Issue another for tampering.
TAMPER_BEARER=$("$DOP" token issue --grants notion.read --name tamper --expires 1h 2>/dev/null)
BUNDLE=$(ls "$VAULT_DIR/capabilities" | head -1)
# Flip a byte in the ciphertext region.
python3 -c "
import sys
p = '$VAULT_DIR/capabilities/$BUNDLE'
with open(p, 'rb') as f: b = bytearray(f.read())
b[-1] ^= 0xFF
with open(p, 'wb') as f: f.write(b)
"
if DOP_TOKEN="$TAMPER_BEARER" "$DOP" exec --agent-name t -- true 2>/dev/null; then
    fail "tampered bundle should fail"
fi
pass "tamper detection works"

echo ""
echo "V1 Phase 4 e2e: PASS"
