#!/usr/bin/env bash
# V1.6.2 e2e: exec-time signature verification.
# Proves that:
#  - missing .record → exec rejects
#  - missing admins.trust → exec rejects
#  - tampered .record (bad signature) → exec rejects
#  - IssuedBy pointing at an unknown admin → exec rejects

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "V1.6.2 e2e: no dop at $DOP" >&2; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v162-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
mkdir -p "$HOME"
export DOP_NO_TUI=1
export DOP_NO_NOTIFY=1

PASS="pass-word-long-enough"
CFG_ROOT="$HOME/Library/Application Support/dop"
VAULT_DIR="$CFG_ROOT/vault"

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

BEARER=$("$DOP" token issue --no-bind --grants notion.read --name sigtest 2>/dev/null | grep -E '^tok_1' | head -1)
[[ -n "$BEARER" ]] || fail "no bearer"
pass "issued"

echo "=== [2] baseline exec works"
DOP_TOKEN="$BEARER" "$DOP" exec --agent-name b -- true 2>/dev/null || fail "baseline broken"
pass "baseline exec succeeds"

echo "=== [3] admins.trust + .record both exist"
[[ -f "$VAULT_DIR/admins.trust" ]] || fail "no admins.trust"
REC=$(ls "$VAULT_DIR/capabilities"/*.record 2>/dev/null | head -1)
[[ -n "$REC" ]] || fail "no .record file"
pass "sidecars present"

echo "=== [4] remove .record → exec fails"
mv "$REC" "$REC.bak"
if DOP_TOKEN="$BEARER" "$DOP" exec --agent-name n -- true 2>/dev/null; then
    fail "missing record should reject"
fi
mv "$REC.bak" "$REC"
pass "missing record blocks exec"

echo "=== [5] remove admins.trust → exec fails"
mv "$VAULT_DIR/admins.trust" "$VAULT_DIR/admins.trust.bak"
if DOP_TOKEN="$BEARER" "$DOP" exec --agent-name t -- true 2>/dev/null; then
    fail "missing trust file should reject"
fi
mv "$VAULT_DIR/admins.trust.bak" "$VAULT_DIR/admins.trust"
pass "missing trust file blocks exec"

echo "=== [6] tamper .record (flip status) → sig fails"
python3 -c "
import json
p = '$REC'
d = json.load(open(p))
d['status'] = 'active'   # unchanged, but re-serialize to break sig? no — actual tamper below
d['subject'] = 'attacker-owned'
json.dump(d, open(p, 'w'))
"
if DOP_TOKEN="$BEARER" "$DOP" exec --agent-name x -- true 2>/dev/null; then
    fail "tampered record should reject"
fi
pass "tampered record rejected"

echo "=== [7] restore + re-issue → back to green"
# Restore is easiest by revoking + re-issuing.
"$DOP" token revoke sigtest >/dev/null 2>&1 || true
BEARER2=$("$DOP" token issue --no-bind --grants notion.read --name sigtest2 2>/dev/null | grep -E '^tok_1' | head -1)
DOP_TOKEN="$BEARER2" "$DOP" exec --agent-name y -- true 2>/dev/null || fail "re-issued should work"
pass "re-issued bearer works"

echo "=== [8] swap IssuedBy to unknown pubkey → exec fails"
REC2=$(ls -t "$VAULT_DIR/capabilities"/*.record 2>/dev/null | head -1)
python3 -c "
import json
p = '$REC2'
d = json.load(open(p))
d['issued_by'] = '00' * 32   # fake pubkey not in admins.trust
json.dump(d, open(p, 'w'))
"
if DOP_TOKEN="$BEARER2" "$DOP" exec --agent-name z -- true 2>/dev/null; then
    fail "unknown-admin record should reject"
fi
pass "unknown-admin issued_by rejected"

echo ""
echo "V1.6.2 signature-verify e2e: PASS"
