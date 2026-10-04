#!/usr/bin/env bash
# V1.10.4 e2e: admin-loss guard.
# Reproduces the field bug: a save that would drop an admin from the
# recipient list must be refused unless DOP_ALLOW_ADMIN_SHRINK=1.

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "no dop"; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v1104-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
mkdir -p "$HOME"
export DOP_NO_TUI=1
export DOP_NO_NOTIFY=1

PASS="pass-word-long-enough"
export DOP_APPROVAL_PASSPHRASE="$PASS-approve"
CFG_ROOT="$HOME/Library/Application Support/dop"
VAULT_DIR="$CFG_ROOT/vault"

echo "=== [1] admin init + attach vault"
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
"$DOP" token issue --no-bind --grants notion.read --name seed >/dev/null 2>&1
pass "single-admin baseline established"

echo "=== [2] forge admins.trust to look like there's a second admin"
# The guard reads admins.trust for the on-disk recipient set. If we
# make it look like a 2-admin vault, any save with only 1 admin in
# v.Admins must be refused.
cat > "$VAULT_DIR/admins.trust" <<'EOF'
{
  "version": 1,
  "admins": [
    {
      "name": "self-under-test",
      "ed25519_pubkey": "PLACEHOLDER_SELF_PUBKEY",
      "age_recipient": "age1self",
      "note": "self"
    },
    {
      "name": "phantom-teammate",
      "ed25519_pubkey": "phantompk0000000000000000000000000000000000000000000000000000000",
      "age_recipient": "age1phantom",
      "note": "joined via invite"
    }
  ]
}
EOF
# Patch in the real pubkey so the guard sees us as still present.
REAL_PK=$("$DOP" admin status 2>&1 | awk '/admin pubkey/ {print $NF}')
[[ -n "$REAL_PK" ]] || fail "couldn't read admin pubkey"
sed -i.bak "s|PLACEHOLDER_SELF_PUBKEY|$REAL_PK|" "$VAULT_DIR/admins.trust" && rm "$VAULT_DIR/admins.trust.bak"
pass "admins.trust rewritten to include phantom teammate (pk=$REAL_PK)"

echo "=== [3] any admin-plane save must now REFUSE (phantom would be locked out)"
OUT=$("$DOP" token issue --no-bind --grants notion.read --name would-lose-phantom 2>&1 || true)
if ! echo "$OUT" | grep -qi "refusing to save"; then
    echo "$OUT"
    fail "guard did not trip"
fi
if ! echo "$OUT" | grep -qi "phantom-teammate\|phantompk000"; then
    echo "$OUT"
    fail "guard did not name the missing admin"
fi
pass "guard refused + named the missing admin"

echo "=== [4] DOP_ALLOW_ADMIN_SHRINK=1 lets a legitimate remove through"
DOP_ALLOW_ADMIN_SHRINK=1 "$DOP" token issue --no-bind --grants notion.read --name after-allow >/dev/null 2>&1
pass "escape hatch works when explicitly set"

pkill -9 -f "dop admin __session-daemon" 2>/dev/null || true
echo "V1.10.4 admin-guard e2e: PASS"
