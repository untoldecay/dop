#!/usr/bin/env bash
# V1.9.11 e2e: `dop token list` hides revoked by default + auto-push
# to vault runs after each admin mutation.

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "no dop"; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v1911-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
mkdir -p "$HOME"
export DOP_NO_TUI=1
export DOP_NO_NOTIFY=1

PASS="pass-word-long-enough"
CFG_ROOT="$HOME/Library/Application Support/dop"
VAULT_DIR="$CFG_ROOT/vault"
BARE="$WORKROOT/bare.git"

echo "=== [1] setup admin + bare vault remote"
printf "%s\n%s\n" "$PASS" "$PASS-approve" | "$DOP" admin init --passphrase-stdin >/dev/null
"$DOP" init --vault "$BARE" >/dev/null 2>&1
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

echo "=== [2] issue two tokens (autopush should send them to the remote)"
BEARER1_OUT=$("$DOP" token issue --no-bind --grants notion.read --name alpha 2>&1)
BEARER1=$(echo "$BEARER1_OUT" | grep -E '^tok_1' | head -1)
BEARER2_OUT=$("$DOP" token issue --no-bind --grants notion.read --name beta 2>&1)
BEARER2=$(echo "$BEARER2_OUT" | grep -E '^tok_1' | head -1)
[[ -n "$BEARER1" && -n "$BEARER2" ]] || fail "no bearers"
pass "issued alpha + beta"

echo "=== [3] autopush landed the commits on the bare remote"
COMMITS=$(git --git-dir="$BARE" log --oneline 2>&1 | wc -l | tr -d ' ')
if (( COMMITS < 2 )); then
    git --git-dir="$BARE" log --oneline
    fail "expected ≥2 commits on the bare remote, got $COMMITS"
fi
pass "bare remote has $COMMITS commits — autopush worked"

echo "=== [4] revoke alpha"
"$DOP" token revoke alpha >/dev/null 2>&1 || fail "revoke failed"
pass "alpha revoked"

echo "=== [5] token list (default) hides alpha, shows beta"
LIST_OUT=$("$DOP" token list 2>&1)
if echo "$LIST_OUT" | grep -q "subject=alpha"; then
    echo "$LIST_OUT"
    fail "default list must NOT show revoked alpha"
fi
echo "$LIST_OUT" | grep -q "subject=beta" || { echo "$LIST_OUT"; fail "list didn't show active beta"; }
echo "$LIST_OUT" | grep -q "revoked hidden" || fail "no revoked-hidden footer hint"
pass "default list hides revoked + surfaces hint"

echo "=== [6] token list --all shows both"
ALL_OUT=$("$DOP" token list --all 2>&1)
echo "$ALL_OUT" | grep -q "subject=alpha" || fail "--all missed alpha"
echo "$ALL_OUT" | grep -q "subject=beta"  || fail "--all missed beta"
pass "--all includes revoked"

echo "=== [7] revoke also auto-pushed"
COMMITS2=$(git --git-dir="$BARE" log --oneline 2>&1 | wc -l | tr -d ' ')
if (( COMMITS2 <= COMMITS )); then
    fail "revoke did not auto-push (before=$COMMITS after=$COMMITS2)"
fi
pass "revoke autopushed ($COMMITS → $COMMITS2 commits)"

echo "=== [8] DOP_NO_AUTO_PUSH=1 disables it"
COMMITS3=$(git --git-dir="$BARE" log --oneline | wc -l | tr -d ' ')
DOP_NO_AUTO_PUSH=1 "$DOP" token issue --no-bind --grants notion.read --name gamma >/dev/null 2>&1 || fail "issue gamma"
COMMITS4=$(git --git-dir="$BARE" log --oneline | wc -l | tr -d ' ')
if (( COMMITS4 != COMMITS3 )); then
    fail "DOP_NO_AUTO_PUSH=1 should skip push (before=$COMMITS3 after=$COMMITS4)"
fi
pass "DOP_NO_AUTO_PUSH=1 skips push"

pkill -9 -f "dop admin __session-daemon" 2>/dev/null || true
echo "V1.9.11 list + autopush e2e: PASS"
