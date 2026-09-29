#!/usr/bin/env bash
# Batch 4: `dop vault edit` end-to-end via a scripted "editor" that
# performs an in-place YAML edit.

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

echo "=== [1] setup"
printf "%s\n%s\n" "$PASS" "$PASS-approve" | "$DOP" admin init --passphrase-stdin >/dev/null
"$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null
"$DOP" integration add --name notion --token "read=OLD_VALUE:read-only" >/dev/null 2>&1

echo "=== [2] scripted editor: replace OLD_VALUE with NEW_VALUE"
cat > "$WORKROOT/edit.sh" <<'EOF'
#!/usr/bin/env bash
sed -i '' 's/OLD_VALUE/NEW_VALUE/' "$1"
EOF
chmod +x "$WORKROOT/edit.sh"

"$DOP" vault edit --editor "$WORKROOT/edit.sh" 2>&1 | grep -q "saved" || fail "vault edit didn't confirm save"
pass "vault edit succeeded"

echo "=== [3] value was actually changed"
"$DOP" grant add --id notion.read --integration notion --token read >/dev/null 2>&1
BEARER=$("$DOP" token issue --no-bind --grants notion.read --name checker 2>/dev/null)
env_out=$(DOP_TOKEN="$BEARER" "$DOP" exec --agent-name c -- env 2>/dev/null)
echo "$env_out" | grep -q "NOTION_READ_TOKEN=NEW_VALUE" || fail "value not updated: $env_out"
pass "edit persisted correctly"

echo "=== [4] plaintext tempfile cleaned up"
ls "$HOME/Library/Application Support/dop/.vault-edit.yaml" 2>/dev/null && fail "tempfile leaked"
pass "no tempfile leak"

echo "=== [5] logout"
"$DOP" admin logout >/dev/null 2>&1
sleep 0.3

echo ""
echo "V1 vault edit e2e: PASS"
