#!/usr/bin/env bash
# V1.11.1 e2e: `dop token show`, `dop grant show`, `--expires=never`.

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "V1.11.1 e2e: no dop at $DOP" >&2; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v1111-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
mkdir -p "$HOME"
export DOP_NO_TUI=1
export DOP_NO_KEYCHAIN=1

PASS="pass-word-long-enough"
export DOP_APPROVAL_PASSPHRASE="$PASS-approve"
CFG_ROOT="$HOME/Library/Application Support/dop"
VAULT_DIR="$CFG_ROOT/vault"

echo "=== [1] setup: init + seed vault"
printf "%s\n%s\n" "$PASS" "$PASS-approve" | "$DOP" admin init --passphrase-stdin >/dev/null
"$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null
cat > "$VAULT_DIR/vault.yaml" <<'EOF'
schema_version: v1
integrations:
  notion:
    metadata: {base_url: "https://api.notion.com/v1"}
    tokens:
      read:  {value: "ntn_read"}
      write: {value: "ntn_write"}
grants:
  notion.read:  {integration: notion, token: read,  env_prefix: NOTION}
  notion.write: {integration: notion, token: write, env_prefix: NOTION_W}
EOF
pass "vault seeded (2 grants)"

echo "=== [2] issue two tokens, one with --expires=never"
OUT1=$("$DOP" token issue --grants notion.read --name inspector-normal 2>&1)
BEARER1=$(echo "$OUT1" | grep -E '^tok_1' | head -1)
[[ -n "$BEARER1" ]] || fail "no bearer1"
OUT2=$("$DOP" token issue --grants notion.read,notion.write --name inspector-forever --expires=never 2>&1)
BEARER2=$(echo "$OUT2" | grep -E '^tok_1' | head -1)
[[ -n "$BEARER2" ]] || fail "no bearer2"
echo "$OUT2" | grep -q "never" || fail "issue output missed 'never' for --expires=never"
pass "issued normal + forever tokens"

echo "=== [3] dop token list shows 'never' for the forever one"
LIST=$("$DOP" token list --all 2>&1)
echo "$LIST" | grep -q "inspector-forever" || fail "list missed forever"
echo "$LIST" | grep -E "inspector-forever.*expires=never" >/dev/null \
  || fail "list did not display 'never' for --expires=never token: $LIST"
pass "list renders 'never'"

echo "=== [4] dop token show <subject> for normal token"
SHOW1=$("$DOP" token show inspector-normal 2>&1)
echo "$SHOW1" | grep -q "^subject:      inspector-normal" || fail "show missed subject"
echo "$SHOW1" | grep -q "notion.read.*NOTION_TOKEN" || fail "show missed grant → env line"
pass "token show renders subject + grants"

echo "=== [5] dop token show for forever token → 'never' expiry"
SHOW2=$("$DOP" token show inspector-forever 2>&1)
echo "$SHOW2" | grep -q "expires_at:   never" || fail "show didn't say 'never' for forever token"
echo "$SHOW2" | grep -q "notion.write" || fail "show missed second grant"
pass "token show renders 'never' + multi-grant"

echo "=== [6] dop token show --json parses (flag AFTER positional — v1.11.1 splitter)"
JSON=$("$DOP" token show inspector-forever --json 2>&1)
echo "$JSON" | python3 -c "import sys,json; d=json.loads(sys.stdin.read()); assert d['expires_at']=='never'; assert len(d['grants'])==2" \
  || fail "json malformed or missing fields: $JSON"
pass "token show --json ok"

echo "=== [7] dop grant show <id> lists both tokens"
GSHOW=$("$DOP" grant show notion.read 2>&1)
echo "$GSHOW" | grep -q "integration: notion" || fail "grant show missed integration"
echo "$GSHOW" | grep -q "inspector-normal" || fail "grant show missed inspector-normal"
echo "$GSHOW" | grep -q "inspector-forever" || fail "grant show missed inspector-forever"
pass "grant show lists tokens"

echo "=== [8] revoke normal; grant show default hides it, --all reveals"
"$DOP" token revoke inspector-normal >/dev/null 2>&1
GSHOW2=$("$DOP" grant show notion.read 2>&1)
echo "$GSHOW2" | grep -q "inspector-normal" && fail "grant show should hide revoked by default: $GSHOW2"
GSHOW3=$("$DOP" grant show notion.read --all 2>&1)
echo "$GSHOW3" | grep -q "inspector-normal" || fail "grant show --all should reveal revoked: $GSHOW3"
pass "grant show respects --all"

echo "=== [9] --expires with garbage rejects (unchanged behavior)"
if OUT=$("$DOP" token issue --grants notion.read --name bogus --expires=xyz 2>&1); then
  fail "should have rejected --expires=xyz"
fi
pass "bogus --expires still rejected"

echo
echo "V1.11.1 e2e: ALL PASS"
