#!/usr/bin/env bash
# V1.8 e2e: project + tag grouping on grants, smart env-prefix default,
# collision detection in `dop token issue` and `dop doctor`.

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "no dop"; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v18-XXXX)
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
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null
"$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1

echo "=== [2] seed vault with Notion integration + two tokens"
cat > "$VAULT_DIR/vault.yaml" <<'EOF'
schema_version: v1
integrations:
  notion:
    metadata: {base_url: "https://api.notion.com/v1"}
    tokens:
      fray-ro:     {value: "ntn_fray_ro_value"}
      fray-rw:     {value: "ntn_fray_rw_value"}
      timeless-ro: {value: "ntn_time_ro_value"}
EOF

echo "=== [3] grant add with projects + tags"
"$DOP" grant add --id notion.fray.ro --integration notion --token fray-ro \
  --projects fray --tags read,notion 2>&1 | grep -q "NOTION_FRAY_RO_TOKEN" || fail "prefix default wrong"
"$DOP" grant add --id notion.fray.rw --integration notion --token fray-rw \
  --projects fray --tags write,notion >/dev/null 2>&1
"$DOP" grant add --id notion.timeless.ro --integration notion --token timeless-ro \
  --projects timeless --tags read,notion >/dev/null 2>&1
pass "three grants added with metadata"

echo "=== [4] grant list groups by project"
out=$("$DOP" grant list 2>&1)
echo "$out" | grep -q "project: fray" || { echo "$out"; fail "no fray section"; }
echo "$out" | grep -q "project: timeless" || fail "no timeless section"
echo "$out" | grep -q "NOTION_FRAY_RO_TOKEN" || fail "prefix not shown"
echo "$out" | grep -q "tags=\[read,notion\]" || fail "tags not shown"
pass "list groups by project + tags shown"

echo "=== [5] grant list --project fray filters"
out=$("$DOP" grant list --project fray 2>&1)
echo "$out" | grep -q "notion.fray.ro" || fail "fray grant missing"
if echo "$out" | grep -q "notion.timeless.ro"; then fail "timeless leaked into fray filter"; fi
pass "project filter works"

echo "=== [6] token issue --project fray bundles all fray grants"
BEARER=$("$DOP" token issue --no-bind --project fray --name fray-bot 2>&1 | grep -E '^tok_1' | head -1)
[[ -n "$BEARER" ]] || fail "issue by project failed"
env_out=$(DOP_TOKEN="$BEARER" "$DOP" exec --agent-name p -- env 2>/dev/null)
echo "$env_out" | grep -q "NOTION_FRAY_RO_TOKEN=ntn_fray_ro_value" || fail "fray-ro not injected"
echo "$env_out" | grep -q "NOTION_FRAY_RW_TOKEN=ntn_fray_rw_value" || fail "fray-rw not injected"
if echo "$env_out" | grep -q "NOTION_TIMELESS_RO_TOKEN"; then fail "timeless leaked in fray bearer"; fi
pass "project bundle works, no cross-project leak"

echo "=== [7] token issue --project fray --tags read narrows"
BEARER2=$("$DOP" token issue --no-bind --project fray --tags read --name fray-reader 2>&1 | grep -E '^tok_1' | head -1)
env_out=$(DOP_TOKEN="$BEARER2" "$DOP" exec --agent-name r -- env 2>/dev/null)
echo "$env_out" | grep -q "NOTION_FRAY_RO_TOKEN=" || fail "fray-ro missing"
if echo "$env_out" | grep -q "NOTION_FRAY_RW_TOKEN="; then fail "write leaked into read-tag bearer"; fi
pass "tag filter narrows correctly"

echo "=== [8] env-prefix collision refused by token issue"
"$DOP" grant add --id notion.fray.ro-alias --integration notion --token fray-ro \
  --env-prefix NOTION_FRAY_RO --projects fray --tags read 2>&1 | grep -q "NOTION_FRAY_RO_TOKEN" || fail
if "$DOP" token issue --no-bind --grants notion.fray.ro,notion.fray.ro-alias --name bad 2>/dev/null; then
    fail "collision should be refused"
fi
pass "collision refused at issue"

echo "=== [9] dop doctor flags collision within project"
out=$("$DOP" doctor 2>&1)
echo "$out" | grep -q "vault:prefix-collision" || { echo "$out"; fail "doctor didn't flag collision"; }
pass "doctor flags collision"

echo "=== [10] clean up collision → doctor goes green"
"$DOP" grant remove --id notion.fray.ro-alias >/dev/null 2>&1
out=$("$DOP" doctor 2>&1)
echo "$out" | grep -qE "vault:prefix-collision.*no.*collisions" || { echo "$out"; fail "doctor still flagging"; }
pass "collision cleared"

echo ""
echo "V1.8 projects/tags e2e: PASS"
