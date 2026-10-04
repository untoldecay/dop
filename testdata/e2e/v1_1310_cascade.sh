#!/usr/bin/env bash
# V1.13.0-rc8 e2e: cascade engine for grant removal + integration
# token removal. Both paths run through cascadeGrantRemoval and should:
#   - trim grants from affected capabilities
#   - reseal P-256 bearers' EnvWrapped
#   - warn (default) or revoke (--force-revoke-ed25519) ed25519 bearers
#   - revoke bearers that drop to zero grants

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "V1.13 cascade e2e: no dop at $DOP" >&2; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v1310-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
mkdir -p "$HOME"
export DOP_NO_TUI=1
export DOP_NO_KEYCHAIN=1
export DOP_ALLOW_FILE_KEYS=1

PASS="pass-word-long-enough"
export DOP_APPROVAL_PASSPHRASE="$PASS-approve"
VAULT_DIR="$HOME/Library/Application Support/dop/vault"

echo "=== [1] setup — admin + 2 integrations, 3 grants"
printf "%s\n%s\n" "$PASS" "$PASS-approve" | "$DOP" admin init --passphrase-stdin >/dev/null
"$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null
cat > "$VAULT_DIR/vault.yaml" <<'EOF'
schema_version: v1
integrations:
  notion: {metadata: {}, tokens: {read: {value: "ntn_r"}, write: {value: "ntn_w"}}}
  slack:  {metadata: {}, tokens: {bot: {value: "xoxb"}}}
grants:
  notion.read:  {integration: notion, token: read,  env_prefix: NOTION_R}
  notion.write: {integration: notion, token: write, env_prefix: NOTION_W}
  slack.bot:    {integration: slack,  token: bot,   env_prefix: SLACK_B}
EOF
pass "seeded"

echo "=== [2] issue + claim three bearers"
# p256-bearer-A has notion.read + slack.bot (will lose notion.read in test 3)
OUT=$("$DOP" token issue --grants notion.read,slack.bot --name p256-A 2>&1)
B_A=$(echo "$OUT" | grep -E '^tok_1' | head -1)
P_A=$(echo "$OUT" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
DOP_TOKEN="$B_A" "$DOP" claim --skip-approval --key-type p256 "$P_A" >/dev/null 2>&1

# ed25519-bearer-B has notion.read only (will drop to zero grants + be revoked)
OUT=$("$DOP" token issue --grants notion.read --name ed25519-B 2>&1)
B_B=$(echo "$OUT" | grep -E '^tok_1' | head -1)
P_B=$(echo "$OUT" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
DOP_TOKEN="$B_B" "$DOP" claim --skip-approval "$P_B" >/dev/null 2>&1

# p256-bearer-C has notion.write (will survive the grant-remove test)
OUT=$("$DOP" token issue --grants notion.write --name p256-C 2>&1)
B_C=$(echo "$OUT" | grep -E '^tok_1' | head -1)
P_C=$(echo "$OUT" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
DOP_TOKEN="$B_C" "$DOP" claim --skip-approval --key-type p256 "$P_C" >/dev/null 2>&1

pass "3 bearers claimed (p256-A, ed25519-B, p256-C)"

echo "=== [3] remove grant notion.read — cascade through p256-A + ed25519-B"
OUT=$("$DOP" grant remove --id notion.read 2>&1)
echo "$OUT" | grep -q "removed notion.read" || fail "grant remove didn't confirm: $OUT"
echo "$OUT" | grep -q "resealed" || fail "no reseal in summary: $OUT"
echo "$OUT" | grep -qi "ed25519" || fail "no ed25519 mention: $OUT"
pass "cascade summary printed"

echo "=== [4] p256-A still works — now only sees slack.bot (notion gone)"
ENV_A=$(DOP_TOKEN="$B_A" "$DOP" env 2>&1)
echo "$ENV_A" | grep -q "SLACK_B_TOKEN" || fail "p256-A lost slack.bot: $ENV_A"
echo "$ENV_A" | grep -q "NOTION_R_TOKEN" && fail "p256-A still sees notion.read after reseal: $ENV_A"
pass "p256-A live-reseal narrowed env"

echo "=== [5] ed25519-B dropped to zero grants and is revoked"
if DOP_TOKEN="$B_B" "$DOP" env 2>&1 | grep -q "NOTION"; then
  fail "ed25519-B should be revoked after dropping to zero grants"
fi
pass "zero-grant ed25519 bearer revoked"

echo "=== [6] p256-C unaffected (had notion.write, kept it)"
ENV_C=$(DOP_TOKEN="$B_C" "$DOP" env 2>&1)
echo "$ENV_C" | grep -q "NOTION_W_TOKEN" || fail "p256-C lost its grant: $ENV_C"
pass "unrelated bearer untouched"

echo "=== [7] remove-token on slack.bot drops slack entirely + revokes p256-A"
# p256-A now has only slack.bot — removing it drops the bearer to zero.
OUT=$("$DOP" integration remove-token --name slack --token bot 2>&1)
echo "$OUT" | grep -q "integration had no remaining tokens" || fail "no integration-removed message: $OUT"
echo "$OUT" | grep -q "revoked\|no grants" || fail "no zero-grant revoke mention: $OUT"
pass "integration remove-token cascaded"

echo "=== [8] slack integration gone"
if "$DOP" integration list 2>&1 | grep -q "slack"; then
  fail "slack integration should be gone"
fi
pass "slack integration cleaned up"

echo "=== [9] p256-A now revoked (zero grants after slack.bot removal)"
if DOP_TOKEN="$B_A" "$DOP" env 2>&1 | grep -q "TOKEN"; then
  fail "p256-A should be revoked after dropping to zero grants"
fi
pass "zero-grant p256 bearer revoked"

echo
echo "V1.13 cascade e2e: ALL PASS"
