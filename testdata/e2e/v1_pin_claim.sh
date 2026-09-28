#!/usr/bin/env bash
# V1.3 e2e: PIN-claim binding.
# Admin issues with --bind (default) → prints bearer + PIN. Agent claims
# with PIN → gets bound → exec works. Unbound exec fails; claimed exec
# works. PIN expiry, wrong PIN, and rebind rejection all covered.

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "V1.3 e2e: no dop at $DOP" >&2; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v13-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
mkdir -p "$HOME"
export DOP_NO_TUI=1

PASS="pass-word-long-enough"
CFG_ROOT="$HOME/Library/Application Support/dop"
VAULT_DIR="$CFG_ROOT/vault"

echo "=== [1] setup: admin init + vault + login + seed"
printf "%s\n%s\n" "$PASS" "$PASS-approve" | "$DOP" admin init --passphrase-stdin >/dev/null
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

echo "=== [2] token issue (default --bind) prints bearer + PIN"
issue_out=$("$DOP" token issue --grants notion.read --name research-agent 2>&1)
# stdout carries bearer + PIN; stderr carries the human text.
BEARER=$(echo "$issue_out" | grep -E '^tok_1' | head -1)
PIN=$(echo "$issue_out" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
[[ -n "$BEARER" ]] || { echo "$issue_out"; fail "no bearer emitted"; }
[[ -n "$PIN" ]] || { echo "$issue_out"; fail "no PIN emitted"; }
pass "issued bearer=$BEARER PIN=$PIN"

echo "=== [3] exec before claim → refused (binding requires claim)"
if DOP_TOKEN="$BEARER" "$DOP" exec --agent-name r -- true 2>/dev/null; then
    fail "exec should refuse unclaimed bound bearer"
fi
pass "unclaimed bearer refused"

echo "=== [4] wrong PIN → refused"
if DOP_TOKEN="$BEARER" "$DOP" claim --skip-approval WRONG-XX-YZ 2>/dev/null; then
    fail "wrong PIN should be rejected"
fi
pass "wrong PIN rejected"

echo "=== [5] correct claim → succeeds, agent key created"
DOP_TOKEN="$BEARER" "$DOP" claim --skip-approval "$PIN" 2>&1 | grep -q "bound" || fail "claim should succeed"
ls "$CFG_ROOT"/agent-keys/*.key >/dev/null 2>&1 || fail "no agent key persisted"
pass "claim bound successfully, key present"

echo "=== [6] second claim of same bearer → refused (already claimed)"
if DOP_TOKEN="$BEARER" "$DOP" claim --skip-approval "$PIN" 2>/dev/null; then
    fail "second claim should be rejected"
fi
pass "double claim rejected"

echo "=== [7] exec after claim → succeeds, env injected"
env_out=$(DOP_TOKEN="$BEARER" "$DOP" exec --agent-name r1 -- env 2>/dev/null)
echo "$env_out" | grep -q "NOTION_TOKEN=ntn_secret_ro_value" || fail "env not injected"
pass "bound exec works"

echo "=== [8] whoami shows binding"
who=$(DOP_TOKEN="$BEARER" "$DOP" whoami 2>&1)
echo "$who" | grep -q "binding:.*pin.*claimed" || { echo "$who"; fail "binding not shown"; }
pass "whoami surfaces binding"

echo "=== [9] delete the agent key → exec fails"
rm -f "$CFG_ROOT"/agent-keys/*.key
if DOP_TOKEN="$BEARER" "$DOP" exec --agent-name k -- true 2>/dev/null; then
    fail "exec should fail without agent key"
fi
pass "missing agent key blocks exec"

echo "=== [10] --no-bind still works (unbound bearer)"
UNB=$("$DOP" token issue --no-bind --grants notion.read --name legacy 2>&1 | grep -E '^tok_1' | head -1)
[[ -n "$UNB" ]] || fail "unbound issue failed"
DOP_TOKEN="$UNB" "$DOP" exec --agent-name u -- env 2>/dev/null | grep -q "NOTION_TOKEN=" || fail "unbound exec should work"
pass "--no-bind path intact"

echo "=== [11] PIN expiry: issue with --pin-ttl 1s, wait, claim fails"
issue2=$("$DOP" token issue --grants notion.read --name shortpin --pin-ttl 1s 2>&1)
B2=$(echo "$issue2" | grep -E '^tok_1' | head -1)
P2=$(echo "$issue2" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
sleep 2
if DOP_TOKEN="$B2" "$DOP" claim --skip-approval "$P2" 2>/dev/null; then
    fail "expired PIN should be rejected"
fi
pass "expired PIN rejected"

echo "=== [12] token repin — expired subject, fresh PIN, can now claim"
repin_out=$(DOP_TOKEN="$B2" "$DOP" token repin --subject shortpin 2>&1)
P2new=$(echo "$repin_out" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
[[ -n "$P2new" ]] || { echo "$repin_out"; fail "repin didn't emit new PIN"; }
DOP_TOKEN="$B2" "$DOP" claim --skip-approval "$P2new" >/dev/null 2>&1 || fail "reclaim after repin failed"
pass "repin works, reclaim succeeds"

echo ""
echo "V1.3 PIN-claim e2e: PASS"
