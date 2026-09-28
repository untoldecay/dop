#!/usr/bin/env bash
# V1 remote-server flow: admin issues on machine A, "server" (machine B)
# runs `dop init --cache` and consumes the bearer WITHOUT an age key.

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "no dop"; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v1-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT

MACHINE_A="$WORKROOT/a"
MACHINE_B="$WORKROOT/b"
mkdir -p "$MACHINE_A" "$MACHINE_B"
BARE="$WORKROOT/bare"
PASS="the-passphrase-15chars"

# --- Machine A: admin ---
echo "=== [A1] admin init + attach vault + login + seed"
HOME="$MACHINE_A" "$DOP" -h >/dev/null 2>&1 || true  # smoke
export DOP_NO_TUI=1
echo -n "$PASS" | HOME="$MACHINE_A" "$DOP" admin init --passphrase-stdin >/dev/null
HOME="$MACHINE_A" "$DOP" init --vault "$BARE" >/dev/null 2>&1
echo -n "$PASS" | HOME="$MACHINE_A" "$DOP" admin login --passphrase-stdin >/dev/null
VAULT_A="$MACHINE_A/Library/Application Support/dop/vault"
cat > "$VAULT_A/vault.yaml" <<'EOF'
schema_version: v1
integrations:
  notion:
    metadata: {base_url: "https://api.notion.com/v1"}
    tokens:
      read: {value: "ntn_secret_ro", scope_note: "read-only"}
grants:
  notion.read: {integration: notion, token: read, env_prefix: NOTION}
EOF

echo "=== [A2] issue a bearer for the server"
BEARER=$(HOME="$MACHINE_A" "$DOP" token issue --grants notion.read --name prod-server --expires 30d 2>&1 | tail -1)
if [[ "$BEARER" != tok_1* ]]; then
    HOME="$MACHINE_A" "$DOP" token issue --grants notion.read --name debug --expires 30d 2>&1 | head -10
    fail "expected bearer, got: $BEARER"
fi
[[ "$BEARER" == tok_1* ]] || fail "bad bearer"
pass "issued: $BEARER"

echo "=== [A3] push to bare"
cd "$VAULT_A"
git config user.email "e2e@test" && git config user.name "e2e"
git add -A && git commit -m "seed + issue" >/dev/null
git push origin HEAD:main 2>/dev/null || git push -u origin HEAD:main 2>/dev/null

# --- Machine B: agent install ---
echo "=== [B1] init --cache (no admin key generated)"
HOME="$MACHINE_B" "$DOP" init --cache "$BARE" >/dev/null 2>&1
[[ ! -f "$MACHINE_B/Library/Application Support/dop/keys/admin.age.enc" ]] || fail "agent install has admin key!"
[[ -f "$MACHINE_B/Library/Application Support/dop/vault/vault.yaml" ]] || fail "agent didn't clone vault.yaml"
[[ -f "$MACHINE_B/Library/Application Support/dop/vault/vault-context.bin" ]] || fail "agent didn't get vault-context.bin"
[[ -d "$MACHINE_B/Library/Application Support/dop/vault/capabilities" ]] || fail "agent didn't get capabilities/"
pass "agent install clean"

echo "=== [B2] agent has no admin capability"
if HOME="$MACHINE_B" "$DOP" admin status 2>&1 | grep -q unlocked; then
    fail "agent shouldn't have an unlocked session"
fi
pass "agent session locked (no keys)"

echo "=== [B3] agent exec works with the bearer"
env_out=$(DOP_TOKEN="$BEARER" HOME="$MACHINE_B" "$DOP" exec --agent-name b1 -- env 2>/dev/null)
echo "$env_out" | grep -q "NOTION_TOKEN=ntn_secret_ro" || { echo "$env_out"; fail "NOTION_TOKEN not injected"; }
pass "agent exec works"

echo "=== [B4] agent whoami identifies the subject"
who=$(DOP_TOKEN="$BEARER" HOME="$MACHINE_B" "$DOP" whoami 2>&1)
echo "$who" | grep -q "prod-server" || fail "subject not shown"
pass "whoami works from agent install"

echo "=== [B5] agent cannot issue tokens"
if HOME="$MACHINE_B" "$DOP" token issue --grants notion.read --name bad 2>&1; then
    fail "agent should not be able to issue tokens"
fi
pass "issuing from agent refused"

# --- Cleanup A ---
HOME="$MACHINE_A" "$DOP" admin logout >/dev/null

echo ""
echo "V1 remote-server e2e: PASS"
