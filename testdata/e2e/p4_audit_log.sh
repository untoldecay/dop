#!/usr/bin/env bash
# P4 end-to-end: audit log captures ok + denied outcomes with expected fields.

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "P4 e2e: no dop at $DOP" >&2; exit 2; }

WORKROOT=$(mktemp -d)
trap 'rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
export XDG_CONFIG_HOME="$HOME/.config"
mkdir -p "$HOME"

pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

echo "=== [1] setup vault"
"$DOP" init >/dev/null
"$DOP" init --vault "$WORKROOT/vault-bare" >/dev/null 2>&1
DOP_CLONE="$HOME/Library/Application Support/dop/vault"
[[ -d "$DOP_CLONE" ]] || DOP_CLONE="$HOME/.config/dop/vault"
LOGS_DIR="$HOME/Library/Application Support/dop/logs"
[[ -d "$(dirname "$LOGS_DIR")" ]] || LOGS_DIR="$HOME/.config/dop/logs"

cp testdata/vault.example.yaml "$DOP_CLONE/vault.plain.yaml"
"$DOP" encrypt "$DOP_CLONE/vault.plain.yaml" "$DOP_CLONE/vault.yaml" >/dev/null 2>&1
rm "$DOP_CLONE/vault.plain.yaml"
VAULT="$DOP_CLONE/vault.yaml"
pass "vault ready"

echo "=== [2] token issue → expect token-issue log line"
NEW=$("$DOP" token issue --vault "$VAULT" --grants boiler.read --name "auditee" 2>/dev/null)
[[ "$NEW" == tok_* ]] || fail "no token"
sleep 0.05
"$DOP" log tail --n 20 | grep -q '"op":"token-issue"' || fail "no token-issue in log"
pass "token-issue logged"

echo "=== [3] successful exec → outcome=ok log line with grants"
DOP_TOKEN="$NEW" "$DOP" exec --vault "$VAULT" --no-pull --agent-name "audit-agent" -- true 2>/dev/null
"$DOP" log tail --n 20 | grep '"op":"exec"' | grep -q '"outcome":"ok"' || fail "no ok exec in log"
"$DOP" log tail --n 20 | grep '"op":"exec"' | grep -q '"agent_name":"audit-agent"' || fail "agent_name not logged"
"$DOP" log tail --n 20 | grep '"op":"exec"' | grep -q '"auth_method":"bearer"' || fail "auth_method not logged"
pass "ok exec logged with fields"

echo "=== [4] denied exec (bad bearer) → outcome=denied log line"
DOP_TOKEN="tok_wrong" "$DOP" exec --vault "$VAULT" --no-pull --agent-name "attacker" -- true 2>/dev/null || true
"$DOP" log tail --n 20 | grep '"agent_name":"attacker"' | grep -q '"outcome":"denied"' || fail "denied not logged"
pass "denied exec logged"

echo "=== [5] log grep filters by outcome"
denied_only=$("$DOP" log grep outcome=denied 2>/dev/null)
if ! echo "$denied_only" | grep -q '"agent_name":"attacker"'; then
    fail "grep didn't return the denied entry"
fi
if echo "$denied_only" | grep -q '"outcome":"ok"'; then
    fail "grep returned ok entries too"
fi
pass "grep filters correctly"

echo "=== [6] token_hash present, bearer NEVER"
if "$DOP" log tail --n 50 | grep -q "$NEW"; then
    fail "raw bearer leaked into audit log!"
fi
"$DOP" log tail --n 50 | grep '"op":"exec"' | grep -q '"token_hash":"' || fail "token_hash missing from exec line"
pass "hash present, bearer never"

echo "=== [7] revoke logs a token-revoke line"
"$DOP" token revoke --vault "$VAULT" "auditee" 2>/dev/null
"$DOP" log tail --n 30 | grep -q '"op":"token-revoke"' || fail "revoke not logged"
pass "revoke logged"

echo ""
echo "P4 e2e: PASS"
