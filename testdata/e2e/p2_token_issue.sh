#!/usr/bin/env bash
# P2 end-to-end: dop token issue → dop exec resolves the new token
#                dop token revoke → subsequent dop exec fails
#                dop token issue with sensitive grant → prompt required
#                dop token list → shows records without leaking bearers

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
if [[ ! -x "$DOP" ]]; then
    echo "P2 e2e: dop binary not found at $DOP" >&2
    exit 2
fi

WORKROOT=$(mktemp -d)
trap 'rm -rf "$WORKROOT"' EXIT

export HOME="$WORKROOT/home"
export XDG_CONFIG_HOME="$HOME/.config"
mkdir -p "$HOME"

pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

echo "=== [1] setup: init + attach vault, seed encrypted"
"$DOP" init >/dev/null
"$DOP" init --vault "$WORKROOT/vault-bare" >/dev/null 2>&1
DOP_CLONE="$HOME/Library/Application Support/dop/vault"
[[ -d "$DOP_CLONE" ]] || DOP_CLONE="$HOME/.config/dop/vault"
cp testdata/vault.example.yaml "$DOP_CLONE/vault.plain.yaml"
"$DOP" encrypt "$DOP_CLONE/vault.plain.yaml" "$DOP_CLONE/vault.yaml" >/dev/null 2>&1
rm "$DOP_CLONE/vault.plain.yaml"
pass "vault ready"

VAULT="$DOP_CLONE/vault.yaml"

echo "=== [2] token issue (read-only grants, no confirmation needed)"
NEW_TOKEN=$("$DOP" --no-such-flag 2>/dev/null || true)  # noop to avoid unused-var lint
NEW_TOKEN=$("$DOP" token issue --vault "$VAULT" --grants boiler.read,notion.read --name "e2e-readonly")
if [[ -z "$NEW_TOKEN" ]]; then
    fail "no token emitted on stdout"
fi
if [[ "$NEW_TOKEN" != tok_* ]]; then
    fail "token doesn't have tok_ prefix: $NEW_TOKEN"
fi
pass "issued: $NEW_TOKEN"

echo "=== [3] exec with new token → scoped env resolves"
env_out=$(DOP_TOKEN="$NEW_TOKEN" "$DOP" exec --no-pull --vault "$VAULT" --agent-name "e2e" -- env 2>/dev/null)
echo "$env_out" | grep -q "BOILER_TOKEN=blr_ro_FIXTURE_TOKEN_READ" || fail "readonly BOILER_TOKEN missing"
echo "$env_out" | grep -q "NOTION_TOKEN=ntn_ro_FIXTURE_TOKEN" || fail "readonly NOTION_TOKEN missing"
pass "scope resolves"

echo "=== [4] token list — shows record without leaking bearer"
list_out=$("$DOP" token list --vault "$VAULT" 2>/dev/null)
echo "$list_out" | grep -q "e2e-readonly" || fail "issued name missing from list"
if echo "$list_out" | grep -q "$NEW_TOKEN"; then
    fail "list output leaked the bearer!"
fi
pass "list shows metadata only"

echo "=== [5] revoke by name → subsequent exec fails"
"$DOP" token revoke --vault "$VAULT" "e2e-readonly" 2>/dev/null
if DOP_TOKEN="$NEW_TOKEN" "$DOP" exec --no-pull --vault "$VAULT" --agent-name "e2e" -- true 2>/dev/null; then
    fail "revoked token still resolves — expected exec to fail"
fi
pass "revoked token no longer resolves"

echo "=== [6] issue with sensitive grant WITHOUT --yes → aborts"
if "$DOP" token issue --vault "$VAULT" --grants boiler.write --name "unsafe" </dev/null 2>/dev/null; then
    fail "sensitive-grant issue succeeded without confirmation"
fi
# Verify no token created
if "$DOP" token list --vault "$VAULT" 2>/dev/null | grep -q "unsafe"; then
    fail "aborted issue left a token in the vault"
fi
pass "sensitive grant rejected without confirmation"

echo "=== [7] issue with sensitive grant + --yes → succeeds"
SENSITIVE_TOKEN=$("$DOP" token issue --vault "$VAULT" --grants boiler.write --name "e2e-writer" --yes 2>/dev/null)
if [[ "$SENSITIVE_TOKEN" != tok_* ]]; then
    fail "sensitive token not issued with --yes"
fi
env_out=$(DOP_TOKEN="$SENSITIVE_TOKEN" "$DOP" exec --no-pull --vault "$VAULT" --agent-name "e2e" -- env 2>/dev/null)
echo "$env_out" | grep -q "BOILER_TOKEN=blr_rw_FIXTURE_TOKEN_WRITE" || fail "write scope not resolved"
pass "sensitive token issues and resolves under --yes"

echo ""
echo "P2 e2e: PASS"
