#!/usr/bin/env bash
# V1.7 e2e: dop-credential-git shim + host→grant map.
# Drives the credential-helper directly via git-credential protocol.

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
SHIM="${DOP_SHIM:-$(pwd)/dop-credential-git}"
[[ -x "$DOP" ]] || { echo "no dop"; exit 2; }
[[ -x "$SHIM" ]] || { echo "no shim at $SHIM"; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-credhelper-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
mkdir -p "$HOME"
export DOP_NO_TUI=1
export DOP_NO_NOTIFY=1

PASS="pass-word-long-enough"
export DOP_APPROVAL_PASSPHRASE="$PASS-approve"
CFG_ROOT="$HOME/Library/Application Support/dop"
VAULT_DIR="$CFG_ROOT/vault"

echo "=== [1] setup admin + vault + issue bearer"
printf "%s\n%s\n" "$PASS" "$PASS-approve" | "$DOP" admin init --passphrase-stdin >/dev/null
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null
"$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1
cat > "$VAULT_DIR/vault.yaml" <<'EOF'
schema_version: v1
integrations:
  github:
    metadata: {base_url: "https://api.github.com"}
    tokens:
      readonly:
        value: "ghp_readonly_secret_value"
grants:
  github.readonly:
    integration: github
    token: readonly
    env_prefix: GITHUB
EOF
BEARER=$("$DOP" token issue --no-bind --grants github.readonly --name ci-bot 2>/dev/null | grep -E '^tok_1' | head -1)
[[ -n "$BEARER" ]] || fail "no bearer"
pass "bearer issued"

echo "=== [2] map github.com → github.readonly"
"$DOP" credential-helper map --host github.com --grant github.readonly --username oauth >/dev/null 2>&1
"$DOP" credential-helper list 2>&1 | grep -q "github.com" || fail "map not persisted"
pass "host mapped"

echo "=== [3] shim get for mapped host returns the credential"
in=$(printf "protocol=https\nhost=github.com\n\n")
out=$(DOP_TOKEN="$BEARER" echo "$in" | DOP_TOKEN="$BEARER" "$SHIM" get)
echo "$out" | grep -q "password=ghp_readonly_secret_value" || { echo "$out"; fail "wrong or missing password"; }
echo "$out" | grep -q "username=oauth" || fail "username missing"
pass "credential returned for mapped host"

echo "=== [4] shim get for unmapped host emits nothing"
in=$(printf "protocol=https\nhost=example.com\n\n")
out=$(DOP_TOKEN="$BEARER" echo "$in" | DOP_TOKEN="$BEARER" "$SHIM" get)
[[ -z "$(echo "$out" | grep -v '^$')" ]] || { echo "$out"; fail "shim should decline for unmapped host"; }
pass "unmapped host declined silently"

echo "=== [5] shim get without DOP_TOKEN emits nothing (falls through)"
in=$(printf "protocol=https\nhost=github.com\n\n")
out=$(unset DOP_TOKEN; echo "$in" | "$SHIM" get 2>/dev/null || true)
[[ -z "$(echo "$out" | grep -v '^$')" ]] || fail "shim should decline without bearer"
pass "missing bearer falls through"

echo "=== [6] store + erase are no-ops"
in=$(printf "protocol=https\nhost=github.com\nusername=foo\npassword=bar\n\n")
"$SHIM" store <<< "$in" 2>&1 | grep -qE "." && fail "store should be silent" || true
"$SHIM" erase <<< "$in" 2>&1 | grep -qE "." && fail "erase should be silent" || true
pass "store/erase are silent no-ops"

echo "=== [7] remove mapping → shim declines again"
"$DOP" credential-helper remove --host github.com >/dev/null 2>&1
in=$(printf "protocol=https\nhost=github.com\n\n")
out=$(DOP_TOKEN="$BEARER" echo "$in" | DOP_TOKEN="$BEARER" "$SHIM" get)
[[ -z "$(echo "$out" | grep -v '^$')" ]] || fail "shim should decline after remove"
pass "remove works"

echo ""
echo "V1.7 credential-helper e2e: PASS"
