#!/usr/bin/env bash
# V1.18.1 e2e: a bearer-free agent (no DOP_TOKEN, found by its P-256 key)
# keeps working after the admin rotates its bearer — once, then twice in a
# row before the agent runs again. Before the fix, the old record was
# "rotated" and the bearer-free path skipped it: "no local agent key has
# sealed env to open" (Honey, 2026-10-08).
set -euo pipefail
DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "V1.18.1 bearer-free rotation e2e: no dop at $DOP" >&2; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }
WORKROOT=$(mktemp -d /tmp/dop-v1811-XXXX)
cleanup() { "$DOP" admin logout >/dev/null 2>&1 || true; rm -rf "$WORKROOT"; }
trap cleanup EXIT
export HOME="$WORKROOT/home" DOP_NO_TUI=1 DOP_NO_KEYCHAIN=1 DOP_ALLOW_FILE_KEYS=1 DOP_NO_NOTIFY=1
mkdir -p "$HOME"
PASS="pass-word-long-enough"
export DOP_APPROVAL_PASSPHRASE="$PASS-approve"

git init -q --bare -b main "$WORKROOT/bare"
printf "%s\n%s\n" "$PASS" "$PASS-approve" | "$DOP" admin init --passphrase-stdin >/dev/null
"$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null
CFG_ROOT="$HOME/Library/Application Support/dop"; [[ -d "$CFG_ROOT" ]] || CFG_ROOT="$HOME/.config/dop"
cat > "$CFG_ROOT/vault/vault.yaml" <<'YAML'
schema_version: v1
integrations:
  notion:
    tokens: {read: {value: "ntn_bearer_free_value"}}
grants:
  notion.read: {integration: notion, token: read, env_prefix: NOTION}
YAML

out=$("$DOP" token issue --grants notion.read --name honey 2>&1)
BEARER=$(echo "$out" | grep -E '^tok_1' | head -1)
PIN=$(echo "$out" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
DOP_TOKEN="$BEARER" "$DOP" claim --skip-approval --key-type p256 "$PIN" >/dev/null 2>&1 || fail "claim failed"
"$DOP" token reseal honey >/dev/null 2>&1 || fail "reseal failed"

check() { # bearer-free exec sees the real value
	"$DOP" exec -- sh -c '[ "$NOTION_TOKEN" = ntn_bearer_free_value ]' </dev/null >/dev/null 2>"$WORKROOT/err" \
		|| { cat "$WORKROOT/err"; fail "$1"; }
}

echo "=== [1] bearer-free exec works"
check "bearer-free exec before rotation"
pass "bearer-free exec"

echo "=== [2] admin rotates; bearer-free exec follows"
"$DOP" token rotate honey >/dev/null 2>&1 || fail "rotate failed"
check "bearer-free exec after one rotation"
pass "followed one rotation"
ls "$CFG_ROOT/agent-keys/"*.p256 | wc -l | grep -q '^ *1$' || fail "expected exactly one agent key after the switch"
pass "agent key re-tagged, not duplicated"

echo "=== [3] two rotations before the agent runs again"
"$DOP" token rotate honey >/dev/null 2>&1 || fail "rotate 2 failed"
"$DOP" token rotate honey >/dev/null 2>&1 || fail "rotate 3 failed"
check "bearer-free exec after two rotations in a row"
pass "followed a chain of rotations"

echo "V1.18.1 bearer-free rotation e2e: PASS"
