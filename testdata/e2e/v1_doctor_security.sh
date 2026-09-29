#!/usr/bin/env bash
# V1.7 e2e: dop doctor — comprehensive health check.

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "no dop"; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-doctor-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
mkdir -p "$HOME"
export DOP_NO_TUI=1
export DOP_NO_NOTIFY=1

PASS="pass-word-long-enough"
CFG_ROOT="$HOME/Library/Application Support/dop"
VAULT_DIR="$CFG_ROOT/vault"

echo "=== [1] fresh install — doctor flags what's missing"
out=$("$DOP" doctor 2>&1)
echo "$out" | grep -q "install:type" || fail "no install-type line"
echo "$out" | grep -q "binary:sops" || fail "no sops line"
echo "$out" | grep -q "binary:git" || fail "no git line"
pass "basic checks emitted on empty install"

echo "=== [2] admin init + login → session line updates"
printf "%s\n%s\n" "$PASS" "$PASS-approve" | "$DOP" admin init --passphrase-stdin >/dev/null
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null
"$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1
out=$("$DOP" doctor 2>&1)
echo "$out" | grep -q "install:type.*admin" || fail "admin install not detected"
echo "$out" | grep -q "admin:session.*unlocked" || fail "session not shown as unlocked"
echo "$out" | grep -q "admin:approval-passphrase.*configured" || fail "approval passphrase not detected"
pass "session + approval passphrase detected"

echo "=== [3] issue a token → sidecar consistency good"
cat > "$VAULT_DIR/vault.yaml" <<'EOF'
schema_version: v1
integrations:
  notion: {tokens: {read: {value: "n"}}}
grants:
  notion.read: {integration: notion, token: read, env_prefix: N}
EOF
"$DOP" token issue --no-bind --grants notion.read --name doctortest >/dev/null 2>&1
out=$("$DOP" doctor 2>&1)
echo "$out" | grep -q "vault:sidecars.*matched" || { echo "$out"; fail "sidecar consistency not reported"; }
echo "$out" | grep -q "vault:trust.*1 admin" || fail "trust file not detected"
pass "trust + sidecars reported"

echo "=== [4] remove a record → orphan detection"
REC=$(ls "$VAULT_DIR/capabilities"/*.record 2>/dev/null | head -1)
rm -f "$REC"
out=$("$DOP" doctor 2>&1)
echo "$out" | grep -qE "vault:sidecars.*bundle.*without.*record" || { echo "$out"; fail "orphan bundle not flagged"; }
pass "orphan bundle detected"

echo "=== [5] corrupt gen-cache → doctor flags it"
mkdir -p "$CFG_ROOT/gen-cache"
echo "not-a-number-shhh" > "$CFG_ROOT/gen-cache/deadbeef"
out=$("$DOP" doctor 2>&1)
echo "$out" | grep -q "cache:generation.*corrupt" || { echo "$out"; fail "corrupt cache not flagged"; }
pass "corrupt gen-cache flagged"

echo "=== [6] audit log health"
out=$("$DOP" doctor 2>&1)
echo "$out" | grep -qE "audit:log.*events" || fail "audit line missing"
pass "audit log reported"

echo "=== [7] --security section adds warnings"
out=$("$DOP" doctor --security 2>&1)
echo "$out" | grep -q "security" || fail "security section missing"
pass "security mode active"

echo ""
echo "V1.7 doctor e2e: PASS"
