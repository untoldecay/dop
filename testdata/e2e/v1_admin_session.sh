#!/usr/bin/env bash
# V1 Phase 2 end-to-end: admin init / login / status / sign RPC / logout.
#
# Uses --passphrase-stdin to feed the passphrase non-interactively.

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "V1 e2e: no dop at $DOP" >&2; exit 2; }

pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v1-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
export XDG_CONFIG_HOME="$HOME/.config"
mkdir -p "$HOME"
export DOP_NO_TUI=1

# Short config root so the socket path stays under macOS's SUN_PATH_MAX.
export XDG_CONFIG_HOME="$WORKROOT/c"

PASSPHRASE="hunter22-open-sesame"

echo "=== [1] dop admin init"
echo -n "$PASSPHRASE" | "$DOP" admin init --passphrase-stdin 2>&1 | head -5
KEYFILE="$HOME/Library/Application Support/dop/keys/admin.age.enc"
[[ -f "$KEYFILE" ]] || KEYFILE="$XDG_CONFIG_HOME/dop/keys/admin.age.enc"
[[ -f "$KEYFILE" ]] || fail "keyfile missing"
[[ "$(stat -f %Lp "$KEYFILE")" == "600" ]] || fail "keyfile perms wrong"
pass "admin key generated"

echo "=== [2] status before login → locked"
out=$("$DOP" admin status)
echo "$out" | grep -q "locked" || fail "expected locked"
pass "status locked pre-login"

echo "=== [3] wrong-passphrase login → error"
if echo -n "wrong-passphrase" | "$DOP" admin login --passphrase-stdin 2>/dev/null; then
    fail "wrong passphrase should have failed"
fi
pass "wrong passphrase rejected"

echo "=== [4] correct login → session starts"
echo -n "$PASSPHRASE" | "$DOP" admin login --passphrase-stdin 2>&1 | head -3
SOCK="$HOME/Library/Application Support/dop/admin.sock"
[[ -S "$SOCK" ]] || SOCK="$XDG_CONFIG_HOME/dop/admin.sock"
[[ -S "$SOCK" ]] || fail "socket missing after login"
pass "session started"

echo "=== [5] status → unlocked"
out=$("$DOP" admin status)
echo "$out" | grep -q "unlocked" || { echo "$out"; fail "expected unlocked"; }
echo "$out" | grep -q "admin pubkey:" || fail "no pubkey in status"
echo "$out" | grep -q "age recipient:" || fail "no age recipient in status"
pass "status unlocked"

echo "=== [6] double-login refused"
if echo -n "$PASSPHRASE" | "$DOP" admin login --passphrase-stdin 2>/dev/null; then
    fail "double login should have refused"
fi
pass "double login refused"

echo "=== [7] logout"
"$DOP" admin logout 2>&1 | head -3
sleep 0.2
[[ ! -S "$SOCK" ]] || fail "socket still present after logout"
pass "socket removed after logout"

echo "=== [8] status after logout → locked"
out=$("$DOP" admin status)
echo "$out" | grep -q "locked" || fail "expected locked"
pass "status locked post-logout"

echo "=== [9] logout on locked session → no-op success"
"$DOP" admin logout 2>&1 | grep -q "no active session" || fail "expected 'no active session' message"
pass "idempotent logout"

echo ""
echo "V1 Phase 2 e2e: PASS"
