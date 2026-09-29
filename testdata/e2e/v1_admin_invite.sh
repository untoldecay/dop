#!/usr/bin/env bash
# V1.9 e2e: admin-invite bootstrap. M1 opens invite → M2 joins → M1
# approves via passphrase → M2 becomes an admin, vault re-encrypted
# for both age recipients.

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "no dop"; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v19-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export DOP_NO_TUI=1
export DOP_NO_NOTIFY=1

BARE="$WORKROOT/bare"
MACHINE_A="$WORKROOT/a"
MACHINE_B="$WORKROOT/b"
mkdir -p "$MACHINE_A" "$MACHINE_B"
PASS_A="pass-word-long-enough"

echo "=== [A1] admin A: init + vault + push"
printf "%s\n%s\n" "$PASS_A" "$PASS_A-approve" | HOME="$MACHINE_A" "$DOP" admin init --passphrase-stdin >/dev/null
echo -n "$PASS_A" | HOME="$MACHINE_A" "$DOP" admin login --passphrase-stdin >/dev/null
HOME="$MACHINE_A" "$DOP" init --vault "$BARE" >/dev/null 2>&1
A_VAULT="$MACHINE_A/Library/Application Support/dop/vault"
cat > "$A_VAULT/vault.yaml" <<'EOF'
schema_version: v1
integrations: {n: {tokens: {r: {value: "v"}}}}
grants: {n.r: {integration: n, token: r}}
EOF
# Seed vault-context so subsequent commands work.
HOME="$MACHINE_A" "$DOP" token issue --no-bind --grants n.r --name seed >/dev/null 2>&1
HOME="$MACHINE_A" "$DOP" push >/dev/null 2>&1 || fail "A push failed"
pass "A initialized"

echo "=== [A2] admin A opens invite for laptop-b (background — polls M2)"
HOME="$MACHINE_A" "$DOP" team invite --name laptop-b --pin-ttl 5m --timeout 3m --passphrase-stdin \
  <<< "$PASS_A-approve" >"$WORKROOT/invite.log" 2>&1 &
INVITE_PID=$!

# Wait for the PIN to be printed.
PIN=""
for _ in {1..30}; do
    PIN=$( (grep -oE 'PIN:.*[A-Z]{2}-[A-Z]{2}-[A-Z]{2}' "$WORKROOT/invite.log" 2>/dev/null || true) | head -1 | awk '{print $2}')
    if [[ -n "$PIN" ]]; then break; fi
    sleep 0.3
done
[[ -n "$PIN" ]] || { cat "$WORKROOT/invite.log"; fail "no PIN emitted"; }
pass "invite opened, PIN=$PIN"

echo "=== [B1] admin B: dop admin join <URL> <PIN>"
# B needs to bootstrap: init (2 passphrases) + unwrap (1) → three lines.
PASS_B="pass-word-long-enough-b"
printf "%s\n%s\n%s\n" "$PASS_B" "$PASS_B-approve" "$PASS_B" | \
  HOME="$MACHINE_B" "$DOP" admin join --passphrase-stdin --timeout 3m "$BARE" "$PIN" \
  >"$WORKROOT/join.log" 2>&1 &
JOIN_PID=$!

# Both sides now polling. Give them time to converge.
for _ in {1..40}; do
    if ! kill -0 $INVITE_PID 2>/dev/null && ! kill -0 $JOIN_PID 2>/dev/null; then break; fi
    sleep 1
done

wait $INVITE_PID
INVITE_RC=$?
wait $JOIN_PID
JOIN_RC=$?

if [[ "$INVITE_RC" != "0" ]]; then
    cat "$WORKROOT/invite.log"
    fail "invite side exited $INVITE_RC"
fi
if [[ "$JOIN_RC" != "0" ]]; then
    cat "$WORKROOT/join.log"
    fail "join side exited $JOIN_RC"
fi
grep -q "approved" "$WORKROOT/invite.log" || { cat "$WORKROOT/invite.log"; fail "no 'approved' in invite log"; }
grep -q "approved" "$WORKROOT/join.log" || { cat "$WORKROOT/join.log"; fail "no 'approved' in join log"; }
pass "both sides converged"

echo "=== [B2] admin B now decrypts the vault (login + list team)"
echo -n "$PASS_B" | HOME="$MACHINE_B" "$DOP" admin login --passphrase-stdin >/dev/null
HOME="$MACHINE_B" "$DOP" team list 2>&1 | grep -q "laptop-b" || fail "B not shown in team list"
HOME="$MACHINE_B" "$DOP" team list 2>&1 | grep -qE "$(hostname)|-2\b|^-" || true
pass "B is an admin, vault decryptable from B"

echo "=== [B3] pending-admin-invites cleaned up"
set +e
left=$( (ls "$A_VAULT/pending-admin-invites"/*.json 2>/dev/null || true) | wc -l | tr -d ' ')
set -e
[[ "$left" == "0" ]] || fail "invite files not cleaned ($left left)"
pass "pending files removed"

echo ""
echo "V1.9 admin-invite e2e: PASS"
