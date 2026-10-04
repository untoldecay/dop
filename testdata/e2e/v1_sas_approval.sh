#!/usr/bin/env bash
# V1.5 e2e: SAS approval gate.
# The agent's `dop claim` blocks until an admin `dop approve <SAS>`
# lands (or `dop reject`, or TTL expiry).

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "V1.5 e2e: no dop at $DOP" >&2; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v15-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
mkdir -p "$HOME"
export DOP_NO_TUI=1
export DOP_NO_KEYCHAIN=1
export DOP_NO_NOTIFY=1

PASS="pass-word-long-enough"
export DOP_APPROVAL_PASSPHRASE="$PASS-approve"
CFG_ROOT="$HOME/Library/Application Support/dop"
VAULT_DIR="$CFG_ROOT/vault"
PENDING_DIR="$CFG_ROOT/pending-claims"
LOG="$CFG_ROOT/logs/audit.jsonl"

echo "=== [1] setup"
printf "%s\n%s\n" "$PASS" "$PASS-approve" | "$DOP" admin init --passphrase-stdin >/dev/null
"$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null
cat > "$VAULT_DIR/vault.yaml" <<'EOF'
schema_version: v1
integrations:
  notion:
    metadata: {base_url: "https://api.notion.com/v1"}
    tokens: {read: {value: "ntn_xxx"}}
grants:
  notion.read: {integration: notion, token: read, env_prefix: NOTION}
EOF

echo "=== [2] issue → bearer + PIN"
issue_out=$("$DOP" token issue --grants notion.read --name sasagent 2>&1)
BEARER=$(echo "$issue_out" | grep -E '^tok_1' | head -1)
PIN=$(echo "$issue_out" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
pass "issued"

echo "=== [3] approve happy path — claim in background (no-tunnel), approve unblocks"
DOP_TOKEN="$BEARER" "$DOP" claim --no-tunnel "$PIN" >"$WORKROOT/claim.out" 2>"$WORKROOT/claim.err" &
CLAIM_PID=$!
# Poll for the pending file to appear.
for _ in {1..20}; do
    if [[ -d "$PENDING_DIR" ]] && [[ -n "$(ls "$PENDING_DIR" 2>/dev/null)" ]]; then break; fi
    sleep 0.2
done
[[ -n "$(ls "$PENDING_DIR" 2>/dev/null)" ]] || fail "pending-claim file never appeared"
SAS=$("$DOP" pending 2>&1 | awk 'NR==2 {print $1}')
[[ -n "$SAS" && "$SAS" != "SAS" ]] || fail "no SAS from dop pending"
pass "pending listed (SAS=$SAS)"

echo -n "$PASS-approve" | "$DOP" approve --passphrase-stdin "$SAS" >/dev/null 2>&1 || fail "approve failed"
wait $CLAIM_PID || fail "claim didn't succeed after approve"
grep -q "bound" "$WORKROOT/claim.err" || { cat "$WORKROOT/claim.err"; fail "claim didn't log 'bound'"; }
pass "approval unblocks claim"

echo "=== [4] agent key present, exec works"
DOP_TOKEN="$BEARER" "$DOP" exec --agent-name a -- env 2>/dev/null | grep -q "NOTION_TOKEN=" || fail "exec broke"
pass "post-approval exec works"

echo "=== [5] reject path — claim in background, reject aborts"
issue2=$("$DOP" token issue --grants notion.read --name sasR 2>&1)
B2=$(echo "$issue2" | grep -E '^tok_1' | head -1)
P2=$(echo "$issue2" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
DOP_TOKEN="$B2" "$DOP" claim --no-tunnel "$P2" >/dev/null 2>"$WORKROOT/claim2.err" &
CLAIM2=$!
for _ in {1..20}; do
    if ls "$PENDING_DIR"/*.json >/dev/null 2>&1; then break; fi
    sleep 0.2
done
SAS2=$("$DOP" pending 2>&1 | awk 'NR==2 {print $1}')
"$DOP" reject "$SAS2" >/dev/null 2>&1 || fail "reject failed"
if wait $CLAIM2; then
    fail "claim should exit non-zero after reject"
fi
grep -q "rejected" "$WORKROOT/claim2.err" || { cat "$WORKROOT/claim2.err"; fail "no reject reason surfaced"; }
pass "reject aborts claim"

echo "=== [6] audit log carries pending + approved + rejected"
grep -q '"event":"claim_pending"' "$LOG" || fail "no claim_pending"
grep -q '"event":"claim_approved"' "$LOG" || fail "no claim_approved"
grep -q '"reason":"rejected"' "$LOG" || fail "no rejected reason"
pass "audit trail complete"

echo "=== [7] approve/reject with typo — unknown SAS"
if echo -n "$PASS-approve" | "$DOP" approve --passphrase-stdin 000-000 2>/dev/null; then
    fail "unknown SAS should fail"
fi
pass "unknown SAS refused"

echo "=== [8] approve without passphrase → refused"
issue3=$("$DOP" token issue --grants notion.read --name sasP 2>&1)
B3=$(echo "$issue3" | grep -E '^tok_1' | head -1)
P3=$(echo "$issue3" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
DOP_TOKEN="$B3" "$DOP" claim --no-tunnel "$P3" >/dev/null 2>"$WORKROOT/claim3.err" &
CLAIM3=$!
for _ in {1..20}; do
    if ls "$PENDING_DIR"/*.json >/dev/null 2>&1; then break; fi
    sleep 0.2
done
SAS3=$("$DOP" pending 2>&1 | awk 'NR==2 {print $1}')
if echo -n "wrong-passphrase-nope" | "$DOP" approve --passphrase-stdin "$SAS3" 2>/dev/null; then
    fail "wrong passphrase should refuse approve"
fi
pass "wrong passphrase refused"
# Clean up the background claim.
"$DOP" reject "$SAS3" >/dev/null 2>&1
wait $CLAIM3 2>/dev/null || true

echo ""
echo "V1.5 SAS approval e2e: PASS"
