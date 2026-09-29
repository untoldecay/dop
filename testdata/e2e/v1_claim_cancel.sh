#!/usr/bin/env bash
# V1.9.4 e2e: dop claim --cancel / --status / --json + stale-file reclaim.

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "V1.9.4 e2e: no dop at $DOP" >&2; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v194-XXXX)
DEBUG_KEEP="${DOP_E2E_KEEP:-0}"
cleanup() { [[ "$DEBUG_KEEP" == "1" ]] || rm -rf "$WORKROOT"; }
trap cleanup EXIT
export HOME="$WORKROOT/home"
mkdir -p "$HOME"
export DOP_NO_TUI=1
export DOP_NO_NOTIFY=1

PASS="pass-word-long-enough"
CFG_ROOT="$HOME/Library/Application Support/dop"
VAULT_DIR="$CFG_ROOT/vault"
PENDING_DIR="$CFG_ROOT/pending-claims"

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

wait_for_pending() {
    for _ in {1..40}; do
        if ls "$PENDING_DIR"/*.json >/dev/null 2>&1; then return 0; fi
        sleep 0.1
    done
    return 1
}
wait_for_json() {
    local file="$1"
    for _ in {1..40}; do
        grep -q '"event":"pending"' "$file" 2>/dev/null && return 0
        sleep 0.1
    done
    return 1
}

echo "=== [2] issue + start a claim in the background"
issue_out=$("$DOP" token issue --grants notion.read --name canceltest 2>&1)
BEARER=$(echo "$issue_out" | grep -E '^tok_1' | head -1)
PIN=$(echo "$issue_out" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
DOP_TOKEN="$BEARER" "$DOP" claim --no-tunnel --json "$PIN" >"$WORKROOT/claim.out" 2>"$WORKROOT/claim.err" &
CLAIM_PID=$!
wait_for_pending || { cat "$WORKROOT/claim.err"; fail "pending file never appeared"; }
pass "claim spawned + pending file present"

echo "=== [3] --json emitted the pending event"
wait_for_json "$WORKROOT/claim.out" || { cat "$WORKROOT/claim.out"; cat "$WORKROOT/claim.err"; fail "no pending JSON"; }
grep -q '"sas":' "$WORKROOT/claim.out" || fail "no SAS in JSON"
grep -q '"public_url":' "$WORKROOT/claim.out" || fail "no public_url in JSON"
grep -q '"qr_png":' "$WORKROOT/claim.out" || fail "no qr_png in JSON"
pass "JSON pending event has sas + public_url + qr_png"

echo "=== [3b] v1.9.9 — QR PNG canvas ≤ 500x500"
QRPATH=$(grep -Eo '"qr_png":"[^"]+"' "$WORKROOT/claim.out" | head -1 | sed 's/^"qr_png":"//; s/"$//')
[[ -n "$QRPATH" && -f "$QRPATH" ]] || fail "qr_png path missing or file absent ($QRPATH)"
# Extract PNG dimensions from IHDR (bytes 16-23, big-endian uint32).
# hexdump lets us read each byte and combine.
HEX=$(hexdump -v -e '/1 "%02x"' -n 8 -s 16 "$QRPATH" 2>/dev/null)
QRW=$((16#${HEX:0:8}))
QRH=$((16#${HEX:8:8}))
[[ -n "$QRW" && -n "$QRH" ]] || fail "could not parse PNG dims from $QRPATH"
if (( QRW > 500 || QRH > 500 )); then
    fail "QR PNG too large: ${QRW}x${QRH} (must be ≤ 500x500)"
fi
pass "QR PNG dims ${QRW}x${QRH} (≤ 500x500 chat-relay-safe)"

echo "=== [4] --status reports pending"
DOP_TOKEN="$BEARER" "$DOP" claim --status --json > "$WORKROOT/status.out" 2>&1 || { cat "$WORKROOT/status.out"; fail "--status failed"; }
grep -q '"state":"pending"' "$WORKROOT/status.out" || { cat "$WORKROOT/status.out"; fail "--status wrong state"; }
pass "--status: pending"

echo "=== [5] --cancel removes the file + running claim exits"
DOP_TOKEN="$BEARER" "$DOP" claim --cancel >/dev/null 2>&1 || fail "--cancel exit code"
# Give the poll loop a tick to notice.
for _ in {1..20}; do
    if ! kill -0 $CLAIM_PID 2>/dev/null; then break; fi
    sleep 0.5
done
if kill -0 $CLAIM_PID 2>/dev/null; then
    kill -9 $CLAIM_PID 2>/dev/null || true
    fail "running claim did not exit after --cancel"
fi
wait $CLAIM_PID 2>/dev/null || true
grep -q '"state":"aborted"' "$WORKROOT/claim.out" || { cat "$WORKROOT/claim.out"; fail "no aborted JSON on the cancelled claim"; }
pass "--cancel wakes the polling claim → aborted JSON event"

echo "=== [6] pending directory empty"
[[ -z "$(ls "$PENDING_DIR" 2>/dev/null | grep -v .lock || true)" ]] || fail "pending-claim file still present"
pass "pending file gone"

echo "=== [7] --status reports absent"
DOP_TOKEN="$BEARER" "$DOP" claim --status --json > "$WORKROOT/status2.out" 2>&1
grep -q '"state":"absent"' "$WORKROOT/status2.out" || { cat "$WORKROOT/status2.out"; fail "--status wrong state"; }
pass "--status: absent"

echo "=== [8] stale-file reclaim: forge a dead-PID pending file, next claim proceeds"
# Get lookup_id via a fresh JSON status (won't populate a file, just derive).
# Instead: manually forge a file with our lookup and PID=99999.
LOOKUP=$(DOP_TOKEN="$BEARER" "$DOP" claim --status --json 2>&1 | sed 's/.*"lookup_id":"\([^"]*\)".*/\1/')
[[ -n "$LOOKUP" && "$LOOKUP" != *'"'* ]] || fail "could not derive lookup_id ($LOOKUP)"
FORGED="$PENDING_DIR/$LOOKUP.json"
# Use a bogus PID that isn't in use — we choose a high number and verify.
BADPID=999999
kill -0 $BADPID 2>/dev/null && BADPID=888888
kill -0 $BADPID 2>/dev/null && BADPID=777777
cat > "$FORGED" <<EOF
{"sas":"999-999","lookup_id":"$LOOKUP","capability_id":"aa","subject":"stale","pubkey":"bb","started_at":"2020-01-01T00:00:00Z","expires_at":"2099-01-01T00:00:00Z","state":"pending","pid":$BADPID,"host":"$(hostname)"}
EOF
# Now start a new claim — should NOT get "reject it first"; instead should
# reclaim the slot and proceed to write its own pending record.
DOP_TOKEN="$BEARER" "$DOP" claim --no-tunnel --json "$PIN" >"$WORKROOT/claim2.out" 2>"$WORKROOT/claim2.err" &
CLAIM2=$!
if ! wait_for_json "$WORKROOT/claim2.out"; then
    kill -9 $CLAIM2 2>/dev/null || true
    echo "--- claim2.out ---"; cat "$WORKROOT/claim2.out"
    echo "--- claim2.err ---"; cat "$WORKROOT/claim2.err"
    fail "stale-reclaim: new claim never emitted a pending JSON event"
fi
# The new claim's SAS must NOT be the forged "999-999".
grep '"event":"pending"' "$WORKROOT/claim2.out" | grep -qv '"sas":"999-999"' || {
    cat "$WORKROOT/claim2.out"
    fail "stale record was not replaced"
}
pass "dead-PID stale file reclaimed silently"

DOP_TOKEN="$BEARER" "$DOP" claim --cancel >/dev/null 2>&1
wait $CLAIM2 2>/dev/null || true
pkill -9 -f "dop admin __session-daemon" 2>/dev/null || true

echo "V1.9.4 claim cancel/status/json e2e: PASS"
