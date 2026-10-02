#!/usr/bin/env bash
# V1.13.0-rc15 e2e: Endpoints doc probe (opt-in).
# Boots a tiny python http.server that serves:
#   /openapi.json → valid OpenAPI (match)
#   /.well-known/openapi.json → 404 (confirms probe falls through)
#   everything else → 404
# Then runs `dop integration add --kind api --probe-endpoints` and
# asserts the endpoints_url metadata got stamped + audit event fired.

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "V1.13 probe e2e: no dop at $DOP" >&2; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v1350-XXXX)
trap 'kill $MOCK_PID 2>/dev/null || true; rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
mkdir -p "$HOME"
export DOP_NO_TUI=1
export DOP_NO_KEYCHAIN=1
export DOP_ALLOW_FILE_KEYS=1

PASS="pass-word-long-enough"
APPROVE="$PASS-approve"
AUDIT="$HOME/Library/Application Support/dop/logs/audit.jsonl"

echo "=== [1] boot mock HTTP server"
MOCK_DIR="$WORKROOT/mock"
mkdir -p "$MOCK_DIR"
cat > "$MOCK_DIR/openapi.json" <<'EOF'
{"openapi":"3.0.0","info":{"title":"mocksvc","version":"1.0"},"paths":{}}
EOF
# python3 http.server on a fixed-but-random port. Finding a free port
# via `python -c` beats grepping http.server's stderr (which buffers
# and sometimes never shows up in `tail -f`-less captures).
PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')
[[ -n "$PORT" ]] || fail "could not get a free port"
cd "$MOCK_DIR"
python3 -u -m http.server "$PORT" --bind 127.0.0.1 > "$MOCK_DIR/stdout" 2> "$MOCK_DIR/stderr" &
MOCK_PID=$!
cd - >/dev/null
MOCK_URL="http://127.0.0.1:$PORT"
# Wait for the port to accept connections.
for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
    if curl -fsS -o /dev/null "$MOCK_URL/openapi.json" 2>/dev/null; then
        break
    fi
    sleep 0.2
done
curl -fsS -o /dev/null "$MOCK_URL/openapi.json" || fail "mock server at $MOCK_URL did not become reachable: $(cat "$MOCK_DIR/stderr")"
pass "mock serving at $MOCK_URL"

echo "=== [2] admin init + login"
printf '%s\n%s\n' "$PASS" "$APPROVE" | "$DOP" admin init --passphrase-stdin >/dev/null
"$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null
pass "admin ready"

echo "=== [3] integration add --probe-endpoints (api, no --endpoints-url)"
OUT=$("$DOP" integration add --kind api --name mocksvc \
    --token api=val:x \
    --base-url "$MOCK_URL" \
    --probe-endpoints 2>&1)
echo "$OUT" | grep -q "probe → http" || fail "probe should have found a URL: $OUT"
echo "$OUT" | grep -q "openapi.json" || fail "probe should resolve to openapi.json path: $OUT"
pass "probe landed + stamped"

echo "=== [4] audit event present"
grep -q '"event":"integration_probed"' "$AUDIT" || fail "no integration_probed audit event"
grep -q '"result":"found"' "$AUDIT" || fail "audit event should carry result=found"
pass "audit trail present"

echo "=== [5] no_match path — probe against a dead port"
# Pick a port we won't bind to (hopefully unused).
DEAD_URL="http://127.0.0.1:1"
OUT_DEAD=$("$DOP" integration add --kind api --name deadsvc \
    --token api=val:x \
    --base-url "$DEAD_URL" \
    --probe-endpoints 2>&1 || true)
echo "$OUT_DEAD" | grep -q "no match\|probe setup" || fail "dead probe should fall through: $OUT_DEAD"
# Save still succeeds — probe is non-fatal.
LIST=$("$DOP" integration list)
echo "$LIST" | grep -q "deadsvc" || fail "integration should have been saved even when probe failed: $LIST"
pass "probe failure is non-fatal"

echo "=== [6] probe skipped when --endpoints-url already supplied"
OUT_SKIP=$("$DOP" integration add --kind api --name explicitsvc \
    --token api=val:x \
    --base-url "$MOCK_URL" \
    --endpoints-url "$MOCK_URL/custom/path.json" \
    --probe-endpoints 2>&1)
echo "$OUT_SKIP" | grep -q "probe-endpoints skipped" || fail "probe should skip when endpoints_url preset: $OUT_SKIP"
pass "probe honors operator-supplied endpoints_url"
