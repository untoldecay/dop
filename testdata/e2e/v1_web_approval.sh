#!/usr/bin/env bash
# V1.6 e2e: web-page approval via passphrase.
# Skips cloudflared (uses --no-tunnel) and hits the local server with
# curl the way a phone browser would.

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "V1.6 e2e: no dop at $DOP" >&2; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v16-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
mkdir -p "$HOME"
export DOP_NO_TUI=1
export DOP_NO_NOTIFY=1

PASS="pass-word-long-enough"
APPROVAL="approve-me-secret"
CFG_ROOT="$HOME/Library/Application Support/dop"
VAULT_DIR="$CFG_ROOT/vault"

echo "=== [1] setup"
printf "%s\n%s\n" "$PASS" "$APPROVAL" | "$DOP" admin init --passphrase-stdin >/dev/null
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

echo "=== [2] issue + start claim with local web server"
issue_out=$("$DOP" token issue --grants notion.read --name webagent 2>&1)
BEARER=$(echo "$issue_out" | grep -E '^tok_1' | head -1)
PIN=$(echo "$issue_out" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)

DOP_TOKEN="$BEARER" "$DOP" claim --no-tunnel "$PIN" >"$WORKROOT/claim.out" 2>"$WORKROOT/claim.err" &
CLAIM_PID=$!
# Wait for the URL line to appear in stderr.
URL=""
for _ in {1..30}; do
    URL=$( (grep -oE 'http://127.0.0.1:[0-9]+/c/[a-f0-9]+' "$WORKROOT/claim.err" 2>/dev/null || true) | head -1 )
    if [[ -n "$URL" ]]; then break; fi
    sleep 0.2
done
[[ -n "$URL" ]] || { cat "$WORKROOT/claim.err"; fail "no URL from claim"; }
pass "server up at $URL"

echo "=== [3] GET the page returns HTML with the subject"
body=$(curl -s "$URL")
echo "$body" | grep -q 'webagent' || fail "page didn't render subject"
echo "$body" | grep -q 'Approval passphrase' || fail "form missing"
# The form action must include the display token — otherwise a submit
# resolves to /c/approve without the token and 404s.
tok=$(echo "$URL" | grep -oE '/c/[a-f0-9]+' | head -1 | cut -d/ -f3)
echo "$body" | grep -q "/c/$tok/approve" || fail "form action missing token"
pass "page renders (form action absolute)"

echo "=== [4] POST wrong passphrase → error visible, no approval"
body=$(curl -s -X POST -d "passphrase=totally-wrong-shhh" "$URL/approve")
echo "$body" | grep -q "incorrect passphrase" || fail "wrong passphrase didn't error"
# Claim should still be running.
if ! kill -0 "$CLAIM_PID" 2>/dev/null; then
    fail "claim exited after wrong passphrase"
fi
pass "wrong passphrase rejected in-band"

echo "=== [5] POST correct passphrase → claim unblocks"
curl -s -X POST -d "passphrase=$APPROVAL" "$URL/approve" >/dev/null
wait $CLAIM_PID || fail "claim didn't succeed"
grep -q "bound" "$WORKROOT/claim.err" || { cat "$WORKROOT/claim.err"; fail "no bound message"; }
pass "passphrase approves"

echo "=== [6] page after decision → 410 Gone"
body=$(curl -s -o /dev/null -w '%{http_code}' "$URL") || true
# Server has shut down by now — 000 (connection refused) or 410 both OK.
if [[ "$body" != "000" && "$body" != "410" ]]; then
    fail "expected 000/410 after decision, got $body"
fi
pass "server closes after decision"

echo "=== [7] URL with wrong token → 404 (no side channel)"
issue2=$("$DOP" token issue --grants notion.read --name webB 2>&1)
B2=$(echo "$issue2" | grep -E '^tok_1' | head -1)
P2=$(echo "$issue2" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
DOP_TOKEN="$B2" "$DOP" claim --no-tunnel "$P2" >/dev/null 2>"$WORKROOT/claim2.err" &
CLAIM2=$!
URL2=""
for _ in {1..30}; do
    URL2=$( (grep -oE 'http://127.0.0.1:[0-9]+/c/[a-f0-9]+' "$WORKROOT/claim2.err" 2>/dev/null || true) | head -1 )
    if [[ -n "$URL2" ]]; then break; fi
    sleep 0.2
done
BASE=$(echo "$URL2" | grep -oE 'http://127.0.0.1:[0-9]+')
code=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/c/deadbeefdeadbeef")
[[ "$code" == "404" ]] || fail "wrong token should 404, got $code"
pass "wrong token 404s"
# Clean up.
curl -s -X POST "$URL2/reject" >/dev/null
wait $CLAIM2 2>/dev/null || true

echo ""
echo "V1.6 web approval e2e: PASS"
