#!/usr/bin/env bash
# V1.13.0-rc13 e2e: Integration kinds — api / cli / mcp / other with
# kind-adaptive env bundles. Covers:
#   [1] api kind — BASE_URL + ENDPOINTS_URL + AUTH_HEADER promote
#   [2] cli kind — CMD + ARGS_HINT promote (not BASE_URL)
#   [3] mcp kind — MCP_URL promotes
#   [4] other kind — only TOKEN + KIND, no promotions
#   [5] legacy integration (no Kind in yaml) treated as api on read
#   [6] mutable kind — flip api → cli on an existing integration
#   [7] integration list prefixes with [kind]

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "V1.13 kind e2e: no dop at $DOP" >&2; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v1340-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
mkdir -p "$HOME"
export DOP_NO_TUI=1
export DOP_NO_KEYCHAIN=1
export DOP_ALLOW_FILE_KEYS=1

PASS="pass-word-long-enough"
APPROVE="$PASS-approve"
export DOP_APPROVAL_PASSPHRASE="$APPROVE"
VAULT_DIR="$HOME/Library/Application Support/dop/vault"

echo "=== [1] admin init + login"
printf '%s\n%s\n' "$PASS" "$APPROVE" | "$DOP" admin init --passphrase-stdin >/dev/null
"$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null
pass "admin ready"

echo "=== [2] api kind — BASE_URL + ENDPOINTS_URL + AUTH_HEADER"
"$DOP" integration add --kind api --name svc-api \
    --token api=api_val:read-only \
    --base-url https://svc.example.com \
    --endpoints-url https://svc.example.com/openapi.json \
    --auth-header "Bearer" >/dev/null 2>&1 || fail "api create failed"
"$DOP" grant add --id svc-api.api --integration svc-api --token api >/dev/null 2>&1
OUT=$("$DOP" token issue --grants svc-api.api --name test-api 2>&1)
BEARER=$(echo "$OUT" | grep -E '^tok_1' | head -1)
PIN=$(echo "$OUT" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
DOP_TOKEN="$BEARER" "$DOP" claim --skip-approval "$PIN" >/dev/null 2>&1
ENV_API=$(DOP_TOKEN="$BEARER" "$DOP" env 2>&1)
echo "$ENV_API" | grep -q "SVC_API_API_KIND='api'" || fail "api KIND missing: $ENV_API"
echo "$ENV_API" | grep -q "SVC_API_API_BASE_URL='https://svc.example.com'" || fail "api BASE_URL missing: $ENV_API"
echo "$ENV_API" | grep -q "SVC_API_API_ENDPOINTS_URL='https://svc.example.com/openapi.json'" || fail "api ENDPOINTS_URL missing: $ENV_API"
echo "$ENV_API" | grep -q "SVC_API_API_AUTH_HEADER='Bearer'" || fail "api AUTH_HEADER missing: $ENV_API"
pass "api env bundle correct"

echo "=== [3] cli kind — CMD + ARGS_HINT (no BASE_URL)"
"$DOP" integration add --kind cli --name boiler-cli \
    --token api=cli_val:read-only \
    --cmd boiler \
    --args-hint "boiler query --json" >/dev/null 2>&1 || fail "cli create failed"
"$DOP" grant add --id boiler-cli.api --integration boiler-cli --token api >/dev/null 2>&1
OUT=$("$DOP" token issue --grants boiler-cli.api --name test-cli 2>&1)
B2=$(echo "$OUT" | grep -E '^tok_1' | head -1)
P2=$(echo "$OUT" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
DOP_TOKEN="$B2" "$DOP" claim --skip-approval "$P2" >/dev/null 2>&1
ENV_CLI=$(DOP_TOKEN="$B2" "$DOP" env 2>&1)
echo "$ENV_CLI" | grep -q "BOILER_CLI_API_KIND='cli'" || fail "cli KIND missing: $ENV_CLI"
echo "$ENV_CLI" | grep -q "BOILER_CLI_API_CMD='boiler'" || fail "cli CMD missing: $ENV_CLI"
echo "$ENV_CLI" | grep -q "BOILER_CLI_API_ARGS_HINT='boiler query --json'" || fail "cli ARGS_HINT missing: $ENV_CLI"
if echo "$ENV_CLI" | grep -q "BOILER_CLI_API_BASE_URL"; then fail "cli should not expose BASE_URL: $ENV_CLI"; fi
pass "cli env bundle correct"

echo "=== [4] mcp kind — MCP_URL"
"$DOP" integration add --kind mcp --name notion-mcp \
    --token api=mcp_val:read \
    --mcp-url https://mcp.notion.example.com >/dev/null 2>&1 || fail "mcp create failed"
"$DOP" grant add --id notion-mcp.api --integration notion-mcp --token api >/dev/null 2>&1
OUT=$("$DOP" token issue --grants notion-mcp.api --name test-mcp 2>&1)
B3=$(echo "$OUT" | grep -E '^tok_1' | head -1)
P3=$(echo "$OUT" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
DOP_TOKEN="$B3" "$DOP" claim --skip-approval "$P3" >/dev/null 2>&1
ENV_MCP=$(DOP_TOKEN="$B3" "$DOP" env 2>&1)
echo "$ENV_MCP" | grep -q "NOTION_MCP_API_KIND='mcp'" || fail "mcp KIND missing: $ENV_MCP"
echo "$ENV_MCP" | grep -q "NOTION_MCP_API_MCP_URL='https://mcp.notion.example.com'" || fail "mcp URL missing: $ENV_MCP"
pass "mcp env bundle correct"

echo "=== [5] other kind — only TOKEN + KIND"
"$DOP" integration add --kind other --name opaque \
    --token api=opaque_val:none >/dev/null 2>&1 || fail "other create failed"
"$DOP" grant add --id opaque.api --integration opaque --token api >/dev/null 2>&1
OUT=$("$DOP" token issue --grants opaque.api --name test-other 2>&1)
B4=$(echo "$OUT" | grep -E '^tok_1' | head -1)
P4=$(echo "$OUT" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
DOP_TOKEN="$B4" "$DOP" claim --skip-approval "$P4" >/dev/null 2>&1
ENV_OTHER=$(DOP_TOKEN="$B4" "$DOP" env 2>&1)
echo "$ENV_OTHER" | grep -q "OPAQUE_API_KIND='other'" || fail "other KIND missing: $ENV_OTHER"
echo "$ENV_OTHER" | grep -q "OPAQUE_API_TOKEN='opaque_val'" || fail "other TOKEN missing: $ENV_OTHER"
pass "other env bundle minimal"

echo "=== [6] legacy integration (no --kind) → treated as api"
"$DOP" integration add --name legacy \
    --token api=legacy_val:read \
    --base-url https://legacy.example.com >/dev/null 2>&1 || fail "legacy create failed"
"$DOP" grant add --id legacy.api --integration legacy --token api >/dev/null 2>&1
OUT=$("$DOP" token issue --grants legacy.api --name test-legacy 2>&1)
B5=$(echo "$OUT" | grep -E '^tok_1' | head -1)
P5=$(echo "$OUT" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
DOP_TOKEN="$B5" "$DOP" claim --skip-approval "$P5" >/dev/null 2>&1
ENV_LEG=$(DOP_TOKEN="$B5" "$DOP" env 2>&1)
echo "$ENV_LEG" | grep -q "LEGACY_API_KIND='api'" || fail "legacy should default to api KIND: $ENV_LEG"
pass "legacy → api default"

echo "=== [7] mutable kind — flip api → cli, visible on next bearer"
"$DOP" integration add --name legacy --kind cli --cmd mycli >/dev/null 2>&1 \
    || fail "flipping kind should succeed on non-protected integration"
# Issue a FRESH bearer — new bearers resolve env from the current
# vault, so no reseal is needed. (Reseal is for keeping an EXISTING
# P-256 bearer in sync; this e2e uses ed25519 to stay simple.)
OUT=$("$DOP" token issue --grants legacy.api --name test-legacy-flipped 2>&1)
B5b=$(echo "$OUT" | grep -E '^tok_1' | head -1)
P5b=$(echo "$OUT" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
DOP_TOKEN="$B5b" "$DOP" claim --skip-approval "$P5b" >/dev/null 2>&1
ENV_FLIP=$(DOP_TOKEN="$B5b" "$DOP" env 2>&1)
echo "$ENV_FLIP" | grep -q "LEGACY_API_KIND='cli'" || fail "flipped kind not visible to agent: $ENV_FLIP"
echo "$ENV_FLIP" | grep -q "LEGACY_API_CMD='mycli'" || fail "flipped CMD not visible: $ENV_FLIP"
pass "kind flipped + new bearer reflects it"

echo "=== [8] integration list — [kind] prefix"
LIST=$("$DOP" integration list)
echo "$LIST" | grep -q "^- \[api\] svc-api" || fail "list missing [api] prefix: $LIST"
echo "$LIST" | grep -q "^- \[cli\] boiler-cli" || fail "list missing [cli] prefix: $LIST"
echo "$LIST" | grep -q "^- \[mcp\] notion-mcp" || fail "list missing [mcp] prefix: $LIST"
echo "$LIST" | grep -q "^- \[other\] opaque" || fail "list missing [other] prefix: $LIST"
pass "list shows kind prefix"
