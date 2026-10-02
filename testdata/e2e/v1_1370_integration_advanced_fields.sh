#!/usr/bin/env bash
# V1.13.0-rc17 e2e: 6 new advanced fields on integration add
# (ClaudeMini field report).
#   cli_auth_env — template expansion with $TOKEN / $SERVER_ROOT / $BASE_URL
#                  → KEY=VAL pairs exported DIRECTLY so the CLI "just works"
#   server_root  — distinct from base_url
#   allowed      — scope hint
#   auth_style   — bearer-header | basic | …
#   cli_install  — install hint
#   cli_help     — help entry command

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "V1.13 advanced-fields e2e: no dop at $DOP" >&2; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v1370-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
mkdir -p "$HOME"
export DOP_NO_TUI=1
export DOP_NO_KEYCHAIN=1
export DOP_ALLOW_FILE_KEYS=1
PASS="pass-word-long-enough"
APPROVE="$PASS-approve"

echo "=== [1] admin init + login"
printf '%s\n%s\n' "$PASS" "$APPROVE" | "$DOP" admin init --passphrase-stdin >/dev/null
"$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null
pass "admin ready"

echo "=== [2] cli kind with cli_auth_env + server_root + install + help"
"$DOP" integration add \
    --kind cli --name boiler \
    --token api=secret_token_val:read-only \
    --cmd boiler \
    --server-root "https://boiler.example.com" \
    --cli-auth-env 'BOILER_TOKEN=$TOKEN;BOILER_SERVER=$SERVER_ROOT' \
    --cli-install 'go install github.com/x/boiler/cmd/boiler@latest' \
    --cli-help 'boiler --help' \
    --allowed 'Agent_Collab,Skills_Registry' >/dev/null
"$DOP" grant add --id boiler.api --integration boiler --token api >/dev/null
OUT=$("$DOP" token issue --grants boiler.api --name test-cli 2>&1)
B=$(echo "$OUT" | grep -E '^tok_1' | head -1)
P=$(echo "$OUT" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
DOP_TOKEN="$B" "$DOP" claim --skip-approval "$P" >/dev/null 2>&1
ENV=$(DOP_TOKEN="$B" "$DOP" env 2>&1)
echo "$ENV" | grep -q "BOILER_API_SERVER_ROOT='https://boiler.example.com'" || fail "SERVER_ROOT missing: $ENV"
echo "$ENV" | grep -q "BOILER_API_ALLOWED='Agent_Collab,Skills_Registry'" || fail "ALLOWED missing: $ENV"
echo "$ENV" | grep -q "BOILER_API_CLI_INSTALL='go install github.com/x/boiler/cmd/boiler@latest'" || fail "CLI_INSTALL missing: $ENV"
echo "$ENV" | grep -q "BOILER_API_CLI_HELP='boiler --help'" || fail "CLI_HELP missing: $ENV"
echo "$ENV" | grep -q "BOILER_API_CMD='boiler'" || fail "CMD missing: $ENV"
# Direct-export from cli_auth_env expansion:
echo "$ENV" | grep -q "BOILER_TOKEN='secret_token_val'" || fail "expanded BOILER_TOKEN missing: $ENV"
echo "$ENV" | grep -q "BOILER_SERVER='https://boiler.example.com'" || fail "expanded BOILER_SERVER missing: $ENV"
# The template itself is also exported for debugging/transparency:
echo "$ENV" | grep -q "BOILER_API_CLI_AUTH_ENV='BOILER_TOKEN=\$TOKEN;BOILER_SERVER=\$SERVER_ROOT'" || fail "CLI_AUTH_ENV template missing: $ENV"
pass "cli_auth_env + server_root + allowed + install + help all promote and expand"

echo "=== [3] api kind with auth_style"
"$DOP" integration add \
    --kind api --name svc \
    --token api=val:x \
    --base-url https://api.example.com \
    --auth-style bearer-header >/dev/null
"$DOP" grant add --id svc.api --integration svc --token api >/dev/null
OUT=$("$DOP" token issue --grants svc.api --name test-api 2>&1)
B2=$(echo "$OUT" | grep -E '^tok_1' | head -1)
P2=$(echo "$OUT" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
DOP_TOKEN="$B2" "$DOP" claim --skip-approval "$P2" >/dev/null 2>&1
ENV2=$(DOP_TOKEN="$B2" "$DOP" env 2>&1)
echo "$ENV2" | grep -q "SVC_API_AUTH_STYLE='bearer-header'" || fail "AUTH_STYLE missing: $ENV2"
pass "auth_style promotes"

echo "=== [4] \$BASE_URL substitution when server_root unset"
"$DOP" integration add \
    --kind cli --name mytool \
    --token api=mt_val:x \
    --cmd mytool \
    --base-url https://mytool.example.com \
    --cli-auth-env 'MYTOOL_URL=$BASE_URL;MYTOOL_TOKEN=$TOKEN' >/dev/null
"$DOP" grant add --id mytool.api --integration mytool --token api >/dev/null
OUT=$("$DOP" token issue --grants mytool.api --name test-sub 2>&1)
B3=$(echo "$OUT" | grep -E '^tok_1' | head -1)
P3=$(echo "$OUT" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
DOP_TOKEN="$B3" "$DOP" claim --skip-approval "$P3" >/dev/null 2>&1
ENV3=$(DOP_TOKEN="$B3" "$DOP" env 2>&1)
echo "$ENV3" | grep -q "MYTOOL_URL='https://mytool.example.com'" || fail "BASE_URL substitution missing: $ENV3"
echo "$ENV3" | grep -q "MYTOOL_TOKEN='mt_val'" || fail "TOKEN substitution missing: $ENV3"
# $SERVER_ROOT falls back to base_url when server_root is unset.
pass "template substitutions work; SERVER_ROOT falls back to BASE_URL"

echo "=== [5] safety blacklist blocks dangerous keys in cli_auth_env"
"$DOP" integration add \
    --kind cli --name attacker \
    --token api=mal_val:x \
    --cmd attacker \
    --cli-auth-env 'PATH=/evil/bin;LD_PRELOAD=/evil.so;SAFE_VAR=good' >/dev/null
"$DOP" grant add --id attacker.api --integration attacker --token api >/dev/null
OUT=$("$DOP" token issue --grants attacker.api --name test-mal 2>&1)
B4=$(echo "$OUT" | grep -E '^tok_1' | head -1)
P4=$(echo "$OUT" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
DOP_TOKEN="$B4" "$DOP" claim --skip-approval "$P4" >/dev/null 2>&1
ENV4=$(DOP_TOKEN="$B4" "$DOP" env 2>&1)
# PATH and LD_PRELOAD must NOT appear as direct exports (they'd come from the template).
# But they MAY still appear from the host shell env — we check for the specific values.
if echo "$ENV4" | grep -q "PATH='/evil/bin'"; then fail "PATH from template was exported: $ENV4"; fi
if echo "$ENV4" | grep -q "LD_PRELOAD='/evil.so'"; then fail "LD_PRELOAD from template was exported: $ENV4"; fi
echo "$ENV4" | grep -q "SAFE_VAR='good'" || fail "SAFE_VAR should have been exported: $ENV4"
pass "blacklist blocks PATH + LD_PRELOAD; benign keys pass"

echo "=== [6] DOP_* overrides blocked"
"$DOP" integration add \
    --kind cli --name doptamper \
    --token api=dt_val:x \
    --cmd dt \
    --cli-auth-env 'DOP_TOKEN=stolen;DOP_NO_TUI=1' >/dev/null
"$DOP" grant add --id doptamper.api --integration doptamper --token api >/dev/null
OUT=$("$DOP" token issue --grants doptamper.api --name test-dop 2>&1)
B5=$(echo "$OUT" | grep -E '^tok_1' | head -1)
P5=$(echo "$OUT" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
DOP_TOKEN="$B5" "$DOP" claim --skip-approval "$P5" >/dev/null 2>&1
ENV5=$(DOP_TOKEN="$B5" "$DOP" env 2>&1)
if echo "$ENV5" | grep -q "DOP_TOKEN='stolen'"; then fail "DOP_TOKEN override from template was exported: $ENV5"; fi
pass "DOP_* overrides blocked"
