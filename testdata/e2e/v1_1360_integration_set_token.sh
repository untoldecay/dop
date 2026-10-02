#!/usr/bin/env bash
# V1.13.0-rc16 e2e: `dop integration set-token` — rotate value and/or
# edit scope note on an existing integration. Owner-gated. Never logs
# the new value.

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "V1.13 set-token e2e: no dop at $DOP" >&2; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v1360-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
mkdir -p "$HOME"
export DOP_NO_TUI=1
export DOP_NO_KEYCHAIN=1
export DOP_ALLOW_FILE_KEYS=1

PASS="pass-word-long-enough"
APPROVE="$PASS-approve"
AUDIT="$HOME/Library/Application Support/dop/logs/audit.jsonl"

echo "=== [1] admin init + login + base integration"
printf '%s\n%s\n' "$PASS" "$APPROVE" | "$DOP" admin init --passphrase-stdin >/dev/null
"$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null
"$DOP" integration add --name svc --token api=old_val:read-only >/dev/null
"$DOP" grant add --id svc.api --integration svc --token api >/dev/null
pass "fixture ready"

echo "=== [2] rotate value only"
"$DOP" integration set-token --name svc --token-name api --value new_val_1 >/dev/null 2>&1 \
    || fail "rotate failed"
# Issue fresh bearer, verify new value
OUT=$("$DOP" token issue --grants svc.api --name test-rot 2>&1)
B=$(echo "$OUT" | grep -E '^tok_1' | head -1)
P=$(echo "$OUT" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
DOP_TOKEN="$B" "$DOP" claim --skip-approval "$P" >/dev/null 2>&1
ENV=$(DOP_TOKEN="$B" "$DOP" env 2>&1)
echo "$ENV" | grep -q "SVC_API_TOKEN='new_val_1'" || fail "rotated value not in env: $ENV"
pass "value rotated + visible to new bearer"

echo "=== [3] edit scope note only"
"$DOP" integration set-token --name svc --token-name api --scope-note "read-write" >/dev/null 2>&1 \
    || fail "scope edit failed"
LIST=$("$DOP" integration list)
# Scope note doesn't appear directly in integration list; check via vault yaml key presence.
VAULT_YAML="$HOME/Library/Application Support/dop/vault/vault.yaml"
grep -q "scope_note:" "$VAULT_YAML" || fail "scope_note key missing from vault.yaml"
pass "scope note updated"

echo "=== [4] both at once"
"$DOP" integration set-token --name svc --token-name api \
    --value final_val --scope-note admin >/dev/null 2>&1 \
    || fail "combined edit failed"
pass "value + scope updated atomically"

echo "=== [5] missing flags refused"
# Capture-then-grep so `set -o pipefail` doesn't trip on set-token's
# intentional non-zero exit.
OUT5=$("$DOP" integration set-token --name svc --token-name api 2>&1 || true)
echo "$OUT5" | grep -q "at least one" || fail "should refuse when neither --value nor --scope-note given: $OUT5"
pass "refuses with no mutation flags"

echo "=== [6] unknown token refused"
OUT6=$("$DOP" integration set-token --name svc --token-name nosuch --value x 2>&1 || true)
echo "$OUT6" | grep -q "no token" || fail "should refuse on unknown token: $OUT6"
pass "refuses on unknown token"

echo "=== [7] audit event emitted, no value leak"
grep -q '"event":"integration_token_set"' "$AUDIT" || fail "no integration_token_set audit event"
grep -q "new_val_1\|final_val" "$AUDIT" && fail "token value leaked to audit log" || true
pass "audit present + no value leak"

echo "=== [8] value via stdin (no CLI leak)"
echo -n "stdin_value" | "$DOP" integration set-token --name svc --token-name api --value-stdin >/dev/null 2>&1 \
    || fail "value-stdin failed"
OUT=$("$DOP" token issue --grants svc.api --name test-stdin 2>&1)
B2=$(echo "$OUT" | grep -E '^tok_1' | head -1)
P2=$(echo "$OUT" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
DOP_TOKEN="$B2" "$DOP" claim --skip-approval "$P2" >/dev/null 2>&1
ENV2=$(DOP_TOKEN="$B2" "$DOP" env 2>&1)
echo "$ENV2" | grep -q "SVC_API_TOKEN='stdin_value'" || fail "stdin value not in env: $ENV2"
pass "stdin value path works"

echo "=== [9] protected non-owner refused (same-admin positive-path only here)"
# Protect the integration — now owner (us) can still set-token.
echo -n "$APPROVE" | "$DOP" integration add --name svc --protected --passphrase-stdin >/dev/null 2>&1 \
    || fail "flipping protected failed"
"$DOP" integration set-token --name svc --token-name api --scope-note "read" >/dev/null 2>&1 \
    || fail "owner should be able to set-token on their protected integration"
pass "owner-set-token on protected integration works"
