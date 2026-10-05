#!/usr/bin/env bash
# V1.14.0-rc3 Phase 7 e2e: portable bearer bypass of exec claim gate.
# Covers:
#   [1] setup: admin + integration + grant + portable bearer
#   [2] `dop exec` with portable bearer in DOP_TOKEN runs child WITHOUT claim
#   [3] standard bearer (non-portable) still refuses without claim
#   [4] audit log carries portable_owner=yes on the portable exec

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "V1.14 portable-exec e2e: no dop at $DOP" >&2; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v1430-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
mkdir -p "$HOME"
export DOP_NO_TUI=1
export DOP_NO_KEYCHAIN=1
export DOP_ALLOW_FILE_KEYS=1

PASS="pass-word-long-enough"
APPROVE="$PASS-approve"
AUDIT="$HOME/Library/Application Support/dop/logs/audit.jsonl"
# v1.14.0-rc4 — bypass the Tier 3 approval dialog for non-tty testing.
export DOP_APPROVAL_PASSPHRASE="$APPROVE"

echo "=== [1] setup: admin + integration + grant"
printf '%s\n%s\n' "$PASS" "$APPROVE" | "$DOP" admin init --passphrase-stdin >/dev/null
"$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null
"$DOP" integration add --name svc --token api=secret-value:read-only >/dev/null
"$DOP" grant add --id svc.api --integration svc --token api >/dev/null
pass "fixture ready"

echo "=== [2] issue a portable bearer + exec without claim"
# --portable stashes the bearer on the capability so dop use can retrieve it.
# --no-bind makes the bearer unclaimed (binding kind: pin, no pubkey).
"$DOP" token issue --grants svc.api --name camShell --no-bind --portable >/dev/null 2>&1 \
    || fail "token issue --portable failed"
# v1.14.0-rc4 — issue didn't print; dop use reaches the stashed bearer.
# Fetch the bearer via dop use (the real-world path).
EVAL=$("$DOP" use --print-export camShell 2>&1) || fail "dop use failed: $EVAL"
eval "$EVAL"
[[ -n "${DOP_TOKEN:-}" ]] || fail "dop use didn't export DOP_TOKEN"

# Exec should run WITHOUT a prior claim. Use `env` as the child since
# it prints its environment and is reliably on $PATH.
EXEC_OUT=$("$DOP" exec --agent-name camShell -- env 2>&1) \
    || fail "portable exec failed: $EXEC_OUT"
echo "$EXEC_OUT" | grep -q "SVC_API_TOKEN=secret-value" || fail "env missing: $EXEC_OUT"
pass "portable exec runs without claim"

echo "=== [3] standard bearer (no --portable, pin-bound) still refuses without claim"
# Issue a NON-portable bearer WITH a PIN binding (the default). An
# unclaimed PIN-bound bearer must fail verifyBinding — that path is
# unchanged for non-portable capabilities.
unset DOP_TOKEN
STD_OUT=$("$DOP" token issue --grants svc.api --name standardAgent --print-bearer 2>&1) \
    || fail "non-portable issue failed"
STD_BEARER=$(echo "$STD_OUT" | grep -oE 'tok_[a-f0-9]+' | head -1)
[[ -n "$STD_BEARER" ]] || fail "no bearer in: $STD_OUT"

export DOP_TOKEN="$STD_BEARER"
if "$DOP" exec --agent-name standardAgent -- env 2>/dev/null; then
    fail "non-portable (pin-bound unclaimed) exec should have required a claim"
fi
pass "non-portable bearer still requires claim"

echo "=== [4] audit event carries portable_owner=yes"
[[ -f "$AUDIT" ]] || fail "audit log missing at $AUDIT"
grep -q '"portable_owner":"yes"' "$AUDIT" \
    || fail "audit missing portable_owner=yes marker"
pass "audit event present"

echo "✓ v1.14.0-rc3 Phase 7 e2e passed"
