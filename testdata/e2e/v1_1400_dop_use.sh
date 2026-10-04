#!/usr/bin/env bash
# V1.14.0-rc1 e2e: `dop use <subject>` — admin's own bearer shortcut.
# Covers:
#   [1] admin init + login + base integration/grant
#   [2] issue bearer WITHOUT --portable → `dop use` refuses with hint
#   [3] issue bearer WITH --portable → `dop use` emits export line
#   [4] eval'd export → bearer actually works for `dop env`
#   [5] --token-file path writes JSON envelope with mode 0600 + TTL
#   [6] unknown subject refused
#   [7] admin-session-locked path refused with pointer to admin login
#   [8] audit event use_attached recorded, bearer value NOT in log

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "V1.14 use e2e: no dop at $DOP" >&2; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v1400-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
mkdir -p "$HOME"
export DOP_NO_TUI=1
export DOP_NO_KEYCHAIN=1
export DOP_ALLOW_FILE_KEYS=1

PASS="pass-word-long-enough"
APPROVE="$PASS-approve"
AUDIT="$HOME/Library/Application Support/dop/logs/audit.jsonl"
# v1.14.0-rc4 — Tier 3 approval gate on --print-export surfaces. The
# env escape hatch lets E2E drive the approval flow without a human
# clicking the native dialog. Same auth strength as the dialog —
# still verifies the real passphrase.
export DOP_APPROVAL_PASSPHRASE="$APPROVE"

echo "=== [1] admin init + login + base integration/grant"
printf '%s\n%s\n' "$PASS" "$APPROVE" | "$DOP" admin init --passphrase-stdin >/dev/null
"$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null
"$DOP" integration add --name svc --token api=secret_val:read-only >/dev/null
"$DOP" grant add --id svc.api --integration svc --token api >/dev/null
pass "fixture ready"

echo "=== [2] bearer WITHOUT --portable → dop use refuses"
OUT2=$("$DOP" token issue --grants svc.api --name without-stash --no-bind --print-bearer 2>&1)
B2=$(echo "$OUT2" | grep -E '^tok_1' | head -1)
[[ -n "$B2" ]] || fail "no bearer emitted on without-stash: $OUT2"
OUT=$("$DOP" use without-stash 2>&1 || true)
echo "$OUT" | grep -q "no portable stash" || fail "expected refusal with hint, got: $OUT"
pass "refused without stash + hint shown"

echo "=== [3] bearer WITH --portable → dop use emits export line"
"$DOP" token issue --grants svc.api --name CamAdmin --no-bind --portable >/dev/null 2>&1 \
    || fail "token issue --portable failed"
OUT_USE=$("$DOP" use --print-export CamAdmin 2>&1)
echo "$OUT_USE" | grep -qE "^export DOP_TOKEN=tok_1" || fail "no export line: $OUT_USE"
pass "dop use emitted eval line"

echo "=== [4] eval'd token works for dop env"
# Extract token from the export line and verify dop env renders the grant.
TOKEN=$(echo "$OUT_USE" | grep -oE 'tok_[a-f0-9]+' | head -1)
[[ -n "$TOKEN" ]] || fail "could not extract token from export line"
ENV_OUT=$(DOP_TOKEN="$TOKEN" "$DOP" env --print-export 2>&1)
echo "$ENV_OUT" | grep -q "SVC_API_TOKEN='secret_val'" || fail "dop env didn't resolve the grant: $ENV_OUT"
pass "token works for dop env"

echo "=== [5] --token-file writes JSON envelope with mode 0600"
TF="$WORKROOT/dop-token.json"
# Standard Go flag ordering: flags before positional.
"$DOP" use --token-file "$TF" CamAdmin >/dev/null 2>&1 || fail "token-file write failed"
[[ -f "$TF" ]] || fail "token file not created"
MODE=$(stat -f '%A' "$TF" 2>/dev/null || stat -c '%a' "$TF" 2>/dev/null)
[[ "$MODE" == "600" ]] || fail "token file mode is $MODE, expected 600"
grep -q '"token"' "$TF" || fail "token file missing 'token' field"
grep -q '"subject"' "$TF" || fail "token file missing 'subject' field"
grep -q '"expires_at"' "$TF" || fail "token file missing 'expires_at' field"
grep -q "$TOKEN" "$TF" || fail "token file doesn't contain the actual bearer"
pass "token file written cleanly"

echo "=== [6] unknown subject refused"
OUT6=$("$DOP" use nosuch 2>&1 || true)
echo "$OUT6" | grep -q "no active capability" || fail "expected unknown-subject error, got: $OUT6"
pass "unknown subject refused"

echo "=== [7] admin-session-locked path refused with pointer"
"$DOP" admin logout >/dev/null 2>&1
# daemon exits ~50ms after returning the OK; poll briefly so the next
# command sees SessionActive=false.
for i in 1 2 3 4 5; do
    if ! "$DOP" use --print-export CamAdmin 2>&1 | grep -q "export DOP_TOKEN"; then
        break
    fi
    sleep 0.2
done
OUT7=$("$DOP" use --print-export CamAdmin 2>&1 || true)
echo "$OUT7" | grep -qi "admin" || fail "expected admin-session hint, got: $OUT7"
pass "locked session refused"

echo "=== [8b] non-tty refusal without --print-export (Phase 6/rc4)"
# Re-login (step 7 logged out).
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null
# For this specific test we need the env escape OFF so the Tier 1
# refusal path actually runs. Rest of the suite restores it.
REFUSAL=$(DOP_APPROVAL_PASSPHRASE="" "$DOP" use CamAdmin 2>&1 || true)
echo "$REFUSAL" | grep -q "refusing to print secret to a non-tty" \
    || fail "expected non-tty refusal, got: $REFUSAL"
echo "$REFUSAL" | grep -q 'eval "\$(dop use' \
    || fail "refusal missing eval hint, got: $REFUSAL"
# With DOP_APPROVAL_PASSPHRASE set (env-escape), stdout print proceeds.
OK8B=$("$DOP" use --print-export CamAdmin 2>&1 || true)
echo "$OK8B" | grep -q "^export DOP_TOKEN=" \
    || fail "env-escape should emit export line, got: $OK8B"
pass "non-tty refusal honored; env-escape opts in"

echo "=== [8] audit event use_attached recorded, bearer NOT in log"
grep -q '"event":"use_attached"' "$AUDIT" || fail "no use_attached event in audit log"
if grep -q "$TOKEN" "$AUDIT"; then
    fail "bearer value leaked into audit log"
fi
pass "audit event recorded + bearer absent from log"
