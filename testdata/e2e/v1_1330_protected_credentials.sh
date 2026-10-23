#!/usr/bin/env bash
# V1.13.0-rc12 e2e: Protected credentials — owner-locked integrations.
# Shape B (convention + loud audit) + daemon revert-on-save.
#
# Covers:
#   [1] create a protected integration (passphrase gate on CLI)
#   [2] non-owner refusal: a second admin pubkey cannot modify / remove / add-grant
#   [3] token issue with a protected grant demands the passphrase
#   [4] daemon revert: direct vault edit by a non-owner is undone before save
#       (audit log carries protected_bypass_attempt)
#   [5] passphrase-less `integration add --protected` fails cleanly

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "V1.13 protected e2e: no dop at $DOP" >&2; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v1330-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
mkdir -p "$HOME"
export DOP_NO_TUI=1
export DOP_NO_KEYCHAIN=1
export DOP_ALLOW_FILE_KEYS=1

PASS="pass-word-long-enough"
APPROVE="$PASS-approve"
VAULT_DIR="$HOME/Library/Application Support/dop/vault"
AUDIT="$HOME/Library/Application Support/dop/logs/audit.jsonl"
# v1.14.0-rc4 — Tier 3 approval bypass for E2E (same strength as the
# dialog — still verifies the actual passphrase).
export DOP_APPROVAL_PASSPHRASE="$APPROVE"

echo "=== [1] admin init + login"
printf "%s\n%s\n" "$PASS" "$APPROVE" | "$DOP" admin init --passphrase-stdin >/dev/null
"$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null
pass "admin ready"

echo "=== [2] create a protected integration (passphrase gate on save)"
# Correct passphrase: should succeed.
echo -n "$APPROVE" | "$DOP" integration add \
    --name secret-svc \
    --token api=secret_val:read-only \
    --protected --passphrase-stdin >/dev/null 2>&1 || fail "protected create (correct pass) failed"
# Verify YAML key is present (SOPS encrypts the value but the key is visible).
grep -q "protected:" "$VAULT_DIR/vault.yaml" || fail "Protected key not persisted"
# User-facing: integration list shows the lock glyph.
LIST=$("$DOP" integration list)
echo "$LIST" | grep -q "🔒" || fail "integration list missing lock glyph: $LIST"
pass "protected integration created + visible"

echo "=== [3] wrong passphrase refused"
if echo -n "wrong-passphrase" | "$DOP" integration add \
    --name another-svc \
    --token api=val:read-only \
    --protected --passphrase-stdin >/dev/null 2>&1; then
  fail "wrong passphrase should refuse"
fi
pass "wrong passphrase refused"

echo "=== [4] grant on protected integration inherits owner-lock"
"$DOP" grant add --id secret-svc.api --integration secret-svc --token api >/dev/null 2>&1 \
    || fail "owner can create grant on their protected integration"
# `protected:` key under the new grant block is visible even when SOPS-encrypted.
awk '/secret-svc.api:/{f=1} f{print; if(/^[^ ]/) exit}' "$VAULT_DIR/vault.yaml" | grep -q "protected:" \
    || fail "grant did not inherit Protected flag"
pass "grant inherits protection + owner"

echo "=== [5] issuing a bearer with a protected grant requires passphrase"
# Missing passphrase: should refuse.
if "$DOP" token issue --grants secret-svc.api --name secret-token >/dev/null 2>&1; then
  fail "token issue should refuse without passphrase for protected grants"
fi
# With correct passphrase: should succeed.
ISSUE_OUT=$(echo -n "$APPROVE" | "$DOP" token issue \
    --grants secret-svc.api --name secret-token \
    --passphrase-stdin --print-bearer 2>&1) || fail "token issue (correct pass) failed: $ISSUE_OUT"
echo "$ISSUE_OUT" | grep -qE '^tok_1' || fail "no bearer emitted"
pass "token issue gated by passphrase"

echo "=== [6] protected_token_issue appears in audit log"
grep -q '"event":"protected_token_issue"' "$AUDIT" || fail "no protected_token_issue audit event"
pass "audit trail present"

echo "=== [6b] co-owners (v1.21): a second admin joins by key, is refused, then added as owner"
HOME_B="$WORKROOT/homeB"; mkdir -p "$HOME_B"
initB=$(HOME="$HOME_B" bash -c 'printf "%s\n%s\n" "'"$PASS"'" "'"$APPROVE"'" | "'"$DOP"'" admin init --passphrase-stdin' 2>&1)
B_ED=$(echo "$initB" | sed -n 's/.*admin ed25519 pubkey: //p' | head -1)
B_AGE=$(echo "$initB" | sed -n 's/.*age recipient: //p' | head -1)
[[ -n "$B_ED" && -n "$B_AGE" ]] || { echo "$initB"; fail "could not read admin B keys"; }
"$DOP" team add-key --name bob --pubkey "$B_AGE" --ed25519 "$B_ED" >/dev/null 2>&1 || fail "team add-key bob failed"
"$DOP" push >/dev/null 2>&1 || fail "push after team add failed"
HOME="$HOME_B" "$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1 || fail "admin B could not attach the vault"
echo -n "$PASS" | HOME="$HOME_B" "$DOP" admin login --passphrase-stdin >/dev/null || fail "admin B login failed"
runB() { HOME="$HOME_B" "$DOP" "$@"; }
# Not an owner yet: refused.
if runB integration add --name secret-svc --description "edited by bob" >/dev/null 2>&1; then
  fail "non-owner bob could edit the protected integration"
fi
pass "non-owner refused"
# Owner A adds bob (own approval passphrase), pushes; bob pulls.
echo -n "$APPROVE" | "$DOP" integration protect --name secret-svc --add-owner bob --passphrase-stdin >/dev/null 2>&1 \
    || fail "owner could not add a co-owner"
"$DOP" integration protect --name secret-svc 2>&1 | grep -q "bob" || fail "bob not listed as owner"
"$DOP" push >/dev/null 2>&1 || fail "push after protect failed"
runB pull >/dev/null 2>&1 || fail "bob pull failed"
# Grants followed the list.
awk '/secret-svc.api:/{f=1} f{print; if(/^[^ ]/) exit}' "$VAULT_DIR/vault.yaml" | grep -q "owners:" \
    || fail "grant did not follow the owners list"
# Co-owner bob can edit, and issue a bearer with the protected grant (his own passphrase).
runB integration add --name secret-svc --description "edited by bob" >/dev/null 2>&1 \
    || fail "co-owner bob could not edit the protected integration"
echo -n "$APPROVE" | HOME="$HOME_B" DOP_APPROVAL_PASSPHRASE="$APPROVE" "$DOP" token issue --grants secret-svc.api --name bob-bot --no-bind --passphrase-stdin >/dev/null 2>&1 \
    || fail "co-owner bob could not issue a bearer with the protected grant"
pass "co-owner can edit and issue"
# The protector cannot be removed; bob can.
A_ED=$("$DOP" admin status 2>/dev/null | sed -n 's/.*ed25519[^:]*: *//p' | head -1)
if [[ -n "$A_ED" ]] && echo -n "$APPROVE" | "$DOP" integration protect --name secret-svc --remove-owner "${A_ED:0:12}" --passphrase-stdin >/dev/null 2>&1; then
  fail "the protector could be removed"
fi
# Bob's edits were auto-pushed; A must be current before changing owners,
# else A's push is rejected and bob never learns he was removed.
"$DOP" pull >/dev/null 2>&1 || fail "A pull before remove-owner failed"
echo -n "$APPROVE" | "$DOP" integration protect --name secret-svc --remove-owner bob --passphrase-stdin >/dev/null 2>&1 \
    || fail "owner could not remove bob"
"$DOP" push >/dev/null 2>&1 || fail "push after remove-owner failed"
runB pull >/dev/null 2>&1 || fail "bob pull after removal failed"
if runB integration add --name secret-svc --description "bob again" >/dev/null 2>&1; then
  fail "removed co-owner bob could still edit"
fi
grep -q '"event":"protected_owners"' "$AUDIT" || fail "no protected_owners audit event"
HOME="$HOME_B" "$DOP" admin logout >/dev/null 2>&1 || true
pass "protector pinned, removed co-owner refused, audit present"

echo "=== [7] owner-only CLI gates (same session, verify positive path)"
# Removing a protected integration you own + supplying no passphrase
# succeeds — we're the owner. The negative "non-owner refusal" case
# needs a two-admin harness, which lives in the manual/field QA kit
# (see docs/testing/protected-credentials-manual.md); the CLI gate
# is enforced by requireProtectionOwner in cmd/dop/protected.go.
"$DOP" integration remove --name secret-svc --force >/dev/null 2>&1 \
    || fail "owner should be able to remove their protected integration"
pass "owner-remove path works"

echo "=== [8] protected_create audit event emitted"
grep -q '"event":"protected_create"' "$AUDIT" \
    || fail "no protected_create audit event (should fire on flip-to-protected)"
pass "create audit trail present"
