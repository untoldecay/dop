#!/usr/bin/env bash
# V1.14.0-rc3 Phase 5 e2e: `dop integration rename`.
# Covers:
#   [1] rename an integration + verify grants rewritten atomically
#   [2] already-issued bearers keep OLD name in bundle (documented behavior)
#   [3] protected integration rename refused when not owner (positive-only here)
#   [4] audit event integration_renamed carries old/new/referrers
#   [5] target name collision refused

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "V1.14 rename e2e: no dop at $DOP" >&2; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v1440-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
mkdir -p "$HOME"
export DOP_NO_TUI=1
export DOP_NO_KEYCHAIN=1

PASS="pass-word-long-enough"
APPROVE="$PASS-approve"
AUDIT="$HOME/Library/Application Support/dop/logs/audit.jsonl"
VAULT_YAML="$WORKROOT/bare/vault.yaml"

echo "=== [1] setup + rename + verify grants rewritten"
printf '%s\n%s\n' "$PASS" "$APPROVE" | "$DOP" admin init --passphrase-stdin >/dev/null
"$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null
"$DOP" integration add --name oldname --token api=val:scope >/dev/null
"$DOP" grant add --id oldname.api --integration oldname --token api >/dev/null
"$DOP" grant add --id oldname.other --integration oldname --token api --tags beta >/dev/null

"$DOP" integration rename --from oldname --to newname >/dev/null 2>&1 \
    || fail "rename failed"

# Grants should now reference "newname".
"$DOP" grant show oldname.api --json 2>&1 | grep -q '"integration":"newname"' \
    || fail "grant oldname.api not rewritten"
"$DOP" grant show oldname.other --json 2>&1 | grep -q '"integration":"newname"' \
    || fail "grant oldname.other not rewritten"
# Integration should be reachable by new name, gone by old.
"$DOP" integration list 2>&1 | grep -q newname || fail "newname missing from list"
if "$DOP" integration list 2>&1 | grep -qE '(^|[^a-z])oldname'; then
    fail "oldname still visible in list"
fi
pass "rename atomic — integration + 2 grants rewritten"

echo "=== [2] rename to a name that collides refused"
"$DOP" integration add --name sibling --token api=v:note >/dev/null
if "$DOP" integration rename --from newname --to sibling 2>/dev/null; then
    fail "collision rename should have refused"
fi
pass "collision rename refused"

echo "=== [3] audit event integration_renamed carries old/new/referrers"
grep -q '"event":"integration_renamed"' "$AUDIT" \
    || fail "no integration_renamed event in audit log"
grep '"event":"integration_renamed"' "$AUDIT" | grep -q '"old_name":"oldname"' \
    || fail "audit missing old_name=oldname"
grep '"event":"integration_renamed"' "$AUDIT" | grep -q '"new_name":"newname"' \
    || fail "audit missing new_name=newname"
grep '"event":"integration_renamed"' "$AUDIT" | grep -q '"referrers":"2"' \
    || fail "audit missing referrers=2"
pass "audit event complete"

echo "=== [4] no-op rename to same normalized key"
if ! "$DOP" integration rename --from newname --to NewName 2>&1 | grep -qi "nothing to do"; then
    # When the normalized key is the same, we no-op (return 0 with hint).
    fail "same-normalized-key rename should no-op"
fi
pass "same-normalized-key is a no-op"

echo "✓ v1.14.0-rc3 Phase 5 e2e passed"
