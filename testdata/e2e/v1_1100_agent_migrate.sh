#!/usr/bin/env bash
# V1.11 e2e: dop agent list / migrate / sweep + backward-compat exec
# with the legacy ed25519 key.

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "V1.11 e2e: no dop at $DOP" >&2; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v1100-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
mkdir -p "$HOME"
export DOP_NO_TUI=1
export DOP_NO_NOTIFY=1
# Force the file backend for both ed25519 and p256 in this test so
# the assertions about on-disk files are stable, regardless of
# whether the machine's Secure Enclave is available.
export DOP_NO_KEYCHAIN=1
export DOP_ALLOW_FILE_KEYS=1

PASS="pass-word-long-enough"
export DOP_APPROVAL_PASSPHRASE="$PASS-approve"
CFG_ROOT="$HOME/Library/Application Support/dop"

echo "=== [1] setup + issue a bearer + claim it (starts as ed25519)"
printf "%s\n%s\n" "$PASS" "$PASS-approve" | "$DOP" admin init --passphrase-stdin >/dev/null
"$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null
cat > "$CFG_ROOT/vault/vault.yaml" <<'EOF'
schema_version: v1
integrations:
  notion:
    metadata: {base_url: "https://api.notion.com/v1"}
    tokens: {read: {value: "ntn_xxx"}}
grants:
  notion.read: {integration: notion, token: read, env_prefix: NOTION}
EOF
issue=$("$DOP" token issue --grants notion.read --name testagent 2>&1)
BEARER=$(echo "$issue" | grep -E '^tok_1' | head -1)
PIN=$(echo "$issue" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
DOP_TOKEN="$BEARER" "$DOP" claim --skip-approval "$PIN" >/dev/null 2>&1
pass "claim succeeded"

echo "=== [2] dop agent list shows one ed25519 file-backed key"
list=$("$DOP" agent list 2>&1)
echo "$list" | grep -q "ed25519" || { echo "$list"; fail "no ed25519 entry"; }
echo "$list" | grep -q "1 total" || { echo "$list"; fail "expected 1 total"; }
pass "list shows ed25519 file-backed"

echo "=== [3] exec works with the ed25519 key"
DOP_TOKEN="$BEARER" "$DOP" exec --agent-name pre-migrate -- env 2>/dev/null | grep -q "NOTION_TOKEN=ntn_xxx" || fail "exec pre-migrate broken"
pass "pre-migrate exec works"

echo "=== [4] dop agent migrate rotates ed25519 → p256"
LOOKUP=$("$DOP" agent list --json | grep lookup_id | head -1 | sed 's/.*"lookup_id": "\([^"]*\)".*/\1/')
[[ -n "$LOOKUP" ]] || fail "couldn't get lookup id"
migrate_out=$("$DOP" agent migrate "$LOOKUP" 2>&1)
echo "$migrate_out" | grep -q "migration complete" || { echo "$migrate_out"; fail "migrate didn't complete"; }
pass "migrate ran"

echo "=== [5] both files present after migrate; ed25519 marked grace-delete"
[[ -f "$CFG_ROOT/agent-keys/$LOOKUP.key" ]] || fail "ed25519 file missing"
[[ -f "$CFG_ROOT/agent-keys/$LOOKUP.p256" ]] || fail "p256 file missing"
[[ -f "$CFG_ROOT/agent-keys/$LOOKUP.migrated" ]] || fail "grace marker missing"
list=$("$DOP" agent list 2>&1)
echo "$list" | grep -q "grace-delete" || { echo "$list"; fail "no grace-delete status"; }
pass "old + new files present, grace marker set"

echo "=== [6] exec now uses the p256 key transparently"
DOP_TOKEN="$BEARER" "$DOP" exec --agent-name post-migrate -- env 2>/dev/null | grep -q "NOTION_TOKEN=ntn_xxx" || fail "exec post-migrate broken"
pass "post-migrate exec works with new p256 key"

echo "=== [7] audit log records the migration"
grep -q '"event":"agent_migrated"' "$CFG_ROOT/logs/audit.jsonl" || fail "no agent_migrated audit event"
pass "audit event recorded"

echo "=== [8] dop agent sweep is a no-op inside the grace window"
sweep_out=$("$DOP" agent sweep 2>&1)
echo "$sweep_out" | grep -qi "nothing to remove" || { echo "$sweep_out"; fail "sweep shouldn't remove during grace"; }
[[ -f "$CFG_ROOT/agent-keys/$LOOKUP.key" ]] || fail "sweep deleted key too early"
pass "sweep respects the grace window"

echo "=== [9] forge an expired grace marker; sweep removes the legacy key"
# Rewrite the marker with a past timestamp.
date -u -v-1H '+%Y-%m-%dT%H:%M:%SZ' > "$CFG_ROOT/agent-keys/$LOOKUP.migrated" 2>/dev/null || \
    date -u -d "-1 hour" '+%Y-%m-%dT%H:%M:%SZ' > "$CFG_ROOT/agent-keys/$LOOKUP.migrated"
sweep_out=$("$DOP" agent sweep 2>&1)
echo "$sweep_out" | grep -q "removed 1" || { echo "$sweep_out"; fail "sweep didn't remove expired key"; }
[[ ! -f "$CFG_ROOT/agent-keys/$LOOKUP.key" ]] || fail "sweep left the .key behind"
[[ ! -f "$CFG_ROOT/agent-keys/$LOOKUP.migrated" ]] || fail "sweep left the marker behind"
pass "sweep removes expired legacy key + marker"

echo "=== [10] exec still works after sweep (p256 key stays)"
DOP_TOKEN="$BEARER" "$DOP" exec --agent-name post-sweep -- env 2>/dev/null | grep -q "NOTION_TOKEN=ntn_xxx" || fail "exec post-sweep broken"
pass "post-sweep exec still works"

echo "=== [11] doctor surfaces the p256 backend"
doc_out=$("$DOP" doctor 2>&1)
echo "$doc_out" | grep -q "agent:keys" || { echo "$doc_out"; fail "doctor missing agent:keys check"; }
echo "$doc_out" | grep -qi "p256" || { echo "$doc_out"; fail "doctor doesn't mention p256"; }
pass "doctor reports agent-key backend mix"

pkill -9 -f "dop admin __session-daemon" 2>/dev/null || true
echo "V1.11 agent-migrate e2e: PASS"
