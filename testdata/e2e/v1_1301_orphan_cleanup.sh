#!/usr/bin/env bash
# V1.13 e2e: orphan agent-key cleanup after `dop token revoke`.
# Pre-v1.13, revoking a token left its local agent key file behind.
# `dop agent list` reported it as "active" because status was based
# on on-disk presence alone. Now:
#   - `dop agent list` labels it "orphan"
#   - `dop agent sweep` deletes it
#   - `dop token revoke` auto-cleans it when run locally

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "V1.13 orphan e2e: no dop at $DOP" >&2; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v1301-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
mkdir -p "$HOME"
export DOP_NO_TUI=1
export DOP_NO_KEYCHAIN=1

PASS="pass-word-long-enough"
CFG_ROOT="$HOME/Library/Application Support/dop"
VAULT_DIR="$CFG_ROOT/vault"
KEYS_DIR="$CFG_ROOT/agent-keys"

echo "=== [1] setup + seed + three claimed tokens"
printf "%s\n%s\n" "$PASS" "$PASS-approve" | "$DOP" admin init --passphrase-stdin >/dev/null
"$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null
cat > "$VAULT_DIR/vault.yaml" <<'EOF'
schema_version: v1
integrations:
  notion: {metadata: {}, tokens: {read: {value: "ntn_x"}}}
grants:
  notion.read: {integration: notion, token: read, env_prefix: NOTION}
EOF
for i in 1 2 3; do
  OUT=$("$DOP" token issue --grants notion.read --name "orphan-$i" 2>&1)
  BEARER=$(echo "$OUT" | grep -E '^tok_1' | head -1)
  PIN=$(echo "$OUT" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
  DOP_TOKEN="$BEARER" "$DOP" claim --skip-approval "$PIN" >/dev/null 2>&1
done
pass "3 tokens claimed"

echo "=== [2] baseline: 3 keys on disk, all active (no orphans yet)"
LIST1=$("$DOP" agent list)
COUNT_ACTIVE=$(echo "$LIST1" | grep -c "active$" || true)
COUNT_ORPHAN=$(echo "$LIST1" | grep -c "orphan" || true)
[[ "$COUNT_ACTIVE" == "3" ]] || fail "expected 3 active, got $COUNT_ACTIVE: $LIST1"
[[ "$COUNT_ORPHAN" == "0" ]] || fail "expected 0 orphans, got $COUNT_ORPHAN"
pass "3 keys active, 0 orphans"

echo "=== [3] revoke orphan-2 and orphan-3 locally — local keys auto-cleaned"
"$DOP" token revoke orphan-2 >/dev/null 2>&1
"$DOP" token revoke orphan-3 >/dev/null 2>&1
LIST2=$("$DOP" agent list)
COUNT_LEFT=$(echo "$LIST2" | grep -c "ed25519" || true)
# After local revoke, the two keys should be gone — only orphan-1's key left.
[[ "$COUNT_LEFT" == "1" ]] || fail "expected 1 key after local revoke, got $COUNT_LEFT: $LIST2"
pass "local revoke cleans up the agent key automatically"

echo "=== [4] simulate a REMOTE revoke by issuing + claiming + nuking the record file"
# Issue + claim a fresh token, then delete its sidecar/bundle manually
# (what a different admin's revoke would do once synced via git). Keep
# the local agent key — that's exactly the orphan state.
OUT=$("$DOP" token issue --grants notion.read --name remote-revoke 2>&1)
B=$(echo "$OUT" | grep -E '^tok_1' | head -1)
P=$(echo "$OUT" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
DOP_TOKEN="$B" "$DOP" claim --skip-approval "$P" >/dev/null 2>&1
# Grab the lookup id so we know which record to delete.
RR_LOOKUP=$("$DOP" token show remote-revoke --json | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['lookup_id'])")
rm -f "$VAULT_DIR/capabilities/$RR_LOOKUP.record"
rm -f "$VAULT_DIR/capabilities/$RR_LOOKUP.bundle"
pass "simulated remote revoke by deleting sidecars"

echo "=== [5] agent list now flags remote-revoke's key as 'orphan'"
LIST3=$("$DOP" agent list)
echo "$LIST3" | grep -q "orphan" || fail "agent list should flag the orphan: $LIST3"
echo "$LIST3" | grep -q "1 orphan key" || fail "agent list should give the orphan nudge: $LIST3"
pass "orphan surfaced in agent list"

echo "=== [6] agent sweep deletes the orphan key file"
SWEEP=$("$DOP" agent sweep 2>&1)
echo "$SWEEP" | grep -q "1 orphan" || fail "sweep didn't name the count: $SWEEP"
LIST4=$("$DOP" agent list)
echo "$LIST4" | grep -q "orphan" && fail "orphan still listed after sweep: $LIST4"
echo "$LIST4" | grep -c "ed25519" | grep -q "^1$" || fail "wrong post-sweep count: $LIST4"
pass "sweep removed the orphan; orphan-1 remains"

echo "=== [7] empty sweep is a no-op"
SWEEP2=$("$DOP" agent sweep 2>&1)
echo "$SWEEP2" | grep -q "nothing to remove" || fail "second sweep should say nothing: $SWEEP2"
pass "idempotent"

echo
echo "V1.13 orphan e2e: ALL PASS"
