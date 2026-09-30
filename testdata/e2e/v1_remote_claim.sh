#!/usr/bin/env bash
# V1.7 e2e: remote-agent claim flow.
# Machine A = admin (issues token + PIN, runs approve-remote).
# Machine B = agent (no daemon on this HOME; runs `dop claim --remote`).
# Both point at the same bare git repo as the vault remote.

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "no dop"; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-remote-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export DOP_NO_TUI=1
export DOP_NO_KEYCHAIN=1
export DOP_NO_NOTIFY=1

BARE="$WORKROOT/bare"
MACHINE_A="$WORKROOT/a"
MACHINE_B="$WORKROOT/b"
mkdir -p "$MACHINE_A" "$MACHINE_B"
PASS="pass-word-long-enough"

echo "=== [A1] admin init + vault + seed"
HOME="$MACHINE_A" printf "%s\n%s\n" "$PASS" "$PASS-approve" | HOME="$MACHINE_A" "$DOP" admin init --passphrase-stdin >/dev/null
HOME="$MACHINE_A" echo -n "$PASS" | HOME="$MACHINE_A" "$DOP" admin login --passphrase-stdin >/dev/null
HOME="$MACHINE_A" "$DOP" init --vault "$BARE" >/dev/null 2>&1
A_VAULT="$MACHINE_A/Library/Application Support/dop/vault"
cat > "$A_VAULT/vault.yaml" <<'EOF'
schema_version: v1
integrations:
  notion: {metadata: {u: "1"}, tokens: {read: {value: "ntn_remote"}}}
grants:
  notion.read: {integration: notion, token: read, env_prefix: N}
EOF

echo "=== [A2] issue bearer + PIN"
issue=$(HOME="$MACHINE_A" "$DOP" token issue --grants notion.read --name remote-bot 2>&1)
BEARER=$(echo "$issue" | grep -E '^tok_1' | head -1)
PIN=$(echo "$issue" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
[[ -n "$BEARER" && -n "$PIN" ]] || fail "issue failed"
HOME="$MACHINE_A" "$DOP" push >/dev/null 2>&1 || fail "admin push after issue failed"
pass "issued bearer=$BEARER pin=$PIN"

echo "=== [B1] agent installs as cache (no admin key)"
HOME="$MACHINE_B" "$DOP" init --cache "$BARE" >/dev/null 2>&1
B_VAULT="$MACHINE_B/Library/Application Support/dop/vault"
[[ -d "$B_VAULT" ]] || fail "agent clone missing"
pass "agent attached at $B_VAULT"

echo "=== [B2] agent runs dop claim --remote (no admin session on this host)"
out=$(HOME="$MACHINE_B" DOP_TOKEN="$BEARER" "$DOP" claim --remote "$PIN" 2>&1)
echo "$out" | grep -q "staged remote-bot for approval" || { echo "$out"; fail "remote claim did not stage"; }
n_json=$(ls "$B_VAULT/pending-remote-claims"/*.json 2>/dev/null | wc -l | tr -d ' ')
n_bun=$(ls "$B_VAULT/pending-remote-claims"/*.bundle 2>/dev/null | wc -l | tr -d ' ')
[[ "$n_json" == "1" ]] || fail "expected 1 pending metadata, got $n_json"
[[ "$n_bun" == "1" ]] || fail "expected 1 pending bundle, got $n_bun"
[[ -d "$MACHINE_B/Library/Application Support/dop/agent-keys" ]] || fail "agent key not persisted"
pass "claim staged + pushed"

echo "=== [A3] admin sees the pending remote claim via --list"
HOME="$MACHINE_A" "$DOP" pull >/dev/null 2>&1 || true
out=$(HOME="$MACHINE_A" "$DOP" approve-remote --list 2>&1)
echo "$out" | grep -q "remote-bot" || { echo "$out"; fail "admin can't see the remote claim"; }
pass "admin lists remote claim"

echo "=== [A4] wrong passphrase → refused"
if echo -n "wrong-passphrase-nope" | HOME="$MACHINE_A" "$DOP" approve-remote --passphrase-stdin --subject remote-bot 2>/dev/null; then
    fail "wrong passphrase should refuse"
fi
pass "wrong passphrase refused"

echo "=== [A5] correct passphrase → approved"
set +e
echo -n "$PASS-approve" | HOME="$MACHINE_A" "$DOP" approve-remote --passphrase-stdin --subject remote-bot >"$WORKROOT/approve.log" 2>&1
AP_RC=$?
left=$( (ls "$A_VAULT/pending-remote-claims"/*.json 2>/dev/null || true) | wc -l | tr -d ' ')
set -e
[[ "$AP_RC" == "0" ]] || { cat "$WORKROOT/approve.log"; fail "approve-remote rc=$AP_RC"; }
grep -q "approved" "$WORKROOT/approve.log" || { cat "$WORKROOT/approve.log"; fail "no 'approved' in output"; }
[[ "$left" == "0" ]] || fail "pending metadata not cleaned ($left left)"
pass "pending files cleaned"

echo "=== [B3] agent pulls → dop exec works"
HOME="$MACHINE_B" "$DOP" pull >/dev/null 2>&1 || fail "agent pull failed"
out=$(HOME="$MACHINE_B" DOP_TOKEN="$BEARER" "$DOP" exec --agent-name r -- env 2>&1)
echo "$out" | grep -q "N_TOKEN=ntn_remote" || { echo "$out"; fail "exec after approve broken"; }
pass "post-approve exec works on agent host"

echo ""
echo "V1.7 remote-claim e2e: PASS"
