#!/usr/bin/env bash
# V1.7 e2e: remote-agent claim flow.
# Machine A = admin (issues token + PIN, runs approve-remote).
# Machine B = agent (no daemon on this HOME; runs `dop claim --remote`).
# Both point at the same bare git repo as the vault remote.
#
# dop-ynw — the agent claims with a P-256 key (file-backed, opt-in);
# approve-remote records key_type + seals EnvWrapped, so bearer-free
# exec and add-grant work on the agent host without a reseal.

set -euo pipefail
# exec masks injected values in captured output (v1.18); `rev` inside and
# outside the child lets the test read the real env.

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "no dop"; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-remote-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export DOP_NO_TUI=1
export DOP_NO_KEYCHAIN=1
export DOP_NO_NOTIFY=1
export DOP_ALLOW_FILE_KEYS=1    # file-backed P-256 on the agent host

BARE="$WORKROOT/bare"
MACHINE_A="$WORKROOT/a"
MACHINE_B="$WORKROOT/b"
mkdir -p "$MACHINE_A" "$MACHINE_B"
PASS="pass-word-long-enough"
export DOP_APPROVAL_PASSPHRASE="$PASS-approve"

echo "=== [A1] admin init + vault + seed"
HOME="$MACHINE_A" printf "%s\n%s\n" "$PASS" "$PASS-approve" | HOME="$MACHINE_A" "$DOP" admin init --passphrase-stdin >/dev/null
HOME="$MACHINE_A" echo -n "$PASS" | HOME="$MACHINE_A" "$DOP" admin login --passphrase-stdin >/dev/null
HOME="$MACHINE_A" "$DOP" init --vault "$BARE" >/dev/null 2>&1
A_VAULT="$MACHINE_A/Library/Application Support/dop/vault"
cat > "$A_VAULT/vault.yaml" <<'EOF'
schema_version: v1
integrations:
  notion: {metadata: {u: "1"}, tokens: {read: {value: "ntn_remote"}}}
  slack: {metadata: {u: "1"}, tokens: {bot: {value: "xoxb_remote"}}}
grants:
  notion.read: {integration: notion, token: read, env_prefix: N}
  slack.bot: {integration: slack, token: bot, env_prefix: S}
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

echo "=== [B2] agent runs dop claim --remote --key-type p256 (no admin session on this host)"
out=$(HOME="$MACHINE_B" DOP_TOKEN="$BEARER" "$DOP" claim --remote --key-type p256 "$PIN" 2>&1)
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
echo "$out" | grep "remote-bot" | grep -q "p256" || { echo "$out"; fail "remote claim not listed as p256"; }
pass "admin lists remote claim (p256)"

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

echo "=== [A6] binding is p256 and EnvWrapped was sealed at approval"
SHOW=$(HOME="$MACHINE_A" "$DOP" token show remote-bot --json 2>&1)
LOOKUP=$(echo "$SHOW" | python3 -c "
import sys, json
d = json.loads(sys.stdin.read())
assert d['binding']['key_type'] == 'p256', 'binding: '+str(d['binding'])
print(d['lookup_id'])
") || fail "token show mismatch: $SHOW"
python3 - "$A_VAULT/capabilities/$LOOKUP.record" <<'PY' || fail "no env_wrapped on sidecar after approve-remote"
import json, sys
d = json.loads(open(sys.argv[1]).read())
assert d.get('env_wrapped'), 'no env_wrapped'
PY
pass "binding.key_type=p256, env_wrapped sealed at approval"

echo "=== [B3] agent pulls → dop exec works"
HOME="$MACHINE_B" "$DOP" pull >/dev/null 2>&1 || fail "agent pull failed"
out=$(HOME="$MACHINE_B" DOP_TOKEN="$BEARER" "$DOP" exec --agent-name r -- sh -c 'env | rev' 2>/dev/null | rev)
echo "$out" | grep -q "N_TOKEN=ntn_remote" || { echo "$out"; fail "exec after approve broken"; }
pass "post-approve exec works on agent host"

echo "=== [B4] bearer-free exec (P-256 key opens EnvWrapped, no DOP_TOKEN)"
out=$(HOME="$MACHINE_B" "$DOP" exec --agent-name remote-bot -- sh -c 'env | rev' 2>&1 | rev)
echo "$out" | grep -q "N_TOKEN=ntn_remote" || { echo "$out"; fail "bearer-free exec after remote approve broken"; }
pass "bearer-free exec works from day one"

echo "=== [A7] admin add-grant slack.bot → direct availability"
HOME="$MACHINE_A" "$DOP" token add-grant remote-bot slack.bot 2>&1 | grep -q "env resealed" || fail "add-grant didn't reseal"
HOME="$MACHINE_A" "$DOP" push >/dev/null 2>&1 || true
pass "add-grant resealed"

echo "=== [B5] agent pulls → same bearer sees the new grant, no re-claim"
HOME="$MACHINE_B" "$DOP" pull >/dev/null 2>&1 || fail "agent pull failed"
out=$(HOME="$MACHINE_B" DOP_TOKEN="$BEARER" "$DOP" exec --agent-name remote-bot -- sh -c 'env | rev' 2>/dev/null | rev)
echo "$out" | grep -q "S_TOKEN=xoxb_remote" || { echo "$out"; fail "add-grant not visible on agent host"; }
echo "$out" | grep -q "N_TOKEN=ntn_remote" || { echo "$out"; fail "lost notion after add-grant"; }
pass "remote-claimed P-256 agent sees add-grant directly"

echo "=== [A8/B6] second bearer: claim --remote then admin --reject"
issue=$(HOME="$MACHINE_A" "$DOP" token issue --grants notion.read --name reject-bot 2>&1)
BEARER2=$(echo "$issue" | grep -E '^tok_1' | head -1)
PIN2=$(echo "$issue" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
[[ -n "$BEARER2" && -n "$PIN2" ]] || fail "second issue failed"
HOME="$MACHINE_A" "$DOP" push >/dev/null 2>&1 || fail "push after second issue failed"
HOME="$MACHINE_B" "$DOP" pull >/dev/null 2>&1 || fail "agent pull failed"
HOME="$MACHINE_B" DOP_TOKEN="$BEARER2" "$DOP" claim --remote "$PIN2" >/dev/null 2>&1 || fail "second remote claim failed"
HOME="$MACHINE_A" "$DOP" pull >/dev/null 2>&1 || true
out=$(HOME="$MACHINE_A" "$DOP" approve-remote --subject reject-bot --reject 2>&1)
echo "$out" | grep -q "rejected reject-bot" || { echo "$out"; fail "reject did not report"; }
left=$( (ls "$A_VAULT/pending-remote-claims"/*.json 2>/dev/null || true) | wc -l | tr -d ' ')
[[ "$left" == "0" ]] || fail "rejected claim still staged ($left left)"
HOME="$MACHINE_A" "$DOP" approve-remote --list 2>&1 | grep -q "no pending remote claims" || fail "rejected claim still listed"
if HOME="$MACHINE_B" DOP_TOKEN="$BEARER2" "$DOP" exec --agent-name reject-bot -- true >/dev/null 2>&1; then
    fail "rejected bearer must not exec"
fi
pass "reject drops the staged claim; bearer stays unclaimed"

echo ""
echo "V1.7 remote-claim e2e: PASS"
