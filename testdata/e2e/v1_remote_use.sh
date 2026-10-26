#!/usr/bin/env bash
# V1.21 e2e: lease a portable bearer to an agent on a server (dop-1dd).
# Machine A = admin (issues the portable bearer, approves leases).
# Machine B = server (cache install, no admin key; runs `dop use --remote`).
#
#   [B1] use --remote stages a request and waits
#   [A1] the request shows in approve-remote --list; wrong passphrase refused
#   [A2] approve with a 10m lease → [B1] gets export DOP_TOKEN
#   [B2] the lease bearer execs with the right env; it is NOT the portable bearer
#   [B3] a second dop use reuses the lease (no new request) — v1.21 lease cache
#   [A3] a 1s lease → expired lease refused on exec
#   [A4] runs with a server copy behind the team — the request must still land (rc2 bug 1)
#   [A4] reject → the waiting server exits non-zero
#   [A5] asked lease above the cap is clamped
set -euo pipefail
DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "no dop"; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }
WORKROOT=$(mktemp -d /tmp/dop-ruse-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export DOP_NO_TUI=1 DOP_NO_KEYCHAIN=1 DOP_NO_NOTIFY=1 DOP_ALLOW_FILE_KEYS=1 DOP_NO_AUTO_PULL=1
BARE="$WORKROOT/bare"; A="$WORKROOT/a"; B="$WORKROOT/b"; mkdir -p "$A" "$B"
PASS="pass-word-long-enough"; export DOP_APPROVAL_PASSPHRASE="$PASS-approve"
a() { HOME="$A" "$DOP" "$@"; }
b() { HOME="$B" "$DOP" "$@"; }

echo "=== [A0] admin init + vault + a portable bearer with a 30m lease cap"
printf "%s\n%s\n" "$PASS" "$PASS-approve" | a admin init --passphrase-stdin >/dev/null
echo -n "$PASS" | a admin login --passphrase-stdin >/dev/null
a init --vault "$BARE" >/dev/null 2>&1
A_VAULT="$A/Library/Application Support/dop/vault"
cat > "$A_VAULT/vault.yaml" <<'YAML'
schema_version: v1
integrations:
  notion: {metadata: {u: "1"}, tokens: {read: {value: "ntn_leased_secret"}}}
grants:
  notion.read: {integration: notion, token: read, env_prefix: N}
YAML
out=$(a token issue --grants notion.read --name cam-shell --portable --lease-cap 30m 2>&1)
PORTABLE=$(echo "$out" | grep -E '^tok_1' | head -1); [[ -n "$PORTABLE" ]] || { echo "$out"; fail "issue portable failed"; }
a push >/dev/null 2>&1 || fail "admin push failed"
pass "portable bearer cam-shell issued (cap 30m)"

echo "=== [B0] server attaches the vault as a cache"
b init --cache "$BARE" >/dev/null 2>&1 || fail "server attach failed"
pass "server attached"

echo "=== [B1] server asks: dop use cam-shell --remote (waits in the background)"
( b use cam-shell --agent-name buzz-reader >"$WORKROOT/use1.out" 2>"$WORKROOT/use1.err" ) & USE1=$!
for i in $(seq 1 30); do a pull >/dev/null 2>&1 || true; ls "$A_VAULT/pending-use"/*.json >/dev/null 2>&1 && break; sleep 1; done
REQ=$(a approve-remote --list 2>&1 | awk '/^lease/{print $0}' | sed -n 's/.*id \([0-9a-f]*\).*/\1/p' | head -1)
[[ -n "$REQ" ]] || { cat "$WORKROOT/use1.err"; fail "request not visible to the admin"; }
pass "request $REQ staged and listed"

echo "=== [A1] wrong passphrase refused"
if echo -n "nope-nope-nope" | a approve-remote --use "$REQ" --lease 10m --passphrase-stdin >/dev/null 2>&1; then fail "wrong passphrase accepted"; fi
pass "wrong passphrase refused"

echo "=== [A2] approve for 10 minutes"
echo -n "$PASS-approve" | a approve-remote --use "$REQ" --lease 10m --passphrase-stdin >"$WORKROOT/ap.log" 2>&1 || { cat "$WORKROOT/ap.log"; fail "approve failed"; }
grep -q "leased cam-shell to buzz-reader" "$WORKROOT/ap.log" || { cat "$WORKROOT/ap.log"; fail "unexpected approve output"; }
wait $USE1 || { cat "$WORKROOT/use1.err"; fail "server use --remote exited non-zero"; }
LEASE=$(sed -n 's/^export DOP_TOKEN=//p' "$WORKROOT/use1.out"); [[ -n "$LEASE" ]] || { cat "$WORKROOT/use1.err"; fail "no export line"; }
[[ "$LEASE" != "$PORTABLE" ]] || fail "the portable bearer itself was shipped"
pass "server got a fresh lease bearer"

echo "=== [B2] the lease works and carries the grant"
out=$(HOME="$B" DOP_TOKEN="$LEASE" "$DOP" exec --agent-name buzz-reader -- sh -c 'env | rev' 2>/dev/null | rev)
echo "$out" | grep -q "N_TOKEN=ntn_leased_secret" || { echo "$out"; fail "lease exec missing env"; }
a pull >/dev/null 2>&1; ls "$A_VAULT/pending-use"/*.json >/dev/null 2>&1 && fail "request/lease files not consumed"
pass "lease execs; request consumed"

echo "=== [B3] a second dop use reuses the lease — no new request"
b use cam-shell --remote --agent-name buzz-reader >"$WORKROOT/reuse.out" 2>"$WORKROOT/reuse.err" || { cat "$WORKROOT/reuse.err"; fail "reuse exited non-zero"; }
grep -q "reusing the lease" "$WORKROOT/reuse.err" || { cat "$WORKROOT/reuse.err"; fail "lease not reused"; }
[[ "$(sed -n 's/^export DOP_TOKEN=//p' "$WORKROOT/reuse.out")" == "$LEASE" ]] || fail "reuse printed another bearer"
a pull >/dev/null 2>&1; ls "$A_VAULT/pending-use"/*.json >/dev/null 2>&1 && fail "reuse staged a new request"
pass "second use reuses the lease"
TOKF="$WORKROOT/lease-token.json"
b use cam-shell --remote --token-file "$TOKF" >/dev/null 2>"$WORKROOT/tokf.err" || { cat "$WORKROOT/tokf.err"; fail "use --token-file exited non-zero"; }
out=$(HOME="$B" DOP_TOKEN_FILE="$TOKF" "$DOP" exec --agent-name buzz-reader -- sh -c 'env | rev' 2>"$WORKROOT/tokf-exec.err" | rev)
echo "$out" | grep -q "N_TOKEN=ntn_leased_secret" || { cat "$WORKROOT/tokf-exec.err"; fail "exec ignores DOP_TOKEN_FILE written by dop use"; }
EXP=$(sed -n 's/.*"expires_at": *"\([^"]*\)".*/\1/p' "$TOKF")
EXP_S=$(date -u -j -f "%Y-%m-%dT%H:%M:%SZ" "$EXP" +%s 2>/dev/null || date -u -d "$EXP" +%s)
(( EXP_S - $(date +%s) <= 600 )) || fail "token file expires_at ($EXP) is beyond the 10m lease"
pass "token file execs and expires with the lease"
forget_lease() { find "$B" -type d -name leases -exec rm -rf {} + 2>/dev/null || true; }

echo "=== [A3] a 1s lease expires"
forget_lease
( b use cam-shell --remote --agent-name buzz-reader >"$WORKROOT/use2.out" 2>/dev/null ) & USE2=$!
for i in $(seq 1 30); do a pull >/dev/null 2>&1 || true; ls "$A_VAULT/pending-use"/*.json >/dev/null 2>&1 && break; sleep 1; done
REQ2=$(a approve-remote --list 2>&1 | sed -n 's/.*id \([0-9a-f]*\).*/\1/p' | head -1)
echo -n "$PASS-approve" | a approve-remote --use "$REQ2" --lease 1s --passphrase-stdin >"$WORKROOT/ap3.log" 2>&1 || { cat "$WORKROOT/ap3.log"; a approve-remote --list; ls "$A_VAULT/pending-use"; fail "approve 1s failed"; }
wait $USE2 || fail "server use (1s) exited non-zero"
SHORT=$(sed -n 's/^export DOP_TOKEN=//p' "$WORKROOT/use2.out"); sleep 2
if HOME="$B" DOP_TOKEN="$SHORT" "$DOP" exec --agent-name buzz-reader -- true >/dev/null 2>&1; then fail "expired lease still execs"; fi
pass "expired lease refused"

echo "=== [A4] reject → server exits non-zero (server copy is behind the team: admin pushed first)"
forget_lease
a token issue --grants notion.read --name other-bearer --portable >/dev/null 2>&1 && a push >/dev/null 2>&1 || fail "admin second push failed"
ls "$A_VAULT/pending-use"/*.json >/dev/null 2>&1 && fail "consumed request came back as a ghost after the admin's merge"
( b use cam-shell --remote >/dev/null 2>"$WORKROOT/use3.err" ) & USE3=$!
for i in $(seq 1 30); do a pull >/dev/null 2>&1 || true; ls "$A_VAULT/pending-use"/*.json >/dev/null 2>&1 && break; sleep 1; done
REQ3=$(a approve-remote --list 2>&1 | sed -n 's/.*id \([0-9a-f]*\).*/\1/p' | head -1)
a approve-remote --use "$REQ3" --reject >/dev/null 2>&1 || fail "reject failed"
if wait $USE3; then fail "server use exited 0 after a reject"; fi
grep -q "rejected" "$WORKROOT/use3.err" || { cat "$WORKROOT/use3.err"; fail "server did not report the reject"; }
pass "reject reaches the server"

echo "=== [A5] lease above the cap is clamped to 30m"
forget_lease
( b use cam-shell --remote >"$WORKROOT/use4.out" 2>/dev/null ) & USE4=$!
for i in $(seq 1 30); do a pull >/dev/null 2>&1 || true; ls "$A_VAULT/pending-use"/*.json >/dev/null 2>&1 && break; sleep 1; done
REQ4=$(a approve-remote --list 2>&1 | sed -n 's/.*id \([0-9a-f]*\).*/\1/p' | head -1)
a token show cam-shell --json 2>/dev/null | grep -o '"lease_cap_seconds":[0-9]*' || echo "(no lease_cap_seconds in token show)"
echo -n "$PASS-approve" | a approve-remote --use "$REQ4" --lease 4h --passphrase-stdin >"$WORKROOT/ap5.log" 2>&1 || { cat "$WORKROOT/ap5.log"; fail "approve (cap) failed"; }
grep -q "cap for cam-shell is 30m" "$WORKROOT/ap5.log" || { cat "$WORKROOT/ap5.log"; fail "cap not applied"; }
wait $USE4 || fail "server use (cap) exited non-zero"
pass "lease clamped to the cap"

a admin logout >/dev/null 2>&1 || true
echo ""
echo "V1.21 remote-use e2e: PASS"
