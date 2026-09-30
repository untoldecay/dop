#!/usr/bin/env bash
# V1.6.3 e2e: covers the six gaps found in the v1.6.2 review.
#  1. vault edit → sidecar regenerates
#  2. dop approve CLI shares rate limit with web (via pending file)
#  3. .gitignore seeded on dop init --vault
#  4a. dop team remove refuses self
#  4b. dop team remove refuses last admin
#  5. bootstrap admins.trust on dop init --vault (with active session)

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "no dop"; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v163-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
mkdir -p "$HOME"
export DOP_NO_TUI=1
export DOP_NO_KEYCHAIN=1
export DOP_NO_NOTIFY=1

PASS="pass-word-long-enough"
CFG_ROOT="$HOME/Library/Application Support/dop"
VAULT_DIR="$CFG_ROOT/vault"

echo "=== [1] setup"
printf "%s\n%s\n" "$PASS" "$PASS-approve" | "$DOP" admin init --passphrase-stdin >/dev/null
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null
"$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1
pass "admin+vault attached"

echo "=== [2] .gitignore seeded"
[[ -f "$VAULT_DIR/.gitignore" ]] || fail "no .gitignore"
grep -q ".dop-encrypt-" "$VAULT_DIR/.gitignore" || fail "gitignore missing sops staging pattern"
pass ".gitignore in place"

echo "=== [3] admins.trust bootstrapped by init --vault"
[[ -f "$VAULT_DIR/admins.trust" ]] || fail "no admins.trust — bootstrap failed"
grep -q "ed25519_pubkey" "$VAULT_DIR/admins.trust" || fail "trust file missing pubkey"
pass "trust file present"

echo "=== [4] seed vault + issue → sidecar exists"
cat > "$VAULT_DIR/vault.yaml" <<'EOF'
schema_version: v1
integrations:
  notion: {metadata: {u: "1"}, tokens: {read: {value: "ntn_xxx"}}}
grants:
  notion.read: {integration: notion, token: read, env_prefix: N}
EOF
BEARER=$("$DOP" token issue --no-bind --grants notion.read --name v163a 2>/dev/null | grep -E '^tok_1' | head -1)
[[ -n "$BEARER" ]] || fail "no bearer"
REC=$(ls "$VAULT_DIR/capabilities"/*.record 2>/dev/null | head -1)
[[ -n "$REC" ]] || fail "no .record file"
pass "issued + sidecar present"

echo "=== [5] vault edit → status revoked → syncSidecars deletes .record + .bundle"
# Simulate a vault edit: unlock, load, mutate status, save via `dop vault edit`.
# Simpler: use dop vault edit but drive it non-interactively by pre-writing
# the editor override.
cat > "$WORKROOT/editor.sh" <<'EEOF'
#!/usr/bin/env bash
sed -i '' 's/status: active/status: revoked/g' "$1"
EEOF
chmod +x "$WORKROOT/editor.sh"
EDITOR="$WORKROOT/editor.sh" "$DOP" vault edit >/dev/null 2>&1 || fail "vault edit failed"
[[ -f "$REC" ]] && fail "sidecar should be deleted after status→revoked"
pass "vault edit propagates revoke → sidecar gone"

echo "=== [6] exec on revoked bearer fails"
if DOP_TOKEN="$BEARER" "$DOP" exec --agent-name v -- true 2>/dev/null; then
    fail "revoked-via-vault-edit bearer should not exec"
fi
pass "vault-edit revocation is enforced"

echo "=== [7] dop approve CLI shares rate limit — 8 wrong attempts → auto-reject"
# Issue a fresh bearer, PIN-bound, spin claim in background, and hammer the
# CLI approve path with wrong passphrases.
issue2=$("$DOP" token issue --grants notion.read --name v163b 2>&1)
B2=$(echo "$issue2" | grep -E '^tok_1' | head -1)
P2=$(echo "$issue2" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
DOP_TOKEN="$B2" "$DOP" claim --no-tunnel "$P2" >/dev/null 2>"$WORKROOT/claim.err" &
CLAIM_PID=$!
for _ in {1..20}; do
    SAS=$( ("$DOP" pending 2>&1 | awk 'NR==2 {print $1}' || true) )
    if [[ -n "$SAS" && "$SAS" != "SAS" && "$SAS" != "(no" ]]; then break; fi
    sleep 0.2
done
[[ -n "$SAS" ]] || fail "no SAS"
for i in {1..8}; do
    echo -n "wrong-nope-$i" | "$DOP" approve --passphrase-stdin "$SAS" 2>&1 | head -1 || true
done
# 9th attempt should be flat-refused (claim already aborted).
out=$(echo -n "$PASS-approve" | "$DOP" approve --passphrase-stdin "$SAS" 2>&1 || true)
echo "$out" | grep -qE "burned|no pending claim matches" || { echo "$out"; fail "8 attempts should have burned the claim"; }
wait $CLAIM_PID 2>/dev/null || true
pass "CLI approve rate limit enforced"

echo "=== [8] dop team remove refuses last-admin removal (only one admin)"
out=$("$DOP" team remove --name "$(hostname)" --force 2>&1 || true)
echo "$out" | grep -q "only admin" || { echo "$out"; fail "should refuse last-admin removal"; }
pass "last-admin removal refused"

echo "=== [9] dop team remove refuses self (with 2 admins registered)"
# Register a second admin so the last-admin guard doesn't trigger first.
# Need a real-looking age recipient — generate one via age-keygen if
# available, else synthesise a plausible one.
if command -v age-keygen >/dev/null 2>&1; then
    TEAMMATE_AGE=$(age-keygen 2>/dev/null | awk -F': ' '/public key/ {print $2}')
else
    TEAMMATE_AGE="age1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqcv3aze"
fi
"$DOP" team add-key --name teammate --pubkey "$TEAMMATE_AGE" --ed25519 aabbccddeeff --note peer >/dev/null 2>&1
"$DOP" team list 2>&1 | grep -q teammate || fail "team add-key failed (age $TEAMMATE_AGE)"
out=$("$DOP" team remove --name "$(hostname)" --force 2>&1 || true)
echo "$out" | grep -q "refusing to remove yourself" || { echo "$out"; fail "should refuse self-remove"; }
pass "self-remove refused"

echo ""
echo "V1.6.3 gaps e2e: PASS"
