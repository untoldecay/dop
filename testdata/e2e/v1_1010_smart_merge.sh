#!/usr/bin/env bash
# V1.10.2 e2e: dop pull's real 3-way merge.
# Setup: shared-identity M1 + M2 so both can decrypt each other's
# vaults. M1 adds token A, M2 adds token B. Neither is on the other's
# clone. dop pull on M2 should merge both — plaintext union.

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "no dop"; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v1102-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT

BARE="$WORKROOT/bare.git"
HOME_A="$WORKROOT/homeA"
HOME_B="$WORKROOT/homeB"
mkdir -p "$HOME_A" "$HOME_B"
export DOP_NO_TUI=1
export DOP_NO_NOTIFY=1

PASS="pass-word-long-enough"
export DOP_APPROVAL_PASSPHRASE="$PASS-approve"
echo "=== [1] M1 setup + vault seed + issue token A"
printf "%s\n%s\n" "$PASS" "$PASS-approve" | HOME="$HOME_A" "$DOP" admin init --passphrase-stdin >/dev/null
HOME="$HOME_A" "$DOP" init --vault "$BARE" >/dev/null 2>&1
echo -n "$PASS" | HOME="$HOME_A" "$DOP" admin login --passphrase-stdin >/dev/null
cat > "$HOME_A/Library/Application Support/dop/vault/vault.yaml" <<'EOF'
schema_version: v1
integrations:
  notion:
    metadata: {base_url: "https://api.notion.com/v1"}
    tokens: {read: {value: "ntn_seed_secret"}}
grants:
  notion.read: {integration: notion, token: read, env_prefix: NOTION}
EOF
HOME="$HOME_A" "$DOP" token issue --no-bind --grants notion.read --name tokenA >/dev/null 2>&1
# Force push (autopush already ran).
pass "M1 seeded + issued tokenA"

echo "=== [2] M2 shared-identity join"
HOME="$HOME_B" "$DOP" init --cache "$BARE" >/dev/null 2>&1
# Convert to admin install by copying M1's admin keys (share-identity blob).
# Simplest for the test: reuse M1's daemon by copying admin.age.enc.
mkdir -p "$HOME_B/Library/Application Support/dop/keys"
cp "$HOME_A/Library/Application Support/dop/keys/admin.age.enc" \
   "$HOME_B/Library/Application Support/dop/keys/admin.age.enc"
cp "$HOME_A/Library/Application Support/dop/keys/approval.hash" \
   "$HOME_B/Library/Application Support/dop/keys/approval.hash"
echo -n "$PASS" | HOME="$HOME_B" "$DOP" admin login --passphrase-stdin >/dev/null
pass "M2 attached with M1's identity"

echo "=== [3] M1 issues tokenC; M2 issues tokenB — force divergence by disabling auto-pull on B"
HOME="$HOME_A" "$DOP" token issue --no-bind --grants notion.read --name tokenC >/dev/null 2>&1
# With auto-pull-on-login (v1.10.3) M2 would sync tokenC before its own
# issue and skip divergence entirely; force the diverged scenario by
# disabling auto-pull + auto-push during M2's issue.
DOP_NO_AUTO_PULL=1 DOP_NO_AUTO_PUSH=1 HOME="$HOME_B" "$DOP" token issue --no-bind --grants notion.read --name tokenB 2>&1 | tail -3 || true
# Commit and confirm B is diverged before pull.
B_VAULT="$HOME_B/Library/Application Support/dop/vault"
cd "$B_VAULT"
git add -A 2>/dev/null && git commit -m "M2 local tokenB" >/dev/null 2>&1 || true
git fetch origin 2>&1 | tail -1
AHEAD=$(git rev-list --count origin/main..HEAD 2>/dev/null || echo 0)
BEHIND=$(git rev-list --count HEAD..origin/main 2>/dev/null || echo 0)
echo "  M2 state: ours=$AHEAD theirs=$BEHIND"
(( AHEAD > 0 && BEHIND > 0 )) || fail "test setup failed to diverge (ours=$AHEAD theirs=$BEHIND)"
pass "divergent state established"

echo "=== [4] dop pull auto-merges — no conflicts, both tokens present"
PULL_OUT=$(HOME="$HOME_B" "$DOP" pull 2>&1)
echo "$PULL_OUT" | grep -qi "merged cleanly" || { echo "$PULL_OUT"; fail "expected 'merged cleanly'"; }
echo "$PULL_OUT" | grep -qi "issued token" || { echo "$PULL_OUT"; fail "summary should mention added tokens"; }
pass "smart merge succeeded"

echo "=== [5] both tokenB (local) and tokenC (remote) survived the merge"
LIST=$(HOME="$HOME_B" "$DOP" token list 2>&1)
echo "$LIST" | grep -q "subject=tokenA" || { echo "$LIST"; fail "tokenA missing"; }
echo "$LIST" | grep -q "subject=tokenB" || { echo "$LIST"; fail "tokenB missing (local lost in merge)"; }
echo "$LIST" | grep -q "subject=tokenC" || { echo "$LIST"; fail "tokenC missing (remote lost in merge)"; }
pass "all three tokens present after merge"

echo "=== [6] merge commit has two parents"
cd "$B_VAULT"
PARENTS=$(git log -1 --pretty=%P HEAD | wc -w | tr -d ' ')
(( PARENTS == 2 )) || fail "expected merge commit with 2 parents, got $PARENTS"
pass "merge commit has both histories"

pkill -9 -f "dop admin __session-daemon" 2>/dev/null || true
echo "V1.10.2 smart-merge e2e: PASS"
