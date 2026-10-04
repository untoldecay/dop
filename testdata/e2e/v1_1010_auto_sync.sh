#!/usr/bin/env bash
# V1.10.3 e2e: auto-sync — pull-merge on admin login, retry push through
# a smart merge when the remote has moved.

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "no dop"; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v1103-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT

BARE="$WORKROOT/bare.git"
HOME_A="$WORKROOT/homeA"
HOME_B="$WORKROOT/homeB"
mkdir -p "$HOME_A" "$HOME_B"
export DOP_NO_TUI=1
export DOP_NO_NOTIFY=1

PASS="pass-word-long-enough"
export DOP_APPROVAL_PASSPHRASE="$PASS-approve"
echo "=== [1] M1 seeded + shared-identity M2 attached"
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
HOME="$HOME_A" "$DOP" token issue --no-bind --grants notion.read --name seed >/dev/null 2>&1

HOME="$HOME_B" "$DOP" init --cache "$BARE" >/dev/null 2>&1
mkdir -p "$HOME_B/Library/Application Support/dop/keys"
cp "$HOME_A/Library/Application Support/dop/keys/admin.age.enc" \
   "$HOME_B/Library/Application Support/dop/keys/admin.age.enc"
cp "$HOME_A/Library/Application Support/dop/keys/approval.hash" \
   "$HOME_B/Library/Application Support/dop/keys/approval.hash"
pass "setup done"

echo "=== [2] M1 issues tokenX while M2 was offline"
HOME="$HOME_A" "$DOP" token issue --no-bind --grants notion.read --name tokenX >/dev/null 2>&1
pass "M1 pushed tokenX"

echo "=== [3] M2 login should silently auto-pull the change"
# M2's cache still has the pre-tokenX vault. Login auto-pulls.
B_VAULT="$HOME_B/Library/Application Support/dop/vault"
cd "$B_VAULT"
git fetch origin 2>&1 | tail -1
BEHIND_BEFORE=$(git rev-list --count HEAD..origin/main 2>/dev/null || echo 0)
(( BEHIND_BEFORE > 0 )) || fail "test setup: M2 should be behind M1"

echo -n "$PASS" | HOME="$HOME_B" "$DOP" admin login --passphrase-stdin >/dev/null

BEHIND_AFTER=$(git rev-list --count HEAD..origin/main 2>/dev/null || echo 0)
(( BEHIND_AFTER == 0 )) || fail "auto-pull-on-login should have fast-forwarded (still behind by $BEHIND_AFTER)"
pass "auto-pull-on-login synced M2 to team"

echo "=== [4] M1 issues tokenY concurrently; M2 issues tokenZ — auto-merge on push"
HOME="$HOME_A" "$DOP" token issue --no-bind --grants notion.read --name tokenY 2>&1 | tail -3 || fail "M1 tokenY issue failed"
# M2 is now behind because M1 just pushed tokenY. M2 issues tokenZ →
# saveVaultViaDaemon → autoPushVault → push fails → autoPullAndMerge →
# push again. All silent, all clean.
set +e
HOME="$HOME_B" "$DOP" token issue --no-bind --grants notion.read --name tokenZ > /tmp/dop-tokenZ.out 2>&1
TZ_RC=$?
set -e
if (( TZ_RC != 0 )); then
    echo "--- M2 tokenZ exit=$TZ_RC ---"
    cat /tmp/dop-tokenZ.out
    fail "M2 token issue returned non-zero"
fi
if grep -qi "auto-push skipped\|deferred" /tmp/dop-tokenZ.out; then
    cat /tmp/dop-tokenZ.out
    fail "auto-sync should have handled the divergence silently"
fi
pass "M2 token issue auto-merged with team + pushed"

echo "=== [5] tokenY (from M1) and tokenZ (from M2) both present after"
# Pull latest to see remote state.
HOME="$HOME_A" "$DOP" pull >/dev/null 2>&1
LIST_A=$(HOME="$HOME_A" "$DOP" token list 2>&1)
echo "$LIST_A" | grep -q "subject=tokenX" || { echo "$LIST_A"; fail "tokenX missing from M1"; }
echo "$LIST_A" | grep -q "subject=tokenY" || { echo "$LIST_A"; fail "tokenY missing from M1"; }
echo "$LIST_A" | grep -q "subject=tokenZ" || { echo "$LIST_A"; fail "tokenZ missing from M1 (auto-sync failed)"; }
pass "M1 sees all three tokens after auto-sync round-trip"

echo "=== [6] DOP_NO_AUTO_PULL=1 disables the login pull"
HOME="$HOME_A" "$DOP" token issue --no-bind --grants notion.read --name late >/dev/null 2>&1
cd "$B_VAULT"
git fetch origin 2>&1 | tail -1
BEHIND=$(git rev-list --count HEAD..origin/main 2>/dev/null || echo 0)
(( BEHIND > 0 )) || fail "test setup: M2 should be behind M1 again"

pkill -9 -f "dop admin __session-daemon.*homeB" 2>/dev/null || true
sleep 1
echo -n "$PASS" | DOP_NO_AUTO_PULL=1 HOME="$HOME_B" "$DOP" admin login --passphrase-stdin >/dev/null
BEHIND_AFTER=$(git rev-list --count HEAD..origin/main 2>/dev/null || echo 0)
(( BEHIND_AFTER == BEHIND )) || fail "DOP_NO_AUTO_PULL should have skipped the pull (before=$BEHIND after=$BEHIND_AFTER)"
pass "DOP_NO_AUTO_PULL=1 skips login pull"

pkill -9 -f "dop admin __session-daemon" 2>/dev/null || true
echo "V1.10.3 auto-sync e2e: PASS"
