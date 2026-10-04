#!/usr/bin/env bash
# V1.10.1 e2e: dop pull for diverged branches.
# Setup: two homes both pointing at the same bare remote. Both issue
# tokens (autopush). Machine B pulls after having its own commits →
# should get a clear diverged-branches message + --take-theirs works.

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "no dop"; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v1101-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT

BARE="$WORKROOT/bare.git"
HOME_A="$WORKROOT/homeA"
HOME_B="$WORKROOT/homeB"
mkdir -p "$HOME_A" "$HOME_B"
export DOP_NO_TUI=1
export DOP_NO_NOTIFY=1

PASS="pass-word-long-enough"
export DOP_APPROVAL_PASSPHRASE="$PASS-approve"
setup_home() {
    local home="$1"
    HOME="$home" printf "%s\n%s\n" "$PASS" "$PASS-approve" | HOME="$home" "$DOP" admin init --passphrase-stdin >/dev/null
    HOME="$home" "$DOP" init --vault "$BARE" >/dev/null 2>&1
    echo -n "$PASS" | HOME="$home" "$DOP" admin login --passphrase-stdin >/dev/null
}

echo "=== [1] set up machine A + bare + seed vault"
setup_home "$HOME_A"
cat > "$HOME_A/Library/Application Support/dop/vault/vault.yaml" <<'EOF'
schema_version: v1
integrations:
  notion:
    metadata: {base_url: "https://api.notion.com/v1"}
    tokens: {read: {value: "ntn_xxx"}}
grants:
  notion.read: {integration: notion, token: read, env_prefix: NOTION}
EOF
HOME="$HOME_A" "$DOP" token issue --no-bind --grants notion.read --name seedA >/dev/null 2>&1
# Ensure something is on the remote.
cd "$HOME_A/Library/Application Support/dop/vault"
git config user.email "a@test" && git config user.name "A"
git add -A 2>/dev/null || true
git commit -m "seed" >/dev/null 2>&1 || true
git push -u origin HEAD:main 2>/dev/null || true
pass "machine A seeded + pushed"

echo "=== [2] machine B init from same bare, log ancestor"
HOME="$HOME_B" "$DOP" init --cache "$BARE" >/dev/null 2>&1
# Convert B's install into an admin install with the same vault
printf "%s\n%s\n" "$PASS" "$PASS-approve" | HOME="$HOME_B" "$DOP" admin init --passphrase-stdin >/dev/null
echo -n "$PASS" | HOME="$HOME_B" "$DOP" admin login --passphrase-stdin >/dev/null
BASE_HEAD=$(git --git-dir="$BARE" log --oneline | wc -l | tr -d ' ')
pass "machine B attached ($BASE_HEAD commits on remote)"

echo "=== [3] force divergence directly on B's git repo (bypass sops)"
# Two machines in DOP normally share identity to sync. We're testing the
# git-side helper here, not the crypto. Force divergence with raw git.
B_VAULT="$HOME_B/Library/Application Support/dop/vault"
cd "$B_VAULT"
git config user.email "b@test" && git config user.name "B"
# Commit something locally that isn't on origin (any file works).
echo "local-only-B" > .local-marker
git add .local-marker
git commit -m "B: local marker" >/dev/null

# Meanwhile A pushes another commit to origin so B is behind AND ahead.
HOME="$HOME_A" "$DOP" token issue --no-bind --grants notion.read --name second >/dev/null 2>&1
cd "$B_VAULT"
git fetch origin 2>&1 | tail -1
AHEAD=$(git rev-list --count origin/main..HEAD 2>/dev/null || echo 0)
BEHIND=$(git rev-list --count HEAD..origin/main 2>/dev/null || echo 0)
echo "  B state: ahead=$AHEAD behind=$BEHIND"
(( AHEAD > 0 && BEHIND > 0 )) || fail "test setup failed to diverge (ahead=$AHEAD behind=$BEHIND)"
pass "divergence forced (B ahead by $AHEAD, behind by $BEHIND)"

echo "=== [4] dop pull --no-merge reports plain-English diagnosis"
PULL_OUT=$(HOME="$HOME_B" "$DOP" pull --no-merge 2>&1 || true)
# No git jargon: no "diverged", "branch", "commit ahead/behind", "origin/main".
if echo "$PULL_OUT" | grep -qwi 'diverged\|origin/main\|ff-only'; then
    echo "$PULL_OUT"
    fail "found git jargon in the plain-English output"
fi
echo "$PULL_OUT" | grep -qi "team" || { echo "$PULL_OUT"; fail "should mention 'team' explanation"; }
echo "$PULL_OUT" | grep -q -- "--keep-mine" || { echo "$PULL_OUT"; fail "should offer --keep-mine"; }
echo "$PULL_OUT" | grep -q -- "--keep-team" || { echo "$PULL_OUT"; fail "should offer --keep-team"; }
pass "plain-English diagnosis + both escape hatches offered"

echo "=== [5] dop pull --keep-team resets B to origin"
HOME="$HOME_B" "$DOP" pull --keep-team 2>&1 | tail -2
cd "$B_VAULT"
B_AHEAD=$(git rev-list --count origin/main..HEAD 2>/dev/null || echo 0)
B_BEHIND=$(git rev-list --count HEAD..origin/main 2>/dev/null || echo 0)
(( B_AHEAD == 0 && B_BEHIND == 0 )) || fail "after --keep-team, still off from team (ours=$B_AHEAD behind=$B_BEHIND)"
[[ ! -f .local-marker ]] || fail "--keep-team left the local-only file behind"
pass "--keep-team synced B to the team"

echo "=== [6] mutually exclusive flags rejected"
BOTH_OUT=$(HOME="$HOME_B" "$DOP" pull --keep-team --keep-mine 2>&1 || true)
echo "$BOTH_OUT" | grep -qi "pick one" || { echo "$BOTH_OUT"; fail "should refuse both flags"; }
pass "--keep-mine + --keep-team refused together"

echo "=== [7] back-compat aliases (--take-theirs / --take-ours) still work"
# Re-diverge with a fresh local commit.
echo "another-local" > .local-marker2
git add .local-marker2 && git commit -m "B: another marker" >/dev/null
HOME="$HOME_A" "$DOP" token issue --no-bind --grants notion.read --name third >/dev/null 2>&1
cd "$B_VAULT"
git fetch origin 2>&1 | tail -1
HOME="$HOME_B" "$DOP" pull --take-theirs 2>&1 | tail -1 | grep -q "team" || fail "--take-theirs alias should still work"
pass "--take-theirs still accepted as alias for --keep-team"

pkill -9 -f "dop admin __session-daemon" 2>/dev/null || true
echo "V1.10.1 pull helper e2e: PASS"
