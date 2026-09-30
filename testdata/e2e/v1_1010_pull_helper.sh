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

echo "=== [4] dop pull reports diverged + suggests options"
PULL_OUT=$(HOME="$HOME_B" "$DOP" pull 2>&1 || true)
echo "$PULL_OUT" | grep -qi "diverged" || { echo "$PULL_OUT"; fail "expected 'diverged' in output"; }
echo "$PULL_OUT" | grep -q -- "--take-theirs" || { echo "$PULL_OUT"; fail "expected --take-theirs suggestion"; }
echo "$PULL_OUT" | grep -q -- "--take-ours" || { echo "$PULL_OUT"; fail "expected --take-ours suggestion"; }
echo "$PULL_OUT" | grep -qi "sops-encrypted" || { echo "$PULL_OUT"; fail "expected sops warning"; }
pass "diverged pull reports diagnosis + all 3 options"

echo "=== [5] dop pull --take-theirs resets B to origin"
HOME="$HOME_B" "$DOP" pull --take-theirs 2>&1 | tail -2
cd "$B_VAULT"
B_AHEAD=$(git rev-list --count origin/main..HEAD 2>/dev/null || echo 0)
B_BEHIND=$(git rev-list --count HEAD..origin/main 2>/dev/null || echo 0)
(( B_AHEAD == 0 && B_BEHIND == 0 )) || fail "after --take-theirs, still diverged (ahead=$B_AHEAD behind=$B_BEHIND)"
[[ ! -f .local-marker ]] || fail "--take-theirs left the local-only file behind"
pass "--take-theirs restored B to origin (local commit discarded)"

echo "=== [6] mutually exclusive flags"
BOTH_OUT=$(HOME="$HOME_B" "$DOP" pull --take-theirs --take-ours 2>&1 || true)
echo "$BOTH_OUT" | grep -qi "mutually exclusive" || { echo "$BOTH_OUT"; fail "should refuse both flags"; }
pass "--take-theirs + --take-ours refused together"

pkill -9 -f "dop admin __session-daemon" 2>/dev/null || true
echo "V1.10.1 pull helper e2e: PASS"
