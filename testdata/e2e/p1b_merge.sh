#!/usr/bin/env bash
# P1.b end-to-end: parallel-branch merge of an encrypted vault should
# resolve cleanly via the SOPS-aware git merge driver.
#
# Steps:
#   1. dop init + dop init --vault <bare-repo>
#   2. Seed encrypted vault, commit + push to bare
#   3. Fork two working clones (clone-A, clone-B), each with its own decrypt
#   4. clone-A: modify boiler.read.value  → commit + push
#   5. clone-B: modify notion.read.value  → commit; git pull (which triggers merge)
#   6. Verify merged encrypted vault decrypts cleanly and contains BOTH edits
#
# Exit non-zero on any failure. Uses only public dop CLI + git + sops.

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
if [[ ! -x "$DOP" ]]; then
    echo "P1.b e2e: dop binary not found at $DOP" >&2
    exit 2
fi

WORKROOT=$(mktemp -d)
trap 'rm -rf "$WORKROOT"' EXIT

export HOME="$WORKROOT/home"
export XDG_CONFIG_HOME="$HOME/.config"
mkdir -p "$HOME"

BARE_REPO="$WORKROOT/vault-bare"
CLONE_A="$WORKROOT/clone-a"
CLONE_B="$WORKROOT/clone-b"

pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

echo "=== [1] dop init + attach vault"
"$DOP" init >/dev/null
"$DOP" init --vault "$BARE_REPO" >/dev/null 2>&1
# Locate the dop-managed clone.
DOP_CLONE="$HOME/Library/Application Support/dop/vault"
if [[ ! -d "$DOP_CLONE" ]]; then
    DOP_CLONE="$HOME/.config/dop/vault"
fi
[[ -d "$DOP_CLONE" ]] || fail "dop-managed vault clone not found"

# Configure git identity in the clone so commits work.
git -C "$DOP_CLONE" config user.email "e2e@example"
git -C "$DOP_CLONE" config user.name "e2e"
pass "vault attached at $DOP_CLONE"

echo "=== [2] seed encrypted vault via dop encrypt, commit + push"
cp testdata/vault.example.yaml "$DOP_CLONE/vault.plain.yaml"
"$DOP" encrypt "$DOP_CLONE/vault.plain.yaml" "$DOP_CLONE/vault.yaml" >/dev/null 2>&1
rm "$DOP_CLONE/vault.plain.yaml"
git -C "$DOP_CLONE" add -A
git -C "$DOP_CLONE" commit -m "seed" >/dev/null
git -C "$DOP_CLONE" push origin HEAD:refs/heads/main >/dev/null 2>&1
git -C "$BARE_REPO" symbolic-ref HEAD refs/heads/main >/dev/null 2>&1
pass "seeded and pushed to bare"

echo "=== [3] fork two working clones"
git clone "$BARE_REPO" "$CLONE_A" >/dev/null 2>&1
git clone "$BARE_REPO" "$CLONE_B" >/dev/null 2>&1
# Bring over the SOPS_AGE_KEY_FILE so both clones can decrypt.
KEYFILE="$HOME/Library/Application Support/dop/keys/age.txt"
[[ -f "$KEYFILE" ]] || KEYFILE="$HOME/.config/dop/keys/age.txt"

for repo in "$CLONE_A" "$CLONE_B"; do
    git -C "$repo" config user.email "e2e@example"
    git -C "$repo" config user.name "e2e"
    # Register the dop merge driver locally (as vaultgit.installMergeDriver would).
    git -C "$repo" config merge.dop.name "DOP SOPS+age merge driver"
    git -C "$repo" config merge.dop.driver "$DOP merge-driver %O %A %B"
done
pass "clones ready with merge driver"

echo "=== [4] clone-A: bump boiler.read.value, commit + push"
(
    export SOPS_AGE_KEY_FILE="$KEYFILE"
    cd "$CLONE_A"
    sops --set '["integrations"]["boiler"]["tokens"]["read"]["value"] "blr_ro_UPDATED_BY_A"' vault.yaml
    git add vault.yaml
    git commit -m "A edits boiler.read" >/dev/null
    git push origin main >/dev/null 2>&1
)
pass "A pushed"

echo "=== [5] clone-B: bump notion.read.value, commit, then pull (triggers merge)"
(
    export SOPS_AGE_KEY_FILE="$KEYFILE"
    cd "$CLONE_B"
    sops --set '["integrations"]["notion"]["tokens"]["read"]["value"] "ntn_ro_UPDATED_BY_B"' vault.yaml
    git add vault.yaml
    git commit -m "B edits notion.read" >/dev/null
    # This pull will trigger a merge because A's push moved main.
    # The dop merge driver should resolve the encrypted-YAML conflict cleanly.
    git pull --no-edit --no-rebase origin main
)
pass "B pulled + merged"

echo "=== [6] verify merged vault contains both edits after decrypt"
(
    export SOPS_AGE_KEY_FILE="$KEYFILE"
    plain=$(sops --decrypt "$CLONE_B/vault.yaml")
    echo "$plain" | grep -q "blr_ro_UPDATED_BY_A" || fail "A's edit missing from merged vault"
    echo "$plain" | grep -q "ntn_ro_UPDATED_BY_B" || fail "B's edit missing from merged vault"
)
pass "both edits present in merged encrypted vault"

echo ""
echo "P1.b e2e: PASS"
