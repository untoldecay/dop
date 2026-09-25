#!/usr/bin/env bash
# P6 end-to-end: teammate lifecycle
#   1. init, attach, seed vault (self is the only recipient)
#   2. Generate a fake "teammate" age keypair
#   3. dop team add-key --name teammate --pubkey <alice> — updates vault + .sops.yaml + sops updatekeys
#   4. dop team list shows the member
#   5. Verify the vault is decryptable by the teammate's key too
#   6. dop team remove --name teammate (dry-run) prints rotation checklist, doesn't remove
#   7. dop team remove --name teammate --force actually removes; teammate can no longer decrypt future writes

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "P6 e2e: no dop at $DOP" >&2; exit 2; }

WORKROOT=$(mktemp -d)
trap 'rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
export XDG_CONFIG_HOME="$HOME/.config"
mkdir -p "$HOME"

pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

echo "=== [1] setup vault"
"$DOP" init >/dev/null
"$DOP" init --vault "$WORKROOT/vault-bare" >/dev/null 2>&1
DOP_CLONE="$HOME/Library/Application Support/dop/vault"
[[ -d "$DOP_CLONE" ]] || DOP_CLONE="$HOME/.config/dop/vault"
cp testdata/vault.example.yaml "$DOP_CLONE/vault.plain.yaml"
"$DOP" encrypt "$DOP_CLONE/vault.plain.yaml" "$DOP_CLONE/vault.yaml" >/dev/null 2>&1
rm "$DOP_CLONE/vault.plain.yaml"
VAULT="$DOP_CLONE/vault.yaml"
pass "vault ready"

echo "=== [2] generate teammate keypair"
TEAMMATE_KEY="$WORKROOT/teammate.age"
age-keygen -o "$TEAMMATE_KEY" 2>/dev/null
TEAMMATE_PUB=$(grep '^# public key:' "$TEAMMATE_KEY" | awk '{print $NF}')
pass "teammate pubkey: $TEAMMATE_PUB"

echo "=== [3] dop team add-key"
"$DOP" team add-key --vault "$VAULT" --name teammate --pubkey "$TEAMMATE_PUB" --note "e2e test"
# Verify .sops.yaml now includes the teammate's pubkey
grep -q "$TEAMMATE_PUB" "$DOP_CLONE/.sops.yaml" || fail ".sops.yaml missing teammate pubkey"
pass "team member added, .sops.yaml updated"

echo "=== [4] dop team list shows the member"
list_out=$("$DOP" team list --vault "$VAULT" 2>/dev/null)
echo "$list_out" | grep -q "teammate" || fail "list missing teammate"
echo "$list_out" | grep -q "$TEAMMATE_PUB" || fail "list missing teammate pubkey"
pass "team list shows member"

echo "=== [5] teammate can decrypt the vault"
# Verify by running sops --decrypt with teammate's key file
SOPS_AGE_KEY_FILE="$TEAMMATE_KEY" sops --decrypt "$VAULT" | grep -q "boiler" || fail "teammate cannot decrypt"
pass "teammate can decrypt the vault"

echo "=== [6] dop team remove dry-run prints checklist"
dryrun_out=$("$DOP" team remove --vault "$VAULT" --name teammate 2>&1)
echo "$dryrun_out" | grep -qi "rotate" || fail "dry-run missing rotation checklist"
echo "$dryrun_out" | grep -q "boiler.tokens" || fail "dry-run missing boiler tokens in checklist"
echo "$dryrun_out" | grep -qi "dry run" || fail "dry-run doesn't announce itself"
# Confirm nothing changed
"$DOP" team list --vault "$VAULT" 2>/dev/null | grep -q "teammate" || fail "dry-run actually removed!"
pass "dry-run printed checklist, made no changes"

echo "=== [7] dop team remove --force actually removes"
"$DOP" team remove --vault "$VAULT" --name teammate --force 2>/dev/null
"$DOP" team list --vault "$VAULT" 2>/dev/null | grep -q "teammate" && fail "still listed after force-remove"
grep -q "$TEAMMATE_PUB" "$DOP_CLONE/.sops.yaml" && fail ".sops.yaml still has teammate pubkey"
pass "force-remove cleaned team_members and .sops.yaml"

echo "=== [8] after removal, a NEW re-encryption locks teammate out"
# Trigger a re-encryption by adding a benign token (this rewrites the vault)
"$DOP" token issue --vault "$VAULT" --grants boiler.read --name "post-removal" >/dev/null 2>&1
# Now teammate's key should fail
if SOPS_AGE_KEY_FILE="$TEAMMATE_KEY" sops --decrypt "$VAULT" 2>/dev/null | grep -q "boiler"; then
    fail "teammate can still decrypt after removal + re-encrypt"
fi
pass "post-removal writes no longer decryptable by teammate"

echo ""
echo "P6 e2e: PASS"
