#!/usr/bin/env bash
# P3 end-to-end: signed-challenge auth via --sign-with
#   1. init + attach + seed a vault
#   2. Generate a fresh age keypair for "buzz-alpha"
#   3. Add agent_pubkeys.buzz-alpha into the vault (grants = boiler.read)
#   4. dop exec --agent-name buzz-alpha --sign-with <keyfile> resolves scope
#      WITHOUT a DOP_TOKEN in env
#   5. Point --sign-with at a DIFFERENT keyfile → exec fails on pubkey mismatch

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "P3 e2e: no dop at $DOP" >&2; exit 2; }

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

echo "=== [2] generate buzz-alpha keypair"
ALPHA_KEY="$WORKROOT/buzz-alpha.age"
age-keygen -o "$ALPHA_KEY" 2>/dev/null
ALPHA_PUB=$(grep '^# public key:' "$ALPHA_KEY" | awk '{print $NF}')
[[ -n "$ALPHA_PUB" ]] || fail "no pubkey extracted"
pass "alpha pubkey: $ALPHA_PUB"

echo "=== [3] add agent_pubkeys.buzz-alpha into the vault"
# Decrypt → append entry via a small YAML edit → re-encrypt
SOPS_AGE_KEY_FILE="$HOME/Library/Application Support/dop/keys/age.txt"
[[ -f "$SOPS_AGE_KEY_FILE" ]] || SOPS_AGE_KEY_FILE="$HOME/.config/dop/keys/age.txt"
export SOPS_AGE_KEY_FILE

plain=$(sops --decrypt "$VAULT")
cat > "$WORKROOT/vault.plain.new.yaml" <<EOF
$plain

agent_pubkeys:
  buzz-alpha:
    pubkey_age: $ALPHA_PUB
    grants: [boiler.read]
    note: "e2e fixture"
EOF

sops --encrypt --age "$(grep '^# public key:' "$SOPS_AGE_KEY_FILE" | awk '{print $NF}')" \
     --input-type yaml --output-type yaml \
     --output "$VAULT" "$WORKROOT/vault.plain.new.yaml"
pass "vault updated with agent_pubkeys entry"

echo "=== [4] dop exec --sign-with (no DOP_TOKEN in env)"
unset DOP_TOKEN
env_out=$("$DOP" exec --vault "$VAULT" --agent-name buzz-alpha --sign-with "$ALPHA_KEY" --no-pull -- env 2>/dev/null)
echo "$env_out" | grep -q "BOILER_TOKEN=blr_ro_FIXTURE_TOKEN_READ" || fail "read scope not resolved via signed auth"
pass "signed auth resolved boiler.read"

echo "=== [5] mismatched keyfile → auth fails"
BETA_KEY="$WORKROOT/buzz-beta.age"
age-keygen -o "$BETA_KEY" 2>/dev/null
if "$DOP" exec --vault "$VAULT" --agent-name buzz-alpha --sign-with "$BETA_KEY" --no-pull -- true 2>/dev/null; then
    fail "mismatched keyfile still authenticated"
fi
pass "mismatched keyfile correctly rejected"

echo ""
echo "P3 e2e: PASS"
