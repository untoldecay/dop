#!/usr/bin/env bash
# V1.18.1 e2e: `dop token repin --reclaim` re-issues a CLAIMED bearer (any
# key type) as a fresh PIN-bound one; without the flag it is refused with
# both ways out (rotate / --reclaim).
set -euo pipefail
DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "V1.18.1 reclaim e2e: no dop at $DOP" >&2; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }
WORKROOT=$(mktemp -d /tmp/dop-v1810-XXXX)
cleanup() { "$DOP" admin logout >/dev/null 2>&1 || true; rm -rf "$WORKROOT"; }
trap cleanup EXIT
export HOME="$WORKROOT/home" DOP_NO_TUI=1 DOP_NO_KEYCHAIN=1 DOP_NO_NOTIFY=1
mkdir -p "$HOME"
PASS="pass-word-long-enough"
export DOP_APPROVAL_PASSPHRASE="$PASS-approve"
CFG_ROOT="$HOME/Library/Application Support/dop"
[[ -d "$CFG_ROOT" ]] || CFG_ROOT="$HOME/.config/dop"

git init -q --bare -b main "$WORKROOT/bare"
printf "%s\n%s\n" "$PASS" "$PASS-approve" | "$DOP" admin init --passphrase-stdin >/dev/null
"$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null
CFG_ROOT="$HOME/Library/Application Support/dop"; [[ -d "$CFG_ROOT" ]] || CFG_ROOT="$HOME/.config/dop"
cat > "$CFG_ROOT/vault/vault.yaml" <<'YAML'
schema_version: v1
integrations:
  notion:
    tokens: {read: {value: "ntn_reclaim_value"}}
grants:
  notion.read: {integration: notion, token: read, env_prefix: NOTION}
YAML

echo "=== [1] issue + claim (ed25519 file key)"
out=$("$DOP" token issue --grants notion.read --name ed-agent 2>&1)
BEARER=$(echo "$out" | grep -E '^tok_1' | head -1)
PIN=$(echo "$out" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
DOP_TOKEN="$BEARER" "$DOP" claim --skip-approval "$PIN" >/dev/null 2>&1 || fail "claim failed"
pass "claimed"

echo "=== [2] repin without --reclaim is refused, pointing to both ways out"
set +e; ref=$("$DOP" token repin --subject ed-agent 2>&1); rc=$?; set -e
(( rc != 0 )) || fail "repin of a claimed bearer should be refused"
echo "$ref" | grep -q "dop token rotate" && echo "$ref" | grep -q -- "--reclaim" || { echo "$ref"; fail "refusal must name rotate and --reclaim"; }
pass "refused with rotate / --reclaim hint"

echo "=== [3] repin --reclaim → new bearer + PIN, old revoked, new unclaimed"
out=$("$DOP" token repin --subject ed-agent --reclaim 2>&1)
NEW=$(echo "$out" | grep -E '^tok_1' | head -1)
NPIN=$(echo "$out" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
[[ -n "$NEW" && -n "$NPIN" && "$NEW" != "$BEARER" ]] || { echo "$out"; fail "no fresh bearer + PIN"; }
"$DOP" token list --all 2>&1 | grep "subject=ed-agent" | grep -q "status=revoked" || fail "old record not revoked"
set +e; DOP_TOKEN="$BEARER" "$DOP" exec -- true >/dev/null 2>&1; old_rc=$?; set -e
(( old_rc != 0 )) || fail "old bearer still works"
pass "fresh bearer + PIN; old one revoked and refused"

echo "=== [4] the agent claims again; the new bearer works"
DOP_TOKEN="$NEW" "$DOP" claim --skip-approval "$NPIN" >/dev/null 2>&1 || fail "re-claim failed"
DOP_TOKEN="$NEW" "$DOP" exec -- sh -c '[ "$NOTION_TOKEN" = ntn_reclaim_value ]' </dev/null >/dev/null 2>&1 || fail "new bearer can't exec"
pass "re-claimed; exec works"
echo "=== [5] rotated P-256 bearer (pubkey-bound) can still --reclaim"
out=$("$DOP" token issue --grants notion.read --name p256-agent 2>&1)
B2=$(echo "$out" | grep -E '^tok_1' | head -1)
P2=$(echo "$out" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
DOP_TOKEN="$B2" DOP_ALLOW_FILE_KEYS=1 "$DOP" claim --skip-approval --key-type p256 "$P2" >/dev/null 2>&1 || fail "p256 claim failed"
"$DOP" token rotate p256-agent >/dev/null 2>&1 || fail "rotate failed"
"$DOP" token show p256-agent 2>&1 | grep -q "binding.kind: pubkey" || fail "rotated record should be pubkey-bound"
out=$("$DOP" token repin --subject p256-agent --reclaim 2>&1)
echo "$out" | grep -qE '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' || { echo "$out"; fail "--reclaim refused a rotated bearer"; }
"$DOP" token show p256-agent 2>&1 | grep -q "binding.kind: pin" || fail "reclaimed bearer should be PIN-bound"
pass "rotated bearer re-issued for a new claim"
echo "V1.18.1 reissue-reclaim e2e: PASS"
