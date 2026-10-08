#!/usr/bin/env bash
# V1.17 e2e (dop-8g7): a claimed agent is a fixed identity. After the
# (admin-approved) claim, `dop env` from a brand-new context — new
# session id, no trust-cache entry, no scripted passphrase — prints
# without any approval, because the agent proves its bound key.
# Bearers without that proof (unbound) stay gated.
set -euo pipefail
DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "V1.17 claimed-env e2e: no dop at $DOP" >&2; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }
WORKROOT=$(mktemp -d /tmp/dop-v1700-XXXX)
cleanup() { "$DOP" admin logout >/dev/null 2>&1 || true; rm -rf "$WORKROOT"; }
trap cleanup EXIT
export HOME="$WORKROOT/home"
mkdir -p "$HOME"
export DOP_NO_TUI=1 DOP_NO_KEYCHAIN=1 DOP_NO_NOTIFY=1
PASS="pass-word-long-enough"
CFG_ROOT="$HOME/Library/Application Support/dop"
[[ -d "$HOME/.config" && ! -d "$CFG_ROOT" ]] && CFG_ROOT="$HOME/.config/dop"
VAULT_DIR="$CFG_ROOT/vault"
LOG="$CFG_ROOT/logs/audit.jsonl"

echo "=== [1] setup"
git init -q --bare -b main "$WORKROOT/bare"
printf "%s\n%s\n" "$PASS" "$PASS-approve" | "$DOP" admin init --passphrase-stdin >/dev/null
"$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null
cat > "$VAULT_DIR/vault.yaml" <<'EOF'
schema_version: v1
integrations:
  notion:
    metadata: {base_url: "https://api.notion.com/v1"}
    tokens: {read: {value: "SECRET_FOR_CLAIMED_AGENT"}}
grants:
  notion.read: {integration: notion, token: read, env_prefix: NOTION}
EOF
pass "admin + vault ready"

echo "=== [2] issue + claim (the claim is the admin-approved step)"
issue_out=$(DOP_APPROVAL_PASSPHRASE="$PASS-approve" "$DOP" token issue --grants notion.read --name honey 2>&1)
BEARER=$(echo "$issue_out" | grep -E '^tok_1' | head -1)
PIN=$(echo "$issue_out" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
[[ -n "$BEARER" && -n "$PIN" ]] || { echo "$issue_out"; fail "issue failed"; }
DOP_TOKEN="$BEARER" DOP_APPROVAL_PASSPHRASE="$PASS-approve" "$DOP" claim --skip-approval "$PIN" >/dev/null 2>&1 || fail "claim failed"
pass "claimed honey"

echo "=== [3] fresh context, no approval available: dop env prints"
unset DOP_APPROVAL_PASSPHRASE
out=$(DOP_TOKEN="$BEARER" DOP_SESSION_ID="restart-$RANDOM-$RANDOM" "$DOP" env </dev/null 2>&1) || { echo "$out"; fail "dop env refused a claimed agent"; }
echo "$out" | grep -q "SECRET_FOR_CLAIMED_AGENT" || { echo "$out"; fail "dop env did not print the env"; }
pass "claimed agent printed its env without approval"
grep '"print_approval_granted"' "$LOG" | grep -q '"key_proof"' || fail "no key_proof audit event"
pass "audited as channel=key_proof"

echo "=== [4] unbound bearer: still gated"
nb_out=$(DOP_APPROVAL_PASSPHRASE="$PASS-approve" "$DOP" token issue --no-bind --grants notion.read --name loose 2>&1)
NB=$(echo "$nb_out" | grep -E '^tok_1' | head -1)
[[ -n "$NB" ]] || { echo "$nb_out"; fail "unbound issue failed"; }
set +e
# A wrong scripted passphrase reaches the refusal without a popup/tunnel.
nb_env=$(DOP_TOKEN="$NB" DOP_APPROVAL_PASSPHRASE="wrong-passphrase" "$DOP" env </dev/null 2>&1)
rc=$?
set -e
(( rc != 0 )) || { echo "$nb_env"; fail "unbound bearer printed without approval"; }
echo "$nb_env" | grep -q "SECRET_FOR_CLAIMED_AGENT" && fail "unbound bearer leaked the secret"
pass "unbound bearer refused without approval"

echo "=== [5] dop use on a claimed bearer points to dop exec"
set +e
use_out=$("$DOP" use honey </dev/null 2>&1)
set -e
echo "$use_out" | grep -q "dop exec --agent-name honey" || { echo "$use_out"; fail "dop use did not point to dop exec"; }
pass "dop use → exec hint"

echo "V1.17 claimed-env-no-approval e2e: PASS"
