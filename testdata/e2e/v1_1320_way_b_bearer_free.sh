#!/usr/bin/env bash
# V1.13.0-rc11 e2e: Way B — bearer-free exec via local agent key.
# Issue a P-256 bearer, claim it, admin reseals (so EnvWrapped exists),
# then run `dop exec` + `dop env` WITHOUT $DOP_TOKEN or --token-file.
# Resolution happens via the local p256 key + EnvWrapped.

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "V1.13 Way B e2e: no dop at $DOP" >&2; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v1320-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
mkdir -p "$HOME"
export DOP_NO_TUI=1
export DOP_NO_KEYCHAIN=1
export DOP_ALLOW_FILE_KEYS=1

PASS="pass-word-long-enough"
export DOP_APPROVAL_PASSPHRASE="$PASS-approve"
VAULT_DIR="$HOME/Library/Application Support/dop/vault"

echo "=== [1] setup + seed + issue + claim p256"
printf "%s\n%s\n" "$PASS" "$PASS-approve" | "$DOP" admin init --passphrase-stdin >/dev/null
"$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null
cat > "$VAULT_DIR/vault.yaml" <<'EOF'
schema_version: v1
integrations:
  notion: {metadata: {}, tokens: {read: {value: "ntn_val"}}}
grants:
  notion.read: {integration: notion, token: read, env_prefix: NOTION}
EOF
OUT=$("$DOP" token issue --grants notion.read --name wayb 2>&1)
BEARER=$(echo "$OUT" | grep -E '^tok_1' | head -1)
PIN=$(echo "$OUT" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
# dop-3o5: before any claim, whoami with no bearer says there's no access.
if OUT_W0=$(env -u DOP_TOKEN -u DOP_TOKEN_FILE "$DOP" whoami 2>&1); then
  fail "whoami with no bearer and no agent key should fail: $OUT_W0"
fi
echo "$OUT_W0" | grep -q "no claimed agent key on this host" || fail "whoami no-access message missing: $OUT_W0"
pass "whoami, unclaimed host: no DOP access"
DOP_TOKEN="$BEARER" "$DOP" claim --skip-approval --key-type p256 "$PIN" >/dev/null 2>&1
pass "claimed with p256"

echo "=== [2] admin reseal — populates EnvWrapped"
"$DOP" token reseal wayb >/dev/null 2>&1 || fail "reseal failed"
pass "resealed"

echo "=== [3] baseline: dop env WITH \$DOP_TOKEN still works"
E1=$(DOP_TOKEN="$BEARER" "$DOP" env 2>&1)
echo "$E1" | grep -q "NOTION_TOKEN='ntn_val'" || fail "baseline env missing: $E1"
pass "with-bearer path still works"

echo "=== [4] WAY B: dop env WITHOUT \$DOP_TOKEN resolves via local p256 key"
# Unset every possible bearer env var.
unset DOP_TOKEN DOP_TOKEN_FILE
E2=$("$DOP" env 2>&1)
echo "$E2" | grep -q "NOTION_TOKEN='ntn_val'" || fail "Way B env missing: $E2"
pass "bearer-free env resolved via agent key"

echo "=== [5] WAY B: dop exec --agent-name without bearer runs child with env"
# Give env to a child, verify it was injected.
OUT_EXEC=$("$DOP" exec --inherit-env --agent-name wayb -- sh -c 'echo "GOT=$NOTION_TOKEN"' 2>&1)
echo "$OUT_EXEC" | grep -q "GOT=ntn_val" || fail "exec didn't inject env: $OUT_EXEC"
pass "bearer-free exec injected env to child"

echo "=== [5a] a free-text --agent-name works with one claimed key (it's the audit label)"
OUT_FT=$("$DOP" exec --inherit-env --agent-name research -- sh -c 'echo "GOT=$NOTION_TOKEN"' 2>&1)
echo "$OUT_FT" | grep -q "GOT=ntn_val" || fail "free-text agent name refused: $OUT_FT"
pass "--agent-name research ran with the only claimed key"

echo "=== [5b] dop-3o5: whoami without \$DOP_TOKEN recognises the claimed agent key"
OUT_W1=$("$DOP" whoami 2>&1) || fail "bearer-free whoami failed: $OUT_W1"
echo "$OUT_W1" | grep -q "claimed on this host" || fail "whoami didn't see the claim: $OUT_W1"
echo "$OUT_W1" | grep -q "subject:    wayb" || fail "whoami subject missing: $OUT_W1"
echo "$OUT_W1" | grep -q "dop exec --agent-name wayb -- <cmd>" || fail "whoami use line missing: $OUT_W1"
echo "$OUT_W1" | grep -q "ntn_val" && fail "whoami printed a secret: $OUT_W1"
echo "$OUT_W1" | grep -q "grants:     notion.read" || fail "whoami doesn't list the grants: $OUT_W1"
echo "$OUT_W1" | grep -qx "  NOTION_TOKEN" || fail "whoami doesn't list the variable names: $OUT_W1"
pass "bearer-free whoami lists the claimed subject, no secret"

echo "=== [6] issue a SECOND p256 bearer — bearer-free env now ambiguous"
OUT=$("$DOP" token issue --grants notion.read --name wayb-second 2>&1)
B2=$(echo "$OUT" | grep -E '^tok_1' | head -1)
P2=$(echo "$OUT" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
DOP_TOKEN="$B2" "$DOP" claim --skip-approval --key-type p256 "$P2" >/dev/null 2>&1
"$DOP" token reseal wayb-second >/dev/null 2>&1
# `dop env` without a bearer should now fail with ambiguity.
if OUT_AMB=$("$DOP" env 2>&1); then
  fail "bearer-free env should refuse with multiple candidates: $OUT_AMB"
fi
echo "$OUT_AMB" | grep -q "multiple local agent keys" || fail "ambiguity error missing: $OUT_AMB"
pass "ambiguous → clear error"
OUT_W2=$("$DOP" whoami 2>&1) || fail "bearer-free whoami (two keys) failed: $OUT_W2"
echo "$OUT_W2" | grep -q "subject:    wayb-second" || fail "whoami missing second subject: $OUT_W2"
pass "bearer-free whoami lists both claimed subjects"

echo "=== [7] --agent-name disambiguates"
OUT_EXEC2=$("$DOP" exec --inherit-env --agent-name wayb-second -- sh -c 'echo "GOT=$NOTION_TOKEN"' 2>&1)
echo "$OUT_EXEC2" | grep -q "GOT=ntn_val" || fail "disambiguation failed: $OUT_EXEC2"
pass "--agent-name narrows to one"

echo "=== [8] with two keys, an unknown --agent-name names the choices"
if OUT_UK=$("$DOP" exec --agent-name research -- true 2>&1); then fail "unknown name should be refused with two keys"; fi
echo "$OUT_UK" | grep -q "one of: " || fail "choice list missing: $OUT_UK"
pass "two keys + unknown name → choices listed"

echo
echo "V1.13 Way B e2e: ALL PASS"
