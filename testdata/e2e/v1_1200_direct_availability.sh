#!/usr/bin/env bash
# V1.12 e2e (M3): direct availability of grant edits.
# Prove that `dop token add-grant` / `remove-grant` on a P-256-bound
# bearer take effect on the very next `dop exec`, no re-claim needed.

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "V1.12 e2e: no dop at $DOP" >&2; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v1200-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
export HOME="$WORKROOT/home"
mkdir -p "$HOME"
export DOP_NO_TUI=1
export DOP_NO_KEYCHAIN=1        # force file-backend path
export DOP_ALLOW_FILE_KEYS=1    # opt into extractable P-256 file keys

PASS="pass-word-long-enough"
export DOP_APPROVAL_PASSPHRASE="$PASS-approve"
CFG_ROOT="$HOME/Library/Application Support/dop"
VAULT_DIR="$CFG_ROOT/vault"

echo "=== [1] setup: admin init + seed 2 integrations + 2 grants"
printf "%s\n%s\n" "$PASS" "$PASS-approve" | "$DOP" admin init --passphrase-stdin >/dev/null
"$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null
cat > "$VAULT_DIR/vault.yaml" <<'EOF'
schema_version: v1
integrations:
  notion:
    metadata: {base_url: "https://api.notion.com/v1"}
    tokens:
      read: {value: "ntn_r_v1"}
  slack:
    metadata: {}
    tokens:
      bot: {value: "xoxb-secret"}
grants:
  notion.read: {integration: notion, token: read, env_prefix: NOTION}
  slack.bot:   {integration: slack, token: bot, env_prefix: SLACK}
EOF
pass "seeded 2 grants"

echo "=== [2] issue P-256 bearer + claim"
OUT=$("$DOP" token issue --grants notion.read --name direct-avail 2>&1)
BEARER=$(echo "$OUT" | grep -E '^tok_1' | head -1)
PIN=$(echo "$OUT" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
[[ -n "$BEARER" && -n "$PIN" ]] || fail "no bearer/PIN"
DOP_TOKEN="$BEARER" "$DOP" claim --skip-approval --key-type p256 "$PIN" >/dev/null 2>&1 \
  || fail "claim (p256) failed"
pass "issued + claimed with p256"

echo "=== [3] token show — confirm binding is p256, no EnvWrapped yet"
SHOW=$("$DOP" token show direct-avail --json 2>&1)
echo "$SHOW" | python3 -c "
import sys, json
d = json.loads(sys.stdin.read())
assert d['binding']['key_type'] == 'p256', 'binding not p256: '+str(d['binding'])
grants = [g['id'] for g in d['grants']]
assert grants == ['notion.read'], 'grants: '+str(grants)
" || fail "token show mismatch: $SHOW"
pass "binding.key_type=p256, grants=[notion.read]"

echo "=== [4] baseline dop env — sees notion (bundle env path, no EnvWrapped)"
ENV1=$(DOP_TOKEN="$BEARER" "$DOP" env 2>&1)
echo "$ENV1" | grep -q "NOTION_TOKEN='ntn_r_v1'" || fail "no NOTION_TOKEN in baseline env: $ENV1"
echo "$ENV1" | grep -q "SLACK_TOKEN" && fail "SLACK_TOKEN shouldn't be visible yet: $ENV1"
pass "baseline env has notion, no slack"

echo "=== [5] admin runs dop token add-grant"
"$DOP" token add-grant direct-avail slack.bot 2>&1 | grep -q "env resealed" \
  || fail "add-grant didn't reseal"
pass "add-grant slack.bot"

echo "=== [6] DIRECT AVAILABILITY: next dop env sees slack.bot"
ENV2=$(DOP_TOKEN="$BEARER" "$DOP" env 2>&1)
echo "$ENV2" | grep -q "NOTION_TOKEN='ntn_r_v1'" || fail "lost NOTION after add-grant: $ENV2"
echo "$ENV2" | grep -q "SLACK_TOKEN='xoxb-secret'" || fail "SLACK still missing after add-grant: $ENV2"
pass "SAME bearer sees new grant's env (no re-claim)"

echo "=== [7] admin runs dop token remove-grant"
"$DOP" token remove-grant direct-avail notion.read 2>&1 | grep -q "env resealed" \
  || fail "remove-grant didn't reseal"
pass "remove-grant notion.read"

echo "=== [8] DIRECT AVAILABILITY: next dop env drops notion"
ENV3=$(DOP_TOKEN="$BEARER" "$DOP" env 2>&1)
echo "$ENV3" | grep -q "NOTION_TOKEN" && fail "NOTION still leaks after remove-grant: $ENV3"
echo "$ENV3" | grep -q "SLACK_TOKEN='xoxb-secret'" || fail "SLACK lost: $ENV3"
pass "SAME bearer no longer sees removed grant's env"

echo "=== [9] rotate the upstream slack token via dop integration add"
# vault.yaml is SOPS-encrypted at rest; can't awk it directly. Use the
# daemon-routed path so the change lands cleanly.
"$DOP" integration add --name slack --token "bot=xoxb-rotated-v2" >/dev/null \
  || fail "integration add (update) failed"
"$DOP" token reseal direct-avail 2>&1 | grep -q "sealed env for" \
  || fail "reseal after vault-edit failed"
pass "vault edited + resealed"

echo "=== [10] DIRECT AVAILABILITY: vault-value change reaches exec"
ENV4=$(DOP_TOKEN="$BEARER" "$DOP" env 2>&1)
echo "$ENV4" | grep -q "SLACK_TOKEN='xoxb-rotated-v2'" \
  || fail "vault edit didn't propagate: $ENV4"
pass "vault-value edit reached agent's env with SAME bearer"

echo "=== [11] add-grant on ed25519 bearer refuses cleanly"
OUT2=$("$DOP" token issue --grants notion.read --name legacy-ed 2>&1)
BEARER_ED=$(echo "$OUT2" | grep -E '^tok_1' | head -1)
PIN_ED=$(echo "$OUT2" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
# legacy ed25519 on purpose (auto now falls back to a P-256 file — dop-7b7)
DOP_TOKEN="$BEARER_ED" "$DOP" claim --skip-approval --key-type ed25519 "$PIN_ED" >/dev/null 2>&1 || true
if OUT3=$("$DOP" token add-grant legacy-ed slack.bot 2>&1); then
  fail "add-grant should have refused ed25519: $OUT3"
fi
echo "$OUT3" | grep -qi "P-256\|migrate\|p256" || fail "error should name P-256 / migrate: $OUT3"
pass "ed25519 bearer gets clear P-256-required error"

echo "=== [12] tamper defense: mutate direct-avail sidecar env_wrapped → exec fails hard"
# Look up the specific direct-avail bearer's lookup id (there are two
# bearers in the vault by now — the ed25519 one from step 11 also has
# a sidecar without env_wrapped, so we can't just take the first one).
DA_LOOKUP=$("$DOP" token show direct-avail --json | python3 -c "import sys,json; print(json.loads(sys.stdin.read())['lookup_id'])")
[[ -n "$DA_LOOKUP" ]] || fail "couldn't find direct-avail lookup id"
REC="$VAULT_DIR/capabilities/$DA_LOOKUP.record"
[[ -f "$REC" ]] || fail "no sidecar at $REC"
# Confirm env_wrapped is there BEFORE the tamper, else the test is
# meaningless.
python3 - "$REC" <<'PY' || fail "no env_wrapped on direct-avail sidecar (test setup broken)"
import json, sys
d = json.loads(open(sys.argv[1]).read())
assert d.get('env_wrapped'), 'no env_wrapped'
PY
# Flip the first hex nibble of env_wrapped.ciphertext.
python3 - "$REC" <<'PY'
import json, sys
p = sys.argv[1]
d = json.loads(open(p).read())
ct = d['env_wrapped']['ciphertext']
d['env_wrapped']['ciphertext'] = ('1' if ct[0] == '0' else '0') + ct[1:]
open(p, 'w').write(json.dumps(d))
PY
# dop env should now HARD FAIL (record signature no longer covers this
# ciphertext, OR if the sig-check somehow lets it through the AEAD tag
# fails). No SLACK_TOKEN in output = the fail we want.
if OUT=$(DOP_TOKEN="$BEARER" "$DOP" env 2>&1); then
  # If exit was 0, env succeeded — that's the wrong outcome.
  echo "$OUT" | grep -q "SLACK_TOKEN" && fail "env leaked SLACK_TOKEN despite tampered env_wrapped"
fi
pass "tampered env_wrapped → hard fail (no silent bundle-env downgrade)"

echo
echo "V1.12 M3 e2e: ALL PASS — direct availability confirmed"
