#!/usr/bin/env bash
# Agent host (no admin key) whose vault clone diverged from the team's
# (2026-11-21): a remote claim committed on an old branch, its push was
# refused, and `dop pull` then asked for an admin key to merge.
#   [1] a diverged agent host: `dop pull` combines without the admin key
#   [2] the admin pushes between the agent's pull and push: the claim's
#       push is refused, dop pulls and pushes again
#   [3] the agent host changed vault.yaml: pull refuses, points to --keep-team

set -euo pipefail

DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "no dop"; exit 2; }
pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

WORKROOT=$(mktemp -d /tmp/dop-v1ahm-XXXX)
trap 'rm -rf "$WORKROOT"' EXIT
A="$WORKROOT/a"
B="$WORKROOT/b"
mkdir -p "$A" "$B"
BARE="$WORKROOT/bare"
PASS="the-passphrase-15chars"
export DOP_APPROVAL_PASSPHRASE="$PASS-approve" DOP_NO_TUI=1 DOP_NO_KEYCHAIN=1 DOP_ALLOW_FILE_KEYS=1
VA="$A/Library/Application Support/dop/vault"
VB="$B/Library/Application Support/dop/vault"
a() { HOME="$A" "$DOP" "$@"; }
b() { HOME="$B" "$DOP" "$@"; }
issue() { a token issue --grants notion.read --name "$1" 2>&1; }

echo "=== [0] admin A seeds the vault; agent host B clones it"
printf "%s\n%s\n" "$PASS" "$PASS-approve" | a admin init --passphrase-stdin >/dev/null
a init --vault "$BARE" >/dev/null 2>&1
echo -n "$PASS" | a admin login --passphrase-stdin >/dev/null
cat > "$VA/vault.yaml" <<'EOF'
schema_version: v1
integrations:
  notion: {metadata: {}, tokens: {read: {value: "ntn_val"}}}
grants:
  notion.read: {integration: notion, token: read, env_prefix: NOTION}
EOF
issue seed >/dev/null
a push >/dev/null 2>&1 || true
b init --cache "$BARE" >/dev/null 2>&1
[[ ! -f "$B/Library/Application Support/dop/keys/admin.age.enc" ]] || fail "B must not hold the admin key"
pass "A admin, B agent host"

echo "=== [1] B has an unpushed commit, A pushed meanwhile: dop pull on B combines both"
mkdir -p "$VB/agent-rules"
echo '{"host":"b"}' > "$VB/agent-rules/b-local.json"
git -C "$VB" -c user.email=e2e@test -c user.name=e2e add -A >/dev/null
git -C "$VB" -c user.email=e2e@test -c user.name=e2e commit -qm "b: local file"
issue second >/dev/null
a push >/dev/null 2>&1 || true
set +e
OUT=$(DOP_NO_AUTO_PULL=1 b pull 2>&1); rc=$?
set -e
(( rc == 0 )) || fail "pull on a diverged agent host failed: $OUT"
echo "$OUT" | grep -q "admin key" && fail "pull still asks for an admin key: $OUT"
[[ -f "$VB/agent-rules/b-local.json" ]] || fail "B's own file was lost"
git -C "$VB" log --oneline | grep -q "b: local file" && fail "expected B's change replayed on the team's tree, not its old commit"
git -C "$VB" merge-base --is-ancestor origin/main HEAD || fail "B is not on top of the team's vault"
b push >/dev/null 2>&1 || fail "push after the combine failed"
a pull >/dev/null 2>&1 || true
[[ -f "$VA/agent-rules/b-local.json" ]] || fail "A doesn't see B's file after push + pull"
pass "diverged agent host: pulled without the admin key, its file kept and shared"

echo "=== [2] A pushes between B's pull and B's claim push: the claim still lands"
OUT=$(issue racer)
BEARER=$(echo "$OUT" | grep -E '^tok_1' | head -1)
PIN=$(echo "$OUT" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
a push >/dev/null 2>&1 || true
b pull >/dev/null 2>&1 || true # B has the racer bearer
issue late >/dev/null           # ...then the team moves on
a push >/dev/null 2>&1 || true
set +e
OUT=$(DOP_NO_AUTO_PULL=1 DOP_TOKEN="$BEARER" b claim --remote --key-type p256 "$PIN" 2>&1); rc=$?
set -e
(( rc == 0 )) || fail "remote claim failed: $OUT"
echo "$OUT" | grep -q "git push failed" && fail "claim push was not retried: $OUT"
echo "$OUT" | grep -q "pushed to vault repo" || fail "claim did not report a push: $OUT"
a pull >/dev/null 2>&1 || true
ls "$VA/pending-remote-claims/"*.json >/dev/null 2>&1 || fail "A doesn't see the staged claim"
pass "refused push → pull → push again; the admin sees the claim"

echo "=== [3] B changed vault.yaml: pull refuses and points to --keep-team"
echo "# local edit" >> "$VB/vault.yaml"
git -C "$VB" -c user.email=e2e@test -c user.name=e2e commit -qam "b: vault.yaml edit"
issue third >/dev/null
a push >/dev/null 2>&1 || true
set +e
OUT=$(DOP_NO_AUTO_PULL=1 b pull 2>&1); rc=$?
set -e
(( rc != 0 )) || fail "pull should refuse when B changed vault.yaml"
echo "$OUT" | grep -q "vault.yaml" || fail "refusal doesn't name vault.yaml: $OUT"
echo "$OUT" | grep -q -- "--keep-team" || fail "refusal doesn't offer --keep-team: $OUT"
b pull --keep-team >/dev/null 2>&1 || fail "--keep-team failed"
pass "vault.yaml changed here → refused, --keep-team recovers"

echo
echo "V1 agent-host merge e2e: ALL PASS"
