#!/usr/bin/env bash
# Stage a throwaway dop install for demo recordings. Everything lives under
# DEMO_ROOT (default /tmp/dopdemo — short on purpose: the admin daemon's
# unix socket path must stay under ~100 chars). Nothing touches the repo
# or your real vault. Re-run freely: it starts from scratch every time.
set -euo pipefail
ROOT="${DEMO_ROOT:-/tmp/dopdemo}"
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
PASS="pass-word-long-enough"          # demo-only, shown typed in the TUI clip
APPROVE="$PASS-approve"

if [[ "${1:-}" == "--clean" ]]; then
  [[ -d "$ROOT" ]] && { HOME="$ROOT/home" "$ROOT/bin/dop" admin logout >/dev/null 2>&1 || true; rm -rf "$ROOT"; }
  echo "removed $ROOT"; exit 0
fi

if [[ -d "$ROOT" ]]; then
  HOME="$ROOT/home" "$ROOT/bin/dop" admin logout >/dev/null 2>&1 || true
  # keep work/ (record.sh's tape copies and frames), wipe everything else
  find "$ROOT" -mindepth 1 -maxdepth 1 ! -name work -exec rm -rf {} +
fi
mkdir -p "$ROOT/bin" "$ROOT/home" "$ROOT/work"

echo "building dop → $ROOT/bin/dop"
(cd "$REPO" && go build -o "$ROOT/bin/dop" ./cmd/dop)

run() { env -u DOP_HOME HOME="$ROOT/home" PATH="$ROOT/bin:$PATH" \
        DOP_NO_TUI=1 DOP_NO_NOTIFY=1 DOP_NO_KEYCHAIN=1 DOP_ALLOW_FILE_KEYS=1 DOP_NO_AUTO_PULL=1 "$@"; }

git init -q --bare -b main "$ROOT/bare"
printf "%s\n%s\n" "$PASS" "$APPROVE" | run dop admin init --passphrase-stdin >/dev/null
run dop init --vault "$ROOT/bare" >/dev/null
echo -n "$PASS" | run dop admin login --passphrase-stdin >/dev/null

VAULT="$ROOT/home/Library/Application Support/dop/vault"
[[ -d "$VAULT" ]] || VAULT="$ROOT/home/.config/dop/vault"   # linux layout
cat > "$VAULT/vault.yaml" <<'YAML'
schema_version: v1
integrations:
  notion:
    kind: api
    description: Notion workspace
    metadata: {base_url: "https://api.notion.com/v1"}
    tokens: {read: {value: "ntn_4f3a9c2e7b1d5a8f0c6e2b9d4a7f1c3e5b8d0a2f", scope_note: "read-only integration"}}
  youtube:
    kind: api
    description: YouTube Data API
    metadata: {base_url: "https://www.googleapis.com/youtube/v3"}
    tokens: {data: {value: "AIzaSyD3m0FakeYouTubeKey_0123456789abcd"}}
  linear:
    kind: api
    description: Linear GraphQL
    metadata: {base_url: "https://api.linear.app/graphql"}
    tokens: {api: {value: "lin_api_FAKE0123456789abcdef0123456789abcdef"}}
grants:
  notion.read: {integration: notion, token: read, env_prefix: NOTION, projects: [buzz], tags: [ro]}
  youtube.data: {integration: youtube, token: data, env_prefix: YT, projects: [buzz]}
  linear.api: {integration: linear, token: api, env_prefix: LINEAR, projects: [ops]}
YAML

# One claimed P-256 agent, resealed, so bearer-free exec works in the clips.
out=$(DOP_APPROVAL_PASSPHRASE="$APPROVE" run dop token issue --grants notion.read --name buzz-reader --expires 30d 2>&1)
bearer=$(grep -E '^tok_1' <<<"$out" | head -1); pin=$(grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' <<<"$out" | head -1)
DOP_TOKEN="$bearer" DOP_APPROVAL_PASSPHRASE="$APPROVE" run dop claim --skip-approval --key-type p256 "$pin" >/dev/null 2>&1
id=$(run dop token list 2>&1 | grep "status=active" | awk '{print $2}' | head -1)
run dop token reseal "$id" >/dev/null 2>&1
run dop exec --agent-name buzz-reader -- env 2>/dev/null | grep -q "NOTION_TOKEN=‹" \
  || { echo "stage: masked exec check failed" >&2; exit 1; }
echo "staged: vault with notion/youtube/linear, agent buzz-reader claimed, admin logged in"
echo "root:   $ROOT"
