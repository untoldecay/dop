#!/usr/bin/env bash
# V1.18.2 e2e: dop exec behind its pty proxy stays usable interactively —
# window size, typed input, ctrl+c, ctrl+z / fg, masking, terminal restored —
# driven through a real interactive bash by expect (terminal_interactive.exp).
set -euo pipefail
DOP="${DOP_BIN:-$(pwd)/dop}"
[[ -x "$DOP" ]] || { echo "V1.18.2 terminal interactive: no dop at $DOP" >&2; exit 2; }
command -v python3 >/dev/null || { echo "V1.18.2 terminal interactive: needs python3" >&2; exit 2; }
HERE="$(cd "$(dirname "$0")" && pwd)"
WORKROOT=$(mktemp -d /tmp/dop-v1820-XXXX)
export DOP_HOME="$WORKROOT/home" DOP_NO_TUI=1 DOP_NO_NOTIFY=1 DOP_NO_KEYCHAIN=1 DOP_ALLOW_FILE_KEYS=1
cleanup() { "$DOP" admin logout >/dev/null 2>&1 || true; rm -rf "$WORKROOT"; }
trap cleanup EXIT
SECRET="ntn_FAKE_LEAKTEST_0123456789abcdef"
PASS="pass-word-long-enough"

git init -q --bare -b main "$WORKROOT/bare"
printf "%s\n%s\n" "$PASS" "$PASS-approve" | "$DOP" admin init --passphrase-stdin >/dev/null 2>&1
"$DOP" init --vault "$WORKROOT/bare" >/dev/null 2>&1
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null 2>&1
cat > "$DOP_HOME/vault/vault.yaml" <<YAML
schema_version: v1
integrations:
  notion:
    tokens: {read: {value: "$SECRET"}}
grants:
  notion.read: {integration: notion, token: read, env_prefix: NOTION}
YAML
out=$(DOP_APPROVAL_PASSPHRASE="$PASS-approve" "$DOP" token issue --grants notion.read --name honey 2>&1)
BEARER=$(echo "$out" | grep -E '^tok_1' | head -1)
PIN=$(echo "$out" | grep -E '^[A-Z]{2}-[A-Z]{2}-[A-Z]{2}$' | head -1)
DOP_TOKEN="$BEARER" DOP_APPROVAL_PASSPHRASE="$PASS-approve" "$DOP" claim --skip-approval --key-type p256 "$PIN" >/dev/null 2>&1
"$DOP" token reseal honey >/dev/null 2>&1

command -v expect >/dev/null || { echo "V1.18.2 terminal interactive: needs expect" >&2; exit 2; }
set +e
out=$(DOP_TOKEN="$BEARER" expect "$HERE/terminal_interactive.exp" "$DOP" 2>&1)
rc=$?
set -e
echo "$out" | tr -d '\r' | grep -aE "^(OK|FAIL):|PASS"
exit $rc
