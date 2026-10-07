#!/usr/bin/env bash
# Builds a throwaway DOP install with fake data for the README GIF tapes
# (contract 26). Runs the real `dop` under DOP_HOME — never touches your
# default install and never points at a real vault remote.
#
#   docs/media/setup-demo.sh            # build /tmp/dop-demo
#   DOP_BIN=./dop docs/media/setup-demo.sh
#   docs/media/setup-demo.sh --clean    # stop its session + delete it
#
# Then record: docs/media/record.sh  (resets + records every tape)

set -euo pipefail

DOP="${DOP_BIN:-dop}"
DEMO="${DEMO_HOME:-/tmp/dop-demo}"   # keep short: admin.sock lives inside
REMOTE="$DEMO-remote.git"
PASS="demo-pass-long-enough"
APPROVE="demo-approve-passphrase"

export DOP_HOME="$DEMO" DOP_NO_TUI=1 DOP_NO_NOTIFY=1
export DOP_APPROVAL_PASSPHRASE="$APPROVE"

clean() {
	"$DOP" admin logout >/dev/null 2>&1 || true
	rm -rf "$DEMO" "$REMOTE"
}

if [[ "${1:-}" == "--clean" ]]; then
	clean
	echo "removed $DEMO"
	exit 0
fi

clean

# Own local bare remote — `-b main`: auto-merge assumes origin/main.
git init -q --bare -b main "$REMOTE"

printf "%s\n%s\n" "$PASS" "$APPROVE" | "$DOP" admin init --passphrase-stdin >/dev/null 2>&1
"$DOP" init --vault "$REMOTE" >/dev/null 2>&1
echo -n "$PASS" | "$DOP" admin login --passphrase-stdin >/dev/null 2>&1

# Vault "acme": three services, fake keys (the TUI probe is opt-in).
"$DOP" integration add --name notion --description "Team wiki and docs" \
	--base-url https://api.notion.com/v1 \
	--token "read=ntn_demo_read_0000" --token "write=ntn_demo_write_0000" >/dev/null 2>&1
"$DOP" integration add --name linear --description "Issue tracker" \
	--base-url https://api.linear.app \
	--token "read=lin_api_demo_read_0000" >/dev/null 2>&1
"$DOP" integration add --name github --description "Code and CI" \
	--base-url https://api.github.com \
	--token "read=ghp_demo_read_0000" --token "write=ghp_demo_write_0000" >/dev/null 2>&1

"$DOP" grant add --id notion.read --integration notion --token read --env-prefix NOTION --tags read >/dev/null 2>&1
"$DOP" grant add --id notion.write --integration notion --token write --env-prefix NOTION_RW --tags write >/dev/null 2>&1
"$DOP" grant add --id linear.read --integration linear --token read --env-prefix LINEAR --tags read >/dev/null 2>&1
"$DOP" grant add --id github.read --integration github --token read --env-prefix GITHUB --tags read >/dev/null 2>&1
"$DOP" grant add --id github.write --integration github --token write --env-prefix GITHUB_RW --tags write >/dev/null 2>&1

# A few bearers so List › Bearers isn't empty.
"$DOP" token issue --no-bind --name deploy-agent --grants github.read,github.write --expires 30d >/dev/null 2>&1
"$DOP" token issue --no-bind --name triage-bot --grants linear.read --expires 7d >/dev/null 2>&1

echo "demo install ready: DOP_HOME=$DEMO (remote $REMOTE)"
echo "  try it:  DOP_HOME=$DEMO dop"
echo "  record:  docs/media/record.sh issue   (or vhs docs/media/<name>.tape)"
echo "  remove:  docs/media/setup-demo.sh --clean"
