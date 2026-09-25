#!/usr/bin/env bash
# P7 end-to-end: distribution artifacts
#   1. goreleaser config validates
#   2. install.sh syntax is clean
#   3. `goreleaser release --snapshot --skip=publish` produces the 4 archives
#      (macOS+Linux × amd64+arm64) with expected names and contents
#   4. Every archive contains the binary + README + docs/RECIPES.md + skill file

set -euo pipefail

pass() { echo "  ✓ $*"; }
fail() { echo "  ✗ $*" >&2; exit 1; }

require() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "P7 e2e: $1 not on PATH; skipping" >&2
        exit 77 # test-skip
    }
}

echo "=== [1] goreleaser check"
require goreleaser
goreleaser check --config .goreleaser.yaml 2>&1 | grep -q "validated" || fail "goreleaser check failed"
pass "config valid"

echo "=== [2] install.sh syntax"
bash -n scripts/install.sh || fail "install.sh has syntax errors"
# require that DOP_INSTALL_DIR and DOP_VERSION are honored (grep for env-var refs)
for var in DOP_INSTALL_DIR DOP_VERSION DOP_REPO; do
    grep -q "$var" scripts/install.sh || fail "install.sh doesn't reference $var"
done
pass "install.sh syntax + env overrides"

echo "=== [3] goreleaser snapshot builds all 4 platform archives"
rm -rf dist
goreleaser release --snapshot --clean --skip=publish 2>&1 > /tmp/goreleaser-p7.log || {
    tail -20 /tmp/goreleaser-p7.log >&2
    fail "goreleaser release --snapshot failed"
}
for platform in darwin_amd64 darwin_arm64 linux_amd64 linux_arm64; do
    archive="dist/dop_v0.0.0-next_${platform}.tar.gz"
    [[ -f "$archive" ]] || fail "missing archive: $archive"
done
pass "4 platform archives produced"

echo "=== [4] each archive contains binary + docs + skill"
for platform in darwin_amd64 darwin_arm64 linux_amd64 linux_arm64; do
    archive="dist/dop_v0.0.0-next_${platform}.tar.gz"
    contents=$(tar -tzf "$archive")
    for expected in "dop" "README.md" "docs/RECIPES.md" "skills/claude-code/SKILL.md"; do
        echo "$contents" | grep -q "^${expected}$" || fail "$archive missing $expected"
    done
done
pass "all archives include binary + docs + skill"

echo "=== [5] the binary in the archive runs on the current platform"
this_platform="$(uname | tr '[:upper:]' '[:lower:]')_$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')"
this_archive="dist/dop_v0.0.0-next_${this_platform}.tar.gz"
[[ -f "$this_archive" ]] || fail "no archive for current platform $this_platform"
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
tar -xzf "$this_archive" -C "$tmpdir"
"$tmpdir/dop" help 2>&1 | grep -q "Doors of Perception" || fail "extracted binary doesn't run"
pass "binary from archive runs and prints help"

echo ""
echo "P7 e2e: PASS"
