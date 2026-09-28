#!/usr/bin/env bash
# Run every test in the project: Go unit + shell e2e.
# Exit non-zero if any fail. Intended as the "before I ship" gate.
#
# Usage:
#   ./scripts/test.sh              run everything
#   ./scripts/test.sh --unit-only  Go unit tests only (fast, no external deps)
#   ./scripts/test.sh --e2e-only   shell e2e tests only (needs sops, git, age-keygen, gh, goreleaser)
#
# Runtime deps for full run:
#   go, sops, git, age-keygen, gh, goreleaser, python3

set -euo pipefail

# CD into the dop root regardless of where the script was called from.
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DOP_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
cd "$DOP_ROOT"

MODE=${1:-all}
FAIL=0
START=$(date +%s)

green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
gray()  { printf '\033[90m%s\033[0m\n' "$*"; }

run_unit() {
    echo ""
    echo "════════════════════════════════════════════════"
    echo "  Go unit tests"
    echo "════════════════════════════════════════════════"
    if go test -count=1 ./... ; then
        green "  ✓ unit tests pass"
    else
        red "  ✗ unit tests failed"
        FAIL=1
    fi
}

run_e2e() {
    echo ""
    echo "════════════════════════════════════════════════"
    echo "  E2E tests (testdata/e2e/*.sh)"
    echo "════════════════════════════════════════════════"

    # E2E tests need the compiled binary.
    gray "  building dop binary..."
    go build -o dop ./cmd/dop
    trap 'rm -f dop' EXIT

    local passed=0
    local failed=0
    local names_failed=()

    # Order matters for readability, not correctness. Sort ensures p1b < p2 < ... < p10.
    for t in $(ls testdata/e2e/p*.sh | sort); do
        name=$(basename "$t")
        # p10_first_run.sh runs the whole regression suite itself — skip in
        # normal runs to avoid double-work. Include it via --with-p10 if wanted.
        if [[ "$name" == "p10_first_run.sh" && "${WITH_P10:-0}" != "1" ]]; then
            gray "  ⋯ $name (skipped; set WITH_P10=1 to include)"
            continue
        fi
        logf=$(mktemp)
        if DOP_NO_TUI=1 DOP_BIN="$DOP_ROOT/dop" bash "$t" > "$logf" 2>&1; then
            green "  ✓ $name"
            passed=$((passed + 1))
        else
            red "  ✗ $name"
            names_failed+=("$name")
            tail -8 "$logf" | sed 's/^/      /'
            failed=$((failed + 1))
            FAIL=1
        fi
        rm -f "$logf"
    done

    echo ""
    echo "  E2E summary: $passed passed, $failed failed"
    if [[ $failed -gt 0 ]]; then
        red "  failing: ${names_failed[*]}"
    fi
}

case "$MODE" in
    --unit-only) run_unit ;;
    --e2e-only)  run_e2e ;;
    all|--all|"") run_unit; run_e2e ;;
    -h|--help)
        sed -n 's/^# //p' "$0" | sed 's/^!.*//'
        exit 0
        ;;
    *)
        red "unknown mode: $MODE"
        echo "usage: $0 [--unit-only | --e2e-only | --all]"
        exit 2
        ;;
esac

END=$(date +%s)
DUR=$((END - START))

echo ""
if [[ $FAIL -eq 0 ]]; then
    green "════════════════════════════════════════════════"
    green "  ALL TESTS PASS  (${DUR}s)"
    green "════════════════════════════════════════════════"
else
    red "════════════════════════════════════════════════"
    red "  TESTS FAILED  (${DUR}s)"
    red "════════════════════════════════════════════════"
fi

exit $FAIL
