#!/usr/bin/env bash
# Re-records README GIFs from a fresh demo install (contract 26).
#
#   docs/media/record.sh            # every docs/media/*.tape
#   docs/media/record.sh issue      # just issue.tape
#
# Run from anywhere; needs dop ≥ v1.17 and vhs on PATH.
# Guide: _rules/_requirements/vhs_recording_guide.md

set -euo pipefail
cd "$(dirname "$0")/../.."

tapes=("$@")
if [[ ${#tapes[@]} -eq 0 ]]; then
	for t in docs/media/*.tape; do tapes+=("$(basename "$t" .tape)"); done
fi

mkdir -p docs/media/out
for name in "${tapes[@]}"; do
	echo "── $name"
	docs/media/setup-demo.sh >/dev/null   # every tape starts from the same data
	vhs "docs/media/$name.tape" >/dev/null
	echo "   docs/media/out/$name.gif ($(du -h "docs/media/out/$name.gif" | cut -f1))"
done
docs/media/setup-demo.sh --clean >/dev/null
