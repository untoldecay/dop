#!/usr/bin/env bash
# Record the demo clips with VHS. Stages a fresh throwaway install first
# (scripts/demo/stage.sh), records each tape, checks the last frame
# exists, and copies mp4 + gif to OUT (default ~/Desktop).
#
#   scripts/demo/record.sh                 # all three clips
#   scripts/demo/record.sh exec tui        # a subset
#   OUT=/path scripts/demo/record.sh       # elsewhere than the Desktop
#
# Needs: vhs, ffmpeg, go. Outputs never land in the repo.
set -euo pipefail
ROOT="${DEMO_ROOT:-/tmp/dopdemo}"
OUT="${OUT:-$HOME/Desktop}"
HERE="$(cd "$(dirname "$0")" && pwd)"
TAPES=("$@"); [[ ${#TAPES[@]} -eq 0 ]] && TAPES=(exec proof tui)
command -v vhs >/dev/null || { echo "record: vhs not found (brew install vhs)" >&2; exit 2; }

"$HERE/stage.sh"
WORK="$ROOT/work"; mkdir -p "$WORK/frames"
theme=$(tr -d '\n' < "$HERE/theme-light.json")
for t in "$HERE"/tapes/*.tape; do
  sed -e "s|__ROOT__|$ROOT|g" -e "s|__THEME__|$theme|g" "$t" > "$WORK/$(basename "$t")"
done

dop_env() { env -u DOP_HOME -u DOP_TOKEN HOME="$ROOT/home" PATH="$ROOT/bin:$PATH" DOP_NO_TUI=1 "$@"; }
for name in "${TAPES[@]}"; do
  case "$name" in
    tui)   dop_env dop admin logout >/dev/null 2>&1 || true ;;   # clip starts locked
    proof) "$HERE/stage.sh" >/dev/null ;;                        # fresh agent + session
  esac
  echo "recording $name"
  (cd "$WORK" && env -u DOP_HOME -u DOP_NO_TUI -u DOP_TOKEN vhs "$name.tape" 2>&1 | grep -i "error" || true)
  mp4=$(grep -m1 '^Output .*\.mp4' "$WORK/$name.tape" | awk '{print $2}')
  gif="${mp4%.mp4}.gif"
  [[ -s "$WORK/$mp4" ]] || { echo "record: $mp4 missing" >&2; exit 1; }
  dur=$(ffprobe -v error -show_entries format=duration -of csv=p=0 "$WORK/$mp4")
  ffmpeg -v error -y -ss "$(python3 -c "print(max(0,float('$dur')-0.4))")" -i "$WORK/$mp4" -frames:v 1 "$WORK/frames/${mp4%.mp4}-end.png"
  cp "$WORK/$mp4" "$WORK/$gif" "$OUT/"
  printf "  %s  %ss  → %s/%s  (last frame: %s/frames/%s-end.png)\n" "$mp4" "${dur%.*}" "$OUT" "$mp4" "$WORK" "${mp4%.mp4}"
done
echo "done. cleanup: DEMO_ROOT=$ROOT $HERE/stage.sh --clean"
