#!/usr/bin/env bash
# Render TUI screen dumps (.ans) to PNGs + one HTML gallery + the restylable TUI lab (<outdir>/lab/index.html).
# Usage: scripts/tui-screens.sh [outdir]   (default: $TMPDIR/dop-screens)
# Pipeline: go test TestWalkScreens -> .ans -> ansisvg (SVG, fixed cell grid) -> headless Chrome (PNG); .ans -> scripts/tui-lab.py (HTML lab).
# ponytail: freeze v0.2.2 takes --language ansi but drops bold and has no italic face, hence ansisvg+Chrome.
set -euo pipefail

OUT="${1:-${TMPDIR:-/tmp}/dop-screens}"
OUT="${OUT%/}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ANSISVG_VER=v0.5.0
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
CELL_W=9 CELL_H=18 FONT_SIZE=15 SCALE=2   # px per cell at 1x; PNG is SCALE x that
mkdir -p "$OUT/ans" "$OUT/png" "$OUT/svg"

# 1. dumps
if ls "$ROOT"/internal/tui/*_test.go >/dev/null 2>&1 && grep -qs 'func TestWalkScreens' "$ROOT"/internal/tui/*_test.go; then
  rm -f "$OUT"/ans/*.ans "$OUT/ans/index.txt"   # walk owns ans/: drop screens that no longer exist
  # ponytail: a failing walk only warns, so stale .ans still render while the test is being fixed
  (cd "$ROOT" && DOP_TUI_WALK="$OUT/ans" go test ./internal/tui -run TestWalkScreens -count=1 -v 2>&1) | tail -n 5 \
    || echo "warn: TestWalkScreens failed; rendering whatever is in $OUT/ans" >&2
else
  echo "note: TestWalkScreens not found in internal/tui; rendering existing $OUT/ans/*.ans" >&2
fi

# 2. tools
GOBIN="$(go env GOPATH)/bin"
ANSISVG="$GOBIN/ansisvg"
"$ANSISVG" --version 2>/dev/null | grep -q "${ANSISVG_VER#v}" || GOBIN="$GOBIN" go install "github.com/wader/ansisvg@$ANSISVG_VER"
[ -x "$CHROME" ] || { echo "need Google Chrome at \$CHROME ($CHROME)" >&2; exit 1; }

shopt -s nullglob
ANS=("$OUT"/ans/*.ans)
[ ${#ANS[@]} -gt 0 ] || { echo "no .ans files in $OUT/ans" >&2; exit 1; }
rm -f "$OUT"/png/*.png "$OUT"/svg/*.svg

render() { # $1 = .ans path
  local f="$1" base size cols rows svg
  base="$(basename "$f" .ans)"; size="${base##*-}"; cols="${size%x*}"; rows="${size#*x}"
  svg="$OUT/svg/$base.svg"
  # pad/clip to exactly $rows lines so every PNG is the full cols x rows box
  awk -v r="$rows" '{if(NR<=r)print} END{for(i=NR+1;i<=r;i++)print ""}' "$f" \
    | "$ANSISVG" --width "$cols" --grid --charboxsize "${CELL_W}x${CELL_H}" \
        --fontname Menlo --fontsize "$FONT_SIZE" --colorscheme "Builtin Dark" > "$svg"
  local prof log pid i; prof="$(mktemp -d)"; log="$prof/chrome.log"
  # ponytail: headless Chrome with a fresh profile writes the PNG then never exits; wait for its log line, then kill
  "$CHROME" --headless=new --disable-gpu --hide-scrollbars --user-data-dir="$prof" \
    --no-first-run --no-default-browser-check --disable-extensions --disable-background-networking \
    --force-device-scale-factor="$SCALE" --window-size="$((cols*CELL_W)),$((rows*CELL_H))" \
    --screenshot="$OUT/png/$base.png" "file://$svg" >"$log" 2>&1 & pid=$!
  for i in $(seq 300); do grep -q 'written to file' "$log" && break; kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null || true
  rm -rf "$prof"
  [ -s "$OUT/png/$base.png" ] || { echo "render failed: $base" >&2; return 1; }
}
export -f render; export OUT ANSISVG CHROME CELL_W CELL_H FONT_SIZE SCALE
# ponytail: one Chrome per screen (~2-6s each), 4 in parallel; one batched page if screen count explodes
printf '%s\0' "${ANS[@]}" | xargs -0 -n1 -P4 bash -c 'render "$0"' || echo "warn: some renders failed, gallery still built" >&2

# 3. gallery: group by <NN>-<slug>, sizes side by side
IDX="$OUT/ans/index.txt"; [ -f "$IDX" ] || : > "$IDX"
esc() { sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'; }
{
  echo '<!doctype html><meta charset="utf-8"><title>dop TUI screens</title>'
  echo '<body style="background:#111;color:#ddd;font:14px -apple-system,sans-serif;margin:16px">'
  echo "<h1 style=\"font-size:18px\">dop TUI screens <small style=\"color:#888\">$(date '+%Y-%m-%d %H:%M')</small></h1>"
  for grp in $(for f in "${ANS[@]}"; do b="$(basename "$f" .ans)"; echo "${b%-*}"; done | sort -u); do
    title="$(awk -F'\t' -v g="$grp" 'index($1,g"-")==1{print $2; exit}' "$IDX" | esc)"
    echo "<section style=\"margin:0 0 32px\"><h2 style=\"font-size:15px;margin:0 0 4px\">${title:-$grp} <code style=\"color:#888\">$grp</code></h2>"
    echo '<div style="display:flex;flex-wrap:wrap;gap:12px;align-items:flex-start">'
    for f in "$OUT"/ans/"$grp"-*.ans; do
      name="$(basename "$f")"; base="${name%.ans}"; size="${base##*-}"
      keys="$(awk -F'\t' -v n="$name" '$1==n{print $3; exit}' "$IDX" | esc)"
      echo "<figure style=\"margin:0;max-width:100%\"><img src=\"png/$base.png\" alt=\"$base\" style=\"max-width:100%;width:$(( ${size%x*} * CELL_W ))px;display:block\" loading=\"lazy\">"
      echo "<figcaption style=\"color:#999;font-size:12px\">$size · keys: <code>${keys:--}</code></figcaption></figure>"
    done
    echo '</div></section>'
  done
} > "$OUT/index.html"
python3 "$ROOT/scripts/tui-lab.py" "$OUT"

echo "$OUT"
echo "screens: $(ls "$OUT"/png/*.png | wc -l | tr -d ' ') png from ${#ANS[@]} ans, $(ls "$OUT"/ans/*.ans | sed -E 's/-[0-9]+x[0-9]+\.ans$//' | sort -u | wc -l | tr -d ' ') groups -> $OUT/index.html"
