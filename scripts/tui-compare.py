#!/usr/bin/env python3
"""Before/after page for TUI screen dumps.
Usage: scripts/tui-compare.py <before-outdir> <after-outdir> [--changed]   writes <after-outdir>/compare/index.html
--changed: skip screens missing from <after> (for partial mock sets).
Lists screens (by slug) whose 80x24 dump changed, was added or removed; renders both with tui-lab's converter.
"""
import html, os, re, sys
sys.path.insert(0, os.path.dirname(__file__))
import importlib
lab = importlib.import_module('tui-lab')  # ponytail: reuse convert() + CSS instead of a second ANSI parser

def load(out):
    d = os.path.join(out, 'ans'); meta = {}
    for row in open(os.path.join(d, 'index.txt'), encoding='utf-8'):
        f = row.rstrip('\n').split('\t')
        if len(f) >= 2 and f[0].endswith('-80x24.ans'):
            slug = re.sub(r'^\d+-', '', f[0][:-10])
            meta[slug] = (f[1], open(os.path.join(d, f[0]), encoding='utf-8').read())
    return meta

def main():
    only = '--changed' in sys.argv; args = [a for a in sys.argv[1:] if a != '--changed']
    if len(args) != 2: sys.exit(__doc__)
    sys.argv = [sys.argv[0]] + args
    before, after = load(args[0]), load(args[1])
    rows = []
    for slug in sorted(set(before) | set(after)):
        b, a = before.get(slug), after.get(slug)
        if b and a and b[1] == a[1]: continue
        if only and not a: continue
        state = 'changed' if b and a else ('added' if a else 'removed')
        title = (a or b)[0]
        pre = lambda t: f'<div class="wrap"><pre class="screen">\n{lab.convert(t, 24)}</pre></div>' if t else '<div class="none">—</div>'
        rows.append(f'<section><h2>{html.escape(slug)} <small>{state} · {html.escape(title)}</small></h2>'
                    f'<div class="pair">{pre(b and b[1])}{pre(a and a[1])}</div></section>')
    css = lab.CSS + '\nsection{width:auto}.pair{display:flex;gap:16px;flex-wrap:nowrap;overflow-x:auto}.none{flex:none;width:calc(80*1ch);color:#555;font:15px Menlo,monospace}.pair .wrap{flex:none}' \
          'h2 small{color:#888;font-weight:normal}h1{font-size:16px;padding:12px 16px;margin:0;background:#22242a}'
    out = os.path.join(sys.argv[2], 'compare'); os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, 'index.html'), 'w', encoding='utf-8') as fh:
        fh.write(f'<!doctype html><meta charset="utf-8"><title>dop TUI before/after</title><style>{css}</style>'
                 f'<h1>before → after · {len(rows)} screens differ</h1><main style="flex-direction:column">{"".join(rows)}</main>\n')
    print(f'{out}/index.html ({len(rows)} screens differ)')

if __name__ == '__main__':
    main()
