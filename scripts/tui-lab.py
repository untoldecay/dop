#!/usr/bin/env python3
"""TUI lab: cell-accurate, restylable HTML copy of the TUI screen dumps.
Usage: scripts/tui-lab.py <outdir>   reads <outdir>/ans/*-80x24.ans + index.txt, writes <outdir>/lab/index.html
Modes: grid (all screens, filtered by set) and single (one screen in a fake terminal, navigate with the TUI's own keys).
Sets come from index.txt column 4 tags: `key`, `flow:<name>`, `edge`; without tags the built-in KEY list marks key screens.
"""
import html, json, os, re, sys

PALETTE = {'brand': '#f5c93a', 'muted': '#6d7280', 'ok': '#10b981', 'danger': '#ef4444'}  # internal/tui/tui.go
# ponytail: extra hexes that map to the same class, so mock/theme dumps stay restylable (distill theme A and B)
ALIASES = {'muted': ['#858279', '#7d838e', '#404040'], 'ok': ['#93b98a', '#8fbfa0'], 'danger': ['#d98074', '#d8858a'], 'brand': ['#8db4cf', '#c2c4cc'], 'fg': ['#c8c6bf', '#c6cad1', '#5c5c5c']}
THEMES = {'current': {'fg': '#bbbbbb', 'bg': '#000000', 'brand': '#f5c93a', 'muted': '#6d7280', 'ok': '#10b981', 'danger': '#ef4444'},
          'A calm yellow': {'fg': '#c8c6bf', 'bg': '#161614', 'brand': '#f5c93a', 'muted': '#858279', 'ok': '#93b98a', 'danger': '#d98074'},
          'B calm blue': {'fg': '#c6cad1', 'bg': '#15171b', 'brand': '#8db4cf', 'muted': '#7d838e', 'ok': '#8fbfa0', 'danger': '#d8858a'},
          'C mono (chosen)': {'fg': '#5c5c5c', 'bg': '#000000', 'brand': '#c2c4cc', 'muted': '#404040', 'ok': '#10b981', 'danger': '#ef4444'}}
DEFAULTS = {'fg': '#bbbbbb', 'bg': '#000000', **PALETTE}  # fg/bg = ansisvg "Builtin Dark", matches the PNG gallery
KEY = ['01-menu-nokey', '13-menu-locked', '17-menu-admin', '18-menu-add-open', '29-menu-admin-flash',
       '20-integration-add-name', '21-integration-add-kind', '26-integration-add-save', '27-integration-add-error',
       '28-integration-add-done', '41-issue-grants', '45-issue-done', '47-integration-list', '48-integration-detail',
       '50-integration-token-actions', '55-integration-remove-confirm', '61-bearer-list', '64-bearer-detail',
       '82-vault-status', '87-settings', '11-doctor-nokey', '36-invite-waiting']
SGR = re.compile(r'\x1b\[([0-9;]*)m')
unknown = set()

def token(rgb):
    hexc = '#%02x%02x%02x' % rgb
    for name, hexes in ((n, [h] + ALIASES.get(n, [])) for n, h in list(PALETTE.items()) + [('fg', '#bbbbbb')]):
        for h in hexes:
            p = (int(h[1:3], 16), int(h[3:5], 16), int(h[5:], 16))
            # ponytail: +-2 per channel, termenv emits #6d7280 as 109;113;128; exact match would miss muted
            if all(abs(a - b) <= 2 for a, b in zip(rgb, p)):
                return (None if name == 'fg' else name), None
    unknown.add(hexc)
    return None, hexc

def squash(toks):
    """a space press is recorded as a " " token joined by " " separators → two empty strings; keep one per press"""
    out, run = [], 0
    for t in toks + [None]:
        if t == '': run += 1; continue
        out += [''] * (run // 2); run = 0
        if t is not None: out.append(t)
    return out

def convert(text, rows):
    lines = (text.split('\n') + [''] * rows)[:rows]
    out, st = [], {'fg': None, 'hex': None, 'bg': None, 'b': 0, 'i': 0, 'u': 0}
    for ln in lines:
        buf = []
        for k, part in enumerate(SGR.split(ln)):
            if k % 2:  # SGR params
                ps = [int(p) if p else 0 for p in part.split(';')] or [0]
                j = 0
                while j < len(ps):
                    p = ps[j]
                    if p == 0: st = {'fg': None, 'hex': None, 'bg': None, 'b': 0, 'i': 0, 'u': 0}
                    elif p == 1: st['b'] = 1
                    elif p == 3: st['i'] = 1
                    elif p == 4: st['u'] = 1
                    elif p == 22: st['b'] = 0
                    elif p == 23: st['i'] = 0
                    elif p == 24: st['u'] = 0
                    elif p == 39: st['fg'] = st['hex'] = None
                    elif p == 49: st['bg'] = None
                    elif p in (38, 48) and ps[j + 1:j + 2] == [2]:
                        rgb = tuple(ps[j + 2:j + 5]); j += 4
                        if p == 38: st['fg'], st['hex'] = token(rgb)
                        else: st['bg'] = '#%02x%02x%02x' % rgb
                    # ponytail: 16/256-colour SGR ignored, the TUI only emits truecolor
                    j += 1
                continue
            if not part: continue
            t = html.escape(part.replace('\t', '    '), quote=False)
            cls = [c for c in (st['fg'], 'b' * st['b'], 'i' * st['i'], 'u' * st['u']) if c]
            style = (f'color:{st["hex"]};' if st['hex'] else '') + (f'--bgc:{st["bg"]};' if st['bg'] else '')
            if st['bg']: cls.append('bg')
            if not cls and not style: buf.append(t); continue
            attrs = (f' class="{" ".join(cls)}"' if cls else '') + (f' data-color="{st["hex"]}"' if st['hex'] else '') \
                + (f' style="{style}"' if style else '')
            buf.append(f'<span{attrs}>{t}</span>')
        out.append(''.join(buf))
    return '\n'.join(out)

CSS = """
:root{--fg:#bbbbbb;--bg:#000000;--brand:#f5c93a;--muted:#6d7280;--ok:#10b981;--danger:#ef4444;--fs:15px;--lh:18px;--cols:80;--rows:24}
body{margin:0;background:#16171b;color:#c9ccd3;font:13px -apple-system,system-ui,sans-serif}
#dials{position:sticky;top:0;z-index:2;background:#22242a;border-bottom:1px solid #333;padding:10px 16px;display:flex;flex-wrap:wrap;gap:8px 16px;align-items:center}
#dials label{display:flex;gap:4px;align-items:center}#dials input[type=number]{width:56px}
#dials textarea{width:340px;height:52px;font:11px Menlo,monospace}
main{display:flex;flex-wrap:wrap;gap:24px;padding:24px 16px;align-items:flex-start}
section{width:min-content;max-width:100%}.kp{overflow-wrap:anywhere}section h2{font-size:13px;margin:0 0 2px}
.kp,.ruler{font:11px Menlo,monospace;color:#888;margin:0 0 6px}.ruler{float:right}
section a{color:#888;font-size:11px;cursor:pointer}
.wrap{position:relative;width:calc(var(--cols)*1ch);font:var(--fs)/var(--lh) Menlo,"SF Mono",Monaco,"DejaVu Sans Mono",monospace;overflow:hidden}
.screen{display:block;margin:0;padding:0;border:0;outline:0;font:inherit;letter-spacing:0;font-variant-ligatures:none;white-space:pre;overflow:hidden;
 width:calc(var(--cols)*1ch);height:calc(var(--rows)*var(--lh));color:var(--fg);background:var(--bg);tab-size:4}
.brand{color:var(--brand)}.muted{color:var(--muted)}.ok{color:var(--ok)}.danger{color:var(--danger)}
.b{font-weight:bold}.i{font-style:italic}.u{text-decoration:underline}.bg{background:var(--bgc)}
.nobold .b{font-weight:normal}.noital .i{font-style:normal}
.guide{position:absolute;top:0;bottom:0;left:calc(80*1ch);width:1px;background:#4af6;pointer-events:none}.noguide .guide{display:none}
.over{position:absolute;right:var(--pr,0);width:3px;height:var(--lh);background:#f33;pointer-events:none}
.bar,#nav{display:none}section.out{display:none}
.single main{justify-content:center;align-items:center;min-height:calc(100vh - 140px)}.single section:not(.cur){display:none}
.single section.cur{background:#2b2d33;border-radius:10px;padding:0 0 10px;box-shadow:0 24px 60px #000a;width:auto}
.single section.cur .ruler,.single section.cur h2,.single section.cur .kp{display:none}
.single .bar{display:flex;gap:8px;align-items:center;padding:10px 12px;font:12px -apple-system,system-ui,sans-serif;color:#999}
.bar i{width:12px;height:12px;border-radius:50%;background:#ff5f57}.bar i+i{background:#febc2e}.bar i+i+i{background:#28c840;margin-right:8px}
.single section.cur .wrap{--pt:var(--lh);--pr:2ch;margin:0 10px;padding:var(--lh) 2ch;background:var(--bg);width:auto}.single section.cur .guide{left:calc(82*1ch)}
.single #nav{display:block;position:fixed;left:0;right:0;bottom:0;padding:10px 16px;background:#22242a;border-top:1px solid #333;font:12px Menlo,monospace;color:#999;z-index:2}
#nav b{color:#ddd;font-weight:normal}#nav kbd{color:#f5c93a}
"""

JS = r"""
const D=__DEFAULTS__, T=__THEMES__, R=document.documentElement, $=s=>document.querySelector(s);
const colours=['fg','bg','brand','muted','ok','danger'];
const BASE={fs:15,lh:1.2,cols:80,rows:24,bold:true,ital:true,guide:true,over:false,mode:'grid',set:'key',edit:false,cur:0};
let S={...D,...BASE};
try{Object.assign(S,JSON.parse(localStorage.getItem('tuilab')||'{}'))}catch(e){}
function apply(){
  colours.forEach(k=>R.style.setProperty('--'+k,S[k]));
  R.style.setProperty('--fs',S.fs+'px');R.style.setProperty('--lh',(S.fs*S.lh).toFixed(2)+'px');
  R.style.setProperty('--cols',S.cols);R.style.setProperty('--rows',S.rows);
  R.classList.toggle('nobold',!S.bold);R.classList.toggle('noital',!S.ital);R.classList.toggle('noguide',!S.guide);
  document.querySelectorAll('.ruler').forEach(e=>e.textContent=S.cols+'×'+S.rows);
  for(const el of document.querySelectorAll('[data-k]')){const v=S[el.dataset.k];el.type=='checkbox'?el.checked=v:el.value=v}
  $('#tokens').value=':root{\n'+colours.map(k=>`  --${k}: ${S[k]};`).join('\n')+`\n  --fs: ${S.fs}px;\n  --lh: ${(S.fs*S.lh).toFixed(2)}px;\n}`;
  R.classList.toggle('single',S.mode=='single');
  const IN=SECS.map(sec=>S.set=='all'||(' '+sec.dataset.tags+' ').includes(' '+S.set+' '));
  SECS.forEach((sec,i)=>sec.classList.toggle('out',S.mode=='grid'&&!IN[i]));
  document.querySelectorAll('.screen').forEach(p=>p.setAttribute('contenteditable',S.edit?'plaintext-only':'false'));
  SECS.forEach((sec,i)=>sec.classList.toggle('cur',i==S.cur));
  if(S.mode=='single'){location.hash=SECS[S.cur].id;nav()}
  overflow();try{localStorage.setItem('tuilab',JSON.stringify(S))}catch(e){}
}
// --- single-mode navigation: replay the walk's recorded key paths ---
const SECS=[...document.querySelectorAll('section')];
const KEYS=SECS.map(s=>JSON.parse(s.dataset.keys));          // tokens, quoted text + direct:* already dropped
const norm={Enter:'enter',Escape:'esc',ArrowDown:'down',ArrowUp:'up',ArrowLeft:'left',ArrowRight:'right',Tab:'tab',Backspace:'backspace',' ':''};
const eq=(a,b)=>a.length==b.length&&a.every((t,i)=>t==b[i]), pre=(a,b)=>a.length<b.length&&a.every((t,i)=>t==b[i]);
function pick(list){if(!list.length)return -1;const after=list.find(i=>i>S.cur);return after??list[0]}
function resolve(seq){                                   // screen index reached by replaying seq from the current screen, or -1
  const c=KEYS[S.cur], want=[...c,...seq], k=seq[seq.length-1];
  let i=pick(KEYS.flatMap((t,i)=>eq(t,want)?[i]:[]));
  // ponytail: no exact screen for this key → jump to the shortest screen that continues from it (auto-plays the in-between keys)
  if(i<0){const ext=KEYS.flatMap((t,i)=>pre(want,t)?[i]:[]).sort((a,b)=>KEYS[a].length-KEYS[b].length);i=ext.length?pick(ext.filter(j=>KEYS[j].length==KEYS[ext[0]].length)):-1}
  // ponytail: branches were recorded from launch, so a main-line screen may have a shorter path than the detour taken to
  // reach it; fall back to the screen sharing the longest key suffix with what was just pressed (at least 4 keys)
  if(i<0&&k!='esc'){const suf=(a,b)=>{let n=0;while(n<a.length&&n<b.length&&a[a.length-1-n]==b[b.length-1-n])n++;return n};
    const fl=(SECS[S.cur].dataset.tags.match(/flow:\S+/)||[''])[0]; let best=4,cand=[];
    if(fl)KEYS.forEach((t,j)=>{if(j==S.cur||!SECS[j].dataset.tags.includes(fl))return;const n=suf(t,want);if(n>best){best=n;cand=[j]}else if(n==best)cand.push(j)});
    i=pick(cand)}
  if(i<0&&k=='esc'){const par=KEYS.flatMap((t,i)=>pre(t,c)?[i]:[]).filter(i=>i<S.cur);i=par.length?par[par.length-1]:S.cur}
  return i;
}
function go(...seqs){                                    // first sequence that leads somewhere wins
  if(seqs[0][0]=='\x00next'||seqs[0][0]=='\x00prev'){const d=seqs[0][0]=='\x00next'?1:-1,inset=i=>S.set=='all'||(' '+SECS[i].dataset.tags+' ').includes(' '+S.set+' ');
    let i=S.cur+d;while(i>=0&&i<SECS.length&&!inset(i))i+=d; if(i>=0&&i<SECS.length){S.cur=i;CUR={};apply()}return}
  for(const seq of seqs){const i=resolve(seq);if(i>=0&&i<SECS.length){S.cur=i;CUR={};apply();return}}
}
// --- in-screen cursor: ↑↓ move the ➤ across the rows of the current list block, enter follows the selected row ---
let CUR={};                                             // {row0, rows[], at} for the screen on display
function cursorBlock(){
  const pre=SECS[S.cur].querySelector('.screen'), lines=pre.innerHTML.split('\n');
  const row0=lines.findIndex(l=>/^\s*<span class="brand b">➤ <\/span>/.test(l)); if(row0<0)return null;
  const ind=lines[row0].indexOf('<span');                 // cells before ➤
  // ponytail: a sibling row is a non-blank line indented 2..8 cells past the ➤ column and not a "key: value" line;
  // if any sibling sits exactly at the label column, deeper lines are descriptions (settings) and are dropped
  const indent=l=>l.search(/\S/), sib=l=>{const n=indent(l);return n>=ind+2&&n<=ind+8&&!/^\s*[^<:]{1,24}:\s/.test(l.replace(/<[^>]+>/g,''))};
  let a=row0,b=row0; while(a>0&&sib(lines[a-1]))a--; while(b<lines.length-1&&sib(lines[b+1]))b++;
  let rows=[];for(let r=a;r<=b;r++)rows.push(r);
  if(rows.some(r=>r!=row0&&indent(lines[r])==ind+2))rows=rows.filter(r=>r==row0||indent(lines[r])==ind+2);
  return {lines,row0,ind,rows,at:rows.indexOf(row0)};
}
function paint(){                                        // re-render the pre with the cursor on CUR.rows[CUR.at]
  const {lines,row0,ind,rows,at}=CUR, out=lines.slice();
  out[row0]=lines[row0].replace('<span class="brand b">➤ </span>','  ').replace(/<span class="brand b">([^<]*)<\/span>/,'$1');
  const r=rows[at]; {const l=out[r];
    // ponytail: label = text after an optional "N. " tag up to a double space or a tag; good enough for menus and lists
    out[r]=l.slice(0,ind)+'<span class="brand b">➤ </span>'+l.slice(ind+2).replace(/^((?:<span class="muted">)?\s*(?:\S\. |[○●] )?(?:<\/span>)?\s*)([^<]*?)(?=  |<|$)/,'$1<span class="brand b">$2</span>')}
  SECS[S.cur].querySelector('.screen').innerHTML=out.join('\n');
}
function key(k){
  if(k=='up'||k=='down'){ if(!CUR.rows)CUR=cursorBlock()||{}; if(CUR.rows){CUR.at=Math.max(0,Math.min(CUR.rows.length-1,CUR.at+(k=='down'?1:-1)));paint();return} }
  if(k=='enter'&&CUR.rows){const off=CUR.at-CUR.rows.indexOf(CUR.row0), txt=CUR.lines[CUR.rows[CUR.at]].replace(/<[^>]+>/g,'').slice(CUR.ind+2).trim(),
      tag=txt.match(/^(\S)\. /), first=txt.replace(/^(?:\S\. |[○●] )/,'')[0]||'';
    // ponytail: the walk reached some rows by shortcut letter (S, a, d…) instead of enter, so try those too
    return go(...(tag?[[tag[1]]]:[]),[...Array(Math.max(0,off)).fill('down'),...Array(Math.max(0,-off)).fill('up'),'enter'],[first.toUpperCase()],[first.toLowerCase()])}
  if(k==']')return go(['\x00next']); if(k=='[')return go(['\x00prev']);
  go([k]);
}
function nav(){
  const c=KEYS[S.cur], next=[...new Set(KEYS.filter(t=>pre(c,t)).map(t=>t[c.length]))].map(t=>t===''?'space':t);
  const flow=(SECS[S.cur].dataset.tags.match(/flow:\S+/)||[''])[0].replace('flow:','');
  $('#nav').innerHTML=`<b>${SECS[S.cur].id}</b> · ${SECS[S.cur].dataset.title}${flow?' · <b>'+flow+'</b>':''} &nbsp;&nbsp; keys here: ${next.map(t=>'<kbd>'+t+'</kbd>').join(' ')||'–'}`+
    ` &nbsp;&nbsp; <kbd>↑↓</kbd> move · <kbd>enter</kbd> select · <kbd>esc</kbd> back · <kbd>[</kbd><kbd>]</kbd> prev/next screen · <kbd>E</kbd> edit`;
}
document.addEventListener('keydown',e=>{
  if(S.mode!='single'||/INPUT|TEXTAREA|SELECT/.test(e.target.tagName))return;
  if(e.key=='E'&&!S.edit||e.key=='Escape'&&S.edit){S.edit=!S.edit;apply();e.preventDefault();return}
  if(S.edit||e.metaKey||e.ctrlKey||e.altKey)return;
  const k=e.key in norm?norm[e.key]:e.key.length==1?e.key:null; if(k===null)return;
  e.preventDefault();key(k)});
const qm=new URLSearchParams(location.search).get('mode');if(qm)S.mode=qm;
if(location.hash){const i=SECS.findIndex(s=>'#'+s.id==location.hash);if(i>=0)S.cur=i}
window.addEventListener('hashchange',()=>{const i=SECS.findIndex(s=>'#'+s.id==location.hash);if(i>=0&&i!=S.cur){S.cur=i;apply()}});
function overflow(){
  document.querySelectorAll('.over').forEach(e=>e.remove()); if(!S.over)return;
  for(const pre of document.querySelectorAll('.screen'))
    pre.innerText.split('\n').forEach((l,i)=>{
      // ponytail: counts code points, wide glyphs (emoji/CJK) count as 1 cell
      if(i<S.rows&&[...l.replace(/\s+$/,'')].length>S.cols){const m=document.createElement('div');m.className='over';
        m.style.top=`calc(var(--pt,0px) + ${i}*var(--lh))`;pre.parentNode.appendChild(m)}});
}
document.querySelectorAll('[data-k]').forEach(el=>el.addEventListener('input',()=>{
  S[el.dataset.k]=el.type=='checkbox'?el.checked:el.type=='number'||(el.tagName=='SELECT'&&!isNaN(el.value))?+el.value:el.value;
  if(el.dataset.k=='set'&&S.mode=='single'){const i=SECS.findIndex(sec=>S.set=='all'||(' '+sec.dataset.tags+' ').includes(' '+S.set+' '));if(i>=0){S.cur=i;CUR={}}}
  apply()}));
$('#theme').onchange=e=>{if(T[e.target.value]){Object.assign(S,T[e.target.value]);apply()}};
$('#reset').onclick=()=>{S={...D,...BASE,mode:S.mode,cur:S.cur};apply()};
document.addEventListener('dblclick',e=>{const sec=e.target.closest('section');if(sec&&S.mode=='grid'&&!S.edit){S.cur=SECS.indexOf(sec);S.mode='single';apply()}});
$('#tokens').onchange=e=>{for(const[,k,v]of e.target.value.matchAll(/--([\w-]+)\s*:\s*([^;]+);/g)){
  if(k=='fs')S.fs=parseFloat(v);else if(k=='lh')S.lh=+(parseFloat(v)/S.fs).toFixed(2);else if(colours.includes(k))S[k]=v.trim()}apply()};
document.querySelectorAll('.rt').forEach(a=>a.onclick=()=>{const s=a.closest('section');
  s.querySelector('.screen').innerHTML=s.querySelector('template').innerHTML;CUR={};overflow()});
document.addEventListener('input',e=>{if(e.target.classList.contains('screen'))overflow()});
apply();
"""

def main():
    args = [a for a in sys.argv[1:] if a != '--all']  # --all accepted for compatibility; all screens are always included
    if not args: sys.exit(__doc__)
    out = args[0].rstrip('/')
    meta = {}
    for row in open(os.path.join(out, 'ans', 'index.txt'), encoding='utf-8'):
        f = row.rstrip('\n').split('\t')
        if len(f) >= 3: meta[f[0]] = f[1], f[2], (f[3] if len(f) > 3 else '')
    names = sorted(n for n in os.listdir(os.path.join(out, 'ans')) if n.endswith('-80x24.ans'))
    secs, tagset = [], set()
    for n in names:
        body = convert(open(os.path.join(out, 'ans', n), encoding='utf-8').read(), 24)
        title, keys, tags = meta.get(n, (n, '', ''))
        e = lambda s: html.escape(s)
        slug = n[:-10]
        # key tokens as the walk recorded them; quoted text and direct:* messages are auto-played by the lab
        # split on single spaces: an empty token is the space key; quoted text → placeholder so inner spaces survive
        toks = [t for t in re.sub(r'"[^"]*"', 'Q', keys).split(' ') if t not in ('Q', '(launch)') and not t.startswith('direct:')]
        # a space press is a " " token joined by " " separators, so it shows up as two empty strings: keep one per press
        toks = squash(toks)
        if not tags and any(slug.startswith(k) for k in KEY): tags = 'key'  # ponytail: old index without tags
        tagset.update(tags.split())
        secs.append(f'<section id="{e(slug)}" data-title="{e(title)}" data-keys=\'{json.dumps(toks)}\' data-tags="{e(tags)}">'
                    f'<div class="bar"><i></i><i></i><i></i>dop — {e(slug)}</div><span class="ruler">80×24</span><h2>{e(n.split("-")[0])} · {e(title)}</h2>'
                    f'<div class="kp">{e(slug)} · keys: {e(keys or "-")} · <a class="rt">reset text</a></div>'
                    f'<template>{body}</template><div class="wrap"><pre class="screen" contenteditable="plaintext-only" '
                    f'spellcheck="false">\n{body}</pre><div class="guide"></div></div></section>')
    pick = ''.join(f'<label>{k}<input type="color" data-k="{k}"></label>' for k in DEFAULTS)
    order = lambda t: (t != 'key', t != 'edge', t)   # key, edge, then flows alphabetically
    sets = ''.join(f'<option value="{html.escape(t)}">{html.escape(t.replace("flow:", ""))}' for t in sorted(tagset, key=order))
    themes = ''.join(f'<option value="{html.escape(k)}">{html.escape(k)}' for k in THEMES)
    dials = (f'<div id="dials"><label>mode<select data-k="mode"><option value="grid">grid<option value="single">single</select></label>'
             f'<label>theme<select id="theme"><option value="">custom{themes}</select></label>'
             f'<label>set<select data-k="set"><option value="all">all{sets}</select></label><label><input type="checkbox" data-k="edit">edit</label>{pick}<label>font px<input type="number" min="10" max="20" step="1" data-k="fs"></label>'
             '<label>line-h<input type="number" min="1" max="1.6" step="0.05" data-k="lh"></label>'
             '<label>cols<select data-k="cols"><option>80<option>100<option>120</select></label>'
             '<label>rows<select data-k="rows"><option>24<option>40</select></label>'
             '<label><input type="checkbox" data-k="bold">bold</label><label><input type="checkbox" data-k="ital">italic</label>'
             '<label><input type="checkbox" data-k="guide">col guide</label><label><input type="checkbox" data-k="over">overflow</label>'
             '<button id="reset">Reset</button><label>Tokens as CSS<textarea id="tokens" spellcheck="false"></textarea></label></div>')
    os.makedirs(os.path.join(out, 'lab'), exist_ok=True)
    path = os.path.join(out, 'lab', 'index.html')
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write(f'<!doctype html><meta charset="utf-8"><title>dop TUI lab</title><style>{CSS}</style>'
                 f'{dials}<main>{"".join(secs)}</main><div id="nav"></div><script>{JS.replace("__DEFAULTS__", json.dumps(DEFAULTS)).replace("__THEMES__", json.dumps(THEMES))}</script>\n')
    if unknown: print('unknown colours: ' + ' '.join(sorted(unknown)), file=sys.stderr)
    print(f'{path} ({len(secs)} screens)')

if __name__ == '__main__':
    main()
