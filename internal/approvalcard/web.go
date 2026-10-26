package approvalcard

import (
	"html/template"
	"io"
)

// Form is the one web page every tunnel surface serves: the card, the
// passphrase field, Approve / Deny. The layout is mobile-first and
// self-contained (no external resources, dark mode via the system).
type Form struct {
	Card         Card
	Action       string // POST target for approve
	RejectAction string // POST target for reject / deny
	Error        string // shown above the field when set
	Left         string // "4m30s" — time left to answer, optional
}

// Page writes the HTML page for f.
func Page(w io.Writer, f Form) error {
	data := struct {
		Form
		Title, Effect, Footer, Mood string
		Rows                        [][2]string
		Options                     []Option
		Default                     int
		Passphrase                  string
	}{Form: f, Title: f.Card.Title(), Effect: f.Card.Effect(), Footer: f.Card.Footer(), Mood: string(f.Card.Mood()),
		Rows: f.Card.Rows(), Options: f.Card.Options, Default: f.Card.Default, Passphrase: Passphrase}
	return pageTmpl.Execute(w, data)
}

var pageTmpl = template.Must(template.New("card").Parse(`<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<meta name="format-detection" content="telephone=no">
<meta name="referrer" content="no-referrer">
<title>{{.Title}}</title>
<style>
:root{--bg:#f7f7f8;--fg:#111;--muted:#666;--card:#fff;--line:#ddd;--ok:#0a7cff;--no:#e03b3b;--amber:#b7791f}
@media(prefers-color-scheme:dark){:root{--bg:#111;--fg:#eee;--muted:#999;--card:#1b1b1d;--line:#333}}
html,body{margin:0;background:var(--bg);color:var(--fg);font:16px -apple-system,BlinkMacSystemFont,system-ui,sans-serif}
main{max-width:30rem;margin:0 auto;padding:1.25rem 1rem calc(1rem + env(safe-area-inset-bottom))}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:1.25rem}
.card.red{border-color:var(--no)}.card.amber{border-color:var(--amber)}
h1{font-size:.95rem;font-weight:600;color:var(--muted);margin:0 0 .75rem}
.effect{font-size:1.15rem;line-height:1.4;margin:0 0 1rem}
dl{margin:0 0 1rem;display:grid;grid-template-columns:auto 1fr;gap:.35rem .75rem}
dt{color:var(--muted)}dd{margin:0;word-break:break-word}
.foot{color:var(--muted);font-size:.9rem;margin:0 0 1rem}
label{display:block;color:var(--muted);font-size:.9rem;margin:.25rem 0}
select,input[type=password]{width:100%;box-sizing:border-box;padding:.9rem;font-size:1rem;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--fg);margin-bottom:.75rem}
.row{display:flex;gap:.5rem}
button{flex:1;min-height:44px;padding:.9rem;font-size:1rem;border:1px solid var(--line);border-radius:8px;background:var(--card);color:var(--fg);cursor:pointer}
button.approve{background:var(--ok);border-color:var(--ok);color:#fff}
.red button.approve{background:var(--card);color:var(--fg);border-color:var(--line)}
.red button.reject{background:var(--no);border-color:var(--no);color:#fff}
.err{color:var(--no);margin:0 0 .75rem}
.left{float:right;color:var(--muted);font-size:.85rem}
</style></head><body>
<main>
  <div class="card {{.Mood}}">
    <h1>{{.Title}}{{if .Left}}<span class="left">{{.Left}} left</span>{{end}}</h1>
    <p class="effect">{{.Effect}}</p>
    {{if .Rows}}<dl>{{range .Rows}}<dt>{{index . 0}}</dt><dd>{{index . 1}}</dd>{{end}}</dl>{{end}}
    {{if .Footer}}<p class="foot">{{.Footer}}</p>{{end}}
    <form method="POST" action="{{.Action}}">
      {{if .Options}}<label for="o">For how long</label>
      <select id="o" name="option">{{range $i, $o := .Options}}<option value="{{$o.Value}}"{{if eq $i $.Default}} selected{{end}}>{{$o.Label}}</option>{{end}}</select>{{end}}
      <label for="p">{{.Passphrase}}</label>
      <input id="p" name="passphrase" type="password" autocomplete="off" autocapitalize="off" spellcheck="false" autofocus required>
      {{if .Error}}<p class="err">{{.Error}}</p>{{end}}
      <div class="row">
        <button class="reject" type="submit" formaction="{{.RejectAction}}" formmethod="POST">Deny</button>
        <button class="approve" type="submit">Approve</button>
      </div>
    </form>
  </div>
</main>
</body></html>`))
