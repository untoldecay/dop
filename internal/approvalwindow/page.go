package approvalwindow

import (
	_ "embed"
	"encoding/json"
	"strings"
)

//go:embed page.html
var pageHTML string

// Page renders the window's HTML for req: the page template with the
// card data inlined as JSON. Exported so tests and the TUI lab can
// render it without a window.
func Page(req Request) string {
	return strings.Replace(pageHTML, "/*DOP_DATA*/null", pageJSON(req), 1)
}

func pageJSON(req Request) string {
	c := req.Card
	opts := make([]map[string]string, 0, len(c.Options))
	for _, o := range c.Options {
		opts = append(opts, map[string]string{"label": o.Label, "value": o.Value})
	}
	b, _ := json.Marshal(map[string]any{
		"title": c.Title(), "effect": c.Effect(), "rows": c.Rows(), "footer": c.Footer(), "mood": string(c.Mood()),
		"options": opts, "default": c.Default, "lease": req.Lease, "body": req.Body, "demo": req.Demo,
		"timeoutMs": req.TimeoutMs, "subject": c.Subject,
	})
	// </script> inside a JSON string would end the script block.
	return strings.ReplaceAll(string(b), "</", `<\/`)
}
