//go:build darwin && cgo

package approvalwindow

import (
	"sync"
	"time"

	webview "github.com/webview/webview_go"
)

// Run opens the window and blocks until a decision, the timeout, or the
// window is closed. Must run on the process's main thread.
func Run(req Request) (Result, error) {
	w := webview.New(false)
	defer w.Destroy()
	w.SetTitle(req.Card.Title())
	w.SetSize(720, 440, webview.HintFixed)

	var (
		mu   sync.Mutex
		res  Result
		done bool
	)
	finish := func(r Result) {
		mu.Lock()
		if !done {
			done, res = true, r
		}
		mu.Unlock()
		w.Dispatch(w.Terminate)
	}
	// decide(button, choice, passphrase) — called by the page.
	_ = w.Bind("decide", func(button, choice, pass string) {
		finish(Result{Button: button, Choice: choice, Passphrase: pass})
	})
	timeout := time.Duration(req.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	if !req.Demo {
		t := time.AfterFunc(timeout, func() { finish(Result{GaveUp: true}) })
		defer t.Stop()
	}
	w.SetHtml(Page(req))
	w.Run()
	mu.Lock()
	defer mu.Unlock()
	if !done { // window closed by the user: a Deny
		res = Result{Button: "Deny"}
	}
	return res, nil
}
