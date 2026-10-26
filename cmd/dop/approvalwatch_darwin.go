//go:build darwin

package main

import (
	"os"
	"time"

	"github.com/fray/dop/internal/config"
)

// startApprovalWatcher runs the watcher in the session daemon when a
// GUI is reachable. DOP_NO_WATCH=1 or DOP_NO_POPUP=1 turn it off. The
// result is what `dop admin status` shows: "on" or "off: <reason>".
func startApprovalWatcher(paths *config.Paths, report func(string)) string {
	if os.Getenv("DOP_NO_WATCH") == "1" || os.Getenv("DOP_NO_POPUP") == "1" {
		return "off: DOP_NO_WATCH / DOP_NO_POPUP set"
	}
	if ok, why := canShowGUIDialog(); !ok {
		return "off: " + why
	}
	if _, err := os.Stat(paths.Vault); err != nil {
		return "off: no vault yet"
	}
	every := envDuration("DOP_WATCH_INTERVAL", 20*time.Second)
	w := newApprovalWatcher(paths)
	w.report = report
	go w.loop(every)
	return "on"
}
