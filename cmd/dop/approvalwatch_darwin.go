//go:build darwin

package main

import (
	"os"
	"time"

	"github.com/fray/dop/internal/config"
)

// startApprovalWatcher runs the watcher in the session daemon when a
// GUI is reachable. DOP_NO_WATCH=1 or DOP_NO_POPUP=1 turn it off.
func startApprovalWatcher(paths *config.Paths) {
	if os.Getenv("DOP_NO_WATCH") == "1" || os.Getenv("DOP_NO_POPUP") == "1" {
		return
	}
	if ok, _ := canShowGUIDialog(); !ok {
		return
	}
	if _, err := os.Stat(paths.Vault); err != nil {
		return
	}
	every := envDuration("DOP_WATCH_INTERVAL", 20*time.Second)
	go newApprovalWatcher(paths).loop(every)
}
