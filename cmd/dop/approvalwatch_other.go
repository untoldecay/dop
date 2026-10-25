//go:build !darwin

package main

import "github.com/fray/dop/internal/config"

// No native dialog off darwin: the TUI banner is the surface.
func startApprovalWatcher(*config.Paths) {}
