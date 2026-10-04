// TUI preferences — thin alias layer over `internal/userprefs`.
//
// rc5b promoted the on-disk store to a shared package so non-TUI code
// (printguard, future surfaces) can read the same preferences without
// crossing into the TUI package. This file keeps the TUI-side names
// stable so the rest of the TUI code didn't need to churn.

package tui

import (
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/userprefs"
)

// Prefs — alias to the shared type so the TUI code continues to use
// `tui.Prefs` while non-TUI code reads `userprefs.Prefs`.
type Prefs = userprefs.Prefs

// LoadPrefs reads tui-prefs.yaml; missing file ⇒ zero-value Prefs.
func LoadPrefs(paths *config.Paths) Prefs { return userprefs.Load(paths) }

// SavePrefs persists the Prefs struct to disk.
func SavePrefs(paths *config.Paths, p Prefs) error { return userprefs.Save(paths, p) }
