// Package version exposes the build metadata to any part of the code
// that wants to surface it (CLI help, TUI header, `dop admin status`,
// audit-log stamps).
//
// Populated by goreleaser via ldflags:
//   -X github.com/fray/dop/internal/version.Version={{.Version}}
//   -X github.com/fray/dop/internal/version.Commit={{.Commit}}
//   -X github.com/fray/dop/internal/version.Date={{.Date}}
// For `go install` / `go build` from source, String() falls back to
// runtime/debug.ReadBuildInfo() so nothing is ever blank.
package version

import "runtime/debug"

var (
	Version = "dev"
	Commit  = ""
	Date    = ""
)

// String returns a compact single-line summary suitable for printing.
// Example: "dop v1.10.4 (commit abc1234, built 2026-09-30T10:00Z)"
func String() string {
	v, c, d := Version, Commit, Date
	if v == "dev" || v == "" {
		if info, ok := debug.ReadBuildInfo(); ok {
			if info.Main.Version != "" && info.Main.Version != "(devel)" {
				v = info.Main.Version
			}
			for _, s := range info.Settings {
				switch s.Key {
				case "vcs.revision":
					if c == "" {
						c = s.Value
					}
				case "vcs.time":
					if d == "" {
						d = s.Value
					}
				}
			}
		}
	}
	out := "dop " + v
	if len(c) >= 7 {
		out += " (commit " + c[:7]
		if d != "" {
			out += ", built " + d
		}
		out += ")"
	} else if d != "" {
		out += " (built " + d + ")"
	}
	return out
}

// Short returns just the semver-ish version string (e.g. "v1.10.4" or
// "dev") — useful for the TUI header where full commit+date is noisy.
func Short() string {
	v := Version
	if v == "dev" || v == "" {
		if info, ok := debug.ReadBuildInfo(); ok {
			if info.Main.Version != "" && info.Main.Version != "(devel)" {
				v = info.Main.Version
			}
		}
	}
	return v
}
