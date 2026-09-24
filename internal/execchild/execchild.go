// Package execchild replaces the current process with the child command,
// inheriting a scoped environment.
//
// syscall.Exec is used (not exec.Command) so DOP itself steps out of the
// process tree once the child launches — signals, exit codes, and pty
// behavior all pass through naturally.
package execchild

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// Run replaces the current process with `argv[0] argv[1:]`, using env as the
// full environment. If cleanEnv is false, env is merged onto os.Environ()
// (child inherits parent env by default). If true, env is passed as-is plus
// PATH/HOME/USER from the parent.
func Run(argv []string, env []string, cleanEnv bool) error {
	if len(argv) == 0 {
		return fmt.Errorf("no command to exec")
	}

	bin, err := exec.LookPath(argv[0])
	if err != nil {
		return fmt.Errorf("lookup %q: %w", argv[0], err)
	}

	var finalEnv []string
	if cleanEnv {
		// Keep the minimum for a usable child shell environment.
		for _, keep := range []string{"PATH", "HOME", "USER", "SHELL", "TERM", "LANG"} {
			if v, ok := os.LookupEnv(keep); ok {
				finalEnv = append(finalEnv, keep+"="+v)
			}
		}
		finalEnv = append(finalEnv, env...)
	} else {
		finalEnv = append(finalEnv, os.Environ()...)
		finalEnv = append(finalEnv, env...)
	}

	return syscall.Exec(bin, argv, finalEnv)
}
