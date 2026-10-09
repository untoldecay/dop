package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
	"golang.org/x/term"
)

// runPTYRedacted runs the child on its own pseudo-terminal when DOP's
// output is a terminal, and relays everything through redactWriter.
// A terminal doesn't prove a human is reading — agent harnesses
// (Cursor, VS Code via node-pty, script, expect) run commands in a pty
// and capture it — so injected keys are masked there too (dop-v5s).
// The child still sees a real terminal: interactive tools, colours and
// /dev/tty keep working, and /dev/tty writes go through the mask.
//
// Terminal handling: the outer terminal is put in raw mode so keys
// (ctrl+c, ctrl+z) reach the inner pty, whose line discipline turns
// them into signals for the child's foreground group. A child stop
// (ctrl+z) restores the outer terminal and stops DOP itself so the
// shell regains control; `fg` re-enters raw mode, resizes and resumes
// the child. Signals sent to DOP (TERM, HUP, INT, QUIT) go to the
// child's process group; SIGWINCH resizes the inner pty. A failed
// write of masked output kills the child — never unmasked output.
// errPTYUnavailable means no pseudo-terminal could be opened, before
// the child started — execChild then runs it on masked pipes instead.
type errPTYUnavailable struct{ err error }

func (e errPTYUnavailable) Error() string { return "pty unavailable: " + e.err.Error() }

func runPTYRedacted(bin string, argv, finalEnv []string, env map[string]string) error {
	vals, labels := redactTargets(env)
	out := newRedactWriter(os.Stdout, vals, labels)

	cmd := exec.Command(bin, argv[1:]...)
	cmd.Args = argv
	cmd.Env = finalEnv
	size, err := pty.GetsizeFull(os.Stdout)
	if err != nil {
		size = nil
	}
	ptmx, err := pty.StartWithSize(cmd, size)
	if err != nil {
		// No pty here (sandboxes such as Cursor's forbid /dev/ptmx).
		// The child hasn't started: the caller falls back to masked pipes.
		return errPTYUnavailable{err}
	}
	defer ptmx.Close()
	pid := cmd.Process.Pid

	inFd := int(os.Stdin.Fd())
	var restore func()
	enterRaw := func() {
		if restore != nil || !term.IsTerminal(inFd) {
			return
		}
		if st, err := term.MakeRaw(inFd); err == nil {
			restore = func() { _ = term.Restore(inFd, st) }
		}
	}
	leaveRaw := func() {
		if restore != nil {
			restore()
			restore = nil
		}
	}
	enterRaw()
	defer leaveRaw()

	resize := func() { _ = pty.InheritSize(os.Stdout, ptmx) }
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, syscall.SIGWINCH, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)
	defer signal.Stop(sigs)
	go func() {
		for s := range sigs {
			if s == syscall.SIGWINCH {
				resize()
				continue
			}
			_ = syscall.Kill(-pid, s.(syscall.Signal))
		}
	}()

	// Keys → child. The child leads its own session on the inner pty,
	// so the kernel ignores a terminal stop (^Z) for it (orphaned
	// process group). While the child's terminal is in normal mode
	// (ISIG), DOP turns its suspend key into SIGSTOP for the child's
	// group; the wait loop below then hands the terminal back to the
	// shell. In raw mode (vim, less…) the key goes through untouched.
	// When stdin isn't a terminal (a pipe), its end becomes a terminal
	// EOF (^D) for the child.
	stdinTTY := term.IsTerminal(inFd)
	ptmxFd := int(ptmx.Fd())
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := os.Stdin.Read(buf)
			data := buf[:n]
			if stdinTTY {
				if t, terr := unix.IoctlGetTermios(ptmxFd, ioctlGetTermios); terr == nil && t.Lflag&unix.ISIG != 0 {
					susp := t.Cc[unix.VSUSP]
					for i := bytes.IndexByte(data, susp); susp != 0 && i >= 0; i = bytes.IndexByte(data, susp) {
						_, _ = ptmx.Write(data[:i])
						_ = syscall.Kill(-pid, syscall.SIGSTOP)
						data = data[i+1:]
					}
				}
			}
			if len(data) > 0 {
				_, _ = ptmx.Write(data)
			}
			if err != nil {
				break
			}
		}
		if !stdinTTY {
			_, _ = ptmx.Write([]byte{4})
		}
	}()

	// Child output → mask → terminal. Fail closed on a write error.
	copied := make(chan struct{})
	go func() {
		defer close(copied)
		_, _ = io.Copy(out, ptmx)
		if out.failed != nil {
			_ = syscall.Kill(-pid, syscall.SIGKILL)
		}
	}()

	code := 0
	for {
		var ws syscall.WaitStatus
		_, err := syscall.Wait4(pid, &ws, syscall.WUNTRACED, nil)

		if err == syscall.EINTR {
			continue
		}
		if err != nil {
			return err
		}
		// Raw stop status: Go's WaitStatus.Stopped() is false for a
		// SIGSTOP stop on darwin (it treats that as ptrace), and SIGSTOP
		// is how DOP suspends the child.
		if ws&0xff == 0x7f {
			leaveRaw()
			_ = syscall.Kill(os.Getpid(), syscall.SIGSTOP) // the shell takes over; `fg` resumes us here
			enterRaw()
			resize()
			_ = syscall.Kill(-pid, syscall.SIGCONT)
			continue
		}
		if ws.Exited() {
			code = ws.ExitStatus()
			break
		}
		if ws.Signaled() {
			code = 128 + int(ws.Signal())
			break
		}
		// Anything else (e.g. a continue report) — keep waiting.
	}

	// Drain what the child wrote before exiting; a background grandchild
	// holding the pty open mustn't keep DOP alive forever.
	select {
	case <-copied:
	case <-time.After(2 * time.Second):
		_ = ptmx.Close()
		<-copied
	}
	if err := out.Flush(); err != nil {
		return err
	}
	leaveRaw()
	if code != 0 {
		return childExit(code)
	}
	return nil
}
