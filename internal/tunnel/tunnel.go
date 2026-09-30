// Package tunnel spawns `cloudflared tunnel --url http://localhost:PORT`
// and returns the public HTTPS URL it announces on stderr.
//
// Zero-config: uses Cloudflare's "Quick Tunnel" flow which doesn't
// require an account or a domain. The URL is ephemeral (dies with the
// process). Perfect for a 2-min claim approval window.
//
// Fallback: if cloudflared is not on PATH, callers should still be able
// to serve on LAN (same-network phone) — that path lives in the caller,
// not here.
package tunnel

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

// urlRegexps match the Quick-Tunnel URLs cloudflared prints in its
// startup banner. Order matters: we try the most specific first, then
// fall back to any https URL under trycloudflare.com or cfargotunnel.com
// so a minor banner tweak upstream doesn't silently break us.
var urlRegexps = []*regexp.Regexp{
	regexp.MustCompile(`https://[a-z0-9-]+\.trycloudflare\.com`),
	regexp.MustCompile(`https://[a-z0-9-]+\.cfargotunnel\.com`),
	regexp.MustCompile(`https?://[a-z0-9.-]*(?:trycloudflare|cfargotunnel)\.com[^\s]*`),
}

func findURL(line string) string {
	for _, re := range urlRegexps {
		if m := re.FindString(line); m != "" {
			return m
		}
	}
	return ""
}

// Tunnel is a running cloudflared subprocess.
type Tunnel struct {
	cmd *exec.Cmd
	URL string

	stopMu sync.Mutex
	stopped bool
}

// KillStrays finds and terminates any lingering `cloudflared tunnel
// --url http://localhost:...` processes from prior sessions (e.g.
// SIGKILL'd parent, force-quit terminal, crash). Returns the number
// killed. Non-fatal: any error is swallowed since this is best-effort
// cleanup at the start of a new claim.
//
// v1.11.1 — Fizz reported "tunnel returns 530" after a prior claim
// died hard, leaving cloudflared orphaned but still holding the
// ephemeral URL registration on Cloudflare's edge. The new claim's
// own tunnel would compete with the dead one. Silent auto-cleanup
// prevents this without a user-visible step.
func KillStrays() int {
	// Only match cloudflared quick tunnels dop would have started —
	// don't touch named tunnels, other users' cloudflared, etc.
	out, err := exec.Command("pgrep", "-f", "cloudflared tunnel --url http://localhost:").Output()
	if err != nil {
		return 0
	}
	killed := 0
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		pid := strings.TrimSpace(line)
		if pid == "" {
			continue
		}
		// SIGTERM first, then SIGKILL after a brief wait.
		p, err := exec.Command("kill", "-TERM", pid).Output()
		_ = p
		if err == nil {
			killed++
		}
	}
	if killed > 0 {
		time.Sleep(100 * time.Millisecond)
		_, _ = exec.Command("pkill", "-KILL", "-f", "cloudflared tunnel --url http://localhost:").Output()
	}
	return killed
}

// Available reports whether the cloudflared binary is on $PATH.
func Available() bool {
	_, err := exec.LookPath("cloudflared")
	return err == nil
}

// Start spawns cloudflared pointed at http://localhost:localPort and
// waits until it announces its public URL (or timeoutSec expires).
// Returns a running Tunnel — callers MUST call Stop when done.
func Start(ctx context.Context, localPort int, timeout time.Duration) (*Tunnel, error) {
	if !Available() {
		return nil, errors.New("cloudflared binary not found on PATH — install from https://developers.cloudflare.com/cloudflared/")
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	cmd := exec.Command("cloudflared", "tunnel", "--no-autoupdate",
		"--url", fmt.Sprintf("http://localhost:%d", localPort))
	// v1.9.9 — put cloudflared in its OWN process group so anything it
	// or its children do at shutdown (signal handlers, tty group leader
	// cleanup, etc.) can't propagate a SIGHUP/SIGTERM back to us. Before
	// this, killing the old tunnel during an auto-restart would race
	// into the parent claim's sigCh and abort the whole flow with
	// 'interrupted — pending claim cancelled'.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	// cloudflared writes to stderr; also drain stdout to prevent block.
	cmd.Stdout = io.Discard
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start cloudflared: %w", err)
	}
	t := &Tunnel{cmd: cmd}

	// Read stderr until we see a trycloudflare URL or timeout.
	urlCh := make(chan string, 1)
	go func() {
		scanner := bufio.NewScanner(stderr)
		scanner.Buffer(make([]byte, 0, 1024), 64*1024)
		found := false
		for scanner.Scan() {
			line := scanner.Text()
			if !found {
				if m := findURL(line); m != "" {
					urlCh <- m
					found = true
				}
			}
			// Otherwise drain silently. If we wanted a debug mode, we'd
			// route this to a log file.
		}
	}()

	select {
	case u := <-urlCh:
		t.URL = strings.TrimSpace(u)
		return t, nil
	case <-time.After(timeout):
		t.Stop()
		return nil, fmt.Errorf("cloudflared did not announce a URL within %s", timeout)
	case <-ctx.Done():
		t.Stop()
		return nil, ctx.Err()
	}
}

// Stop kills the tunnel process group. Idempotent. Kills the whole
// group (not just the leader) because cloudflared spawns children —
// TERM the leader alone leaves orphans that keep the tunnel URL alive
// briefly and race the health-restart path.
func (t *Tunnel) Stop() {
	t.stopMu.Lock()
	defer t.stopMu.Unlock()
	if t.stopped || t.cmd == nil || t.cmd.Process == nil {
		return
	}
	t.stopped = true
	pid := t.cmd.Process.Pid
	// Negative PID → target the process group (created by Setpgid in Start).
	// SIGKILL to be sure it goes; fall back to killing just the leader if
	// group signaling fails on this platform.
	if pid > 0 {
		if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil {
			_ = t.cmd.Process.Kill()
		}
	}
	go func() { _, _ = t.cmd.Process.Wait() }()
}

// CheckAlive probes the tunnel URL with a short-deadline HEAD request
// and reports whether it appears to be reachable. Any 2xx / 3xx / 4xx
// response means cloudflared is proxying; 5xx (especially 530 "origin
// tunnel connection error") or a network-level failure indicates the
// tunnel died. Blocks up to the passed timeout.
//
// v1.9.6 — added because cloudflared quick tunnels regularly drop
// mid-claim and there was no way for the caller to notice until the
// user reported it.
func CheckAlive(url string, timeout time.Duration) bool {
	if url == "" {
		return false
	}
	client := &http.Client{Timeout: timeout}
	req, err := http.NewRequest(http.MethodHead, url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "dop-tunnel-healthcheck/1.9.6")
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	// 530 is cloudflared's "no origin" — the canonical dead-tunnel code.
	if resp.StatusCode >= 500 {
		return false
	}
	return true
}
