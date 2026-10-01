// `dop watch` — live tail of the audit log. v1.4.
//
// Prints past events (--since) then follows new appends. Colors event
// kinds by category so you can spot a claim in a busy terminal.

package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fray/dop/internal/audit"
	"github.com/fray/dop/internal/capability"
	"github.com/fray/dop/internal/config"
)

// ANSI colors — keep dependency-free; the TUI uses lipgloss but this
// stream mode should work in any pipe or minimal terminal.
const (
	ansiReset  = "\033[0m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiGreen  = "\033[32m"
	ansiYellow = "\033[33m"
	ansiBlue   = "\033[34m"
	ansiCyan   = "\033[36m"
	ansiBold   = "\033[1m"
)

func runWatch(args []string) int {
	fs := flag.NewFlagSet("watch", flag.ExitOnError)
	since := fs.Duration("since", 24*time.Hour, "print backfill from this window before following")
	all := fs.Bool("all", false, "print entire log before following")
	follow := fs.Bool("follow", true, "keep tailing after backfill (default true)")
	filter := fs.String("filter", "", "comma-separated event kinds (issue,claim,claim_denied,repin,revoke)")
	noColor := fs.Bool("no-color", false, "disable ANSI colors")
	_ = fs.Parse(args)

	if !isatty(os.Stdout) {
		*noColor = true
	}

	paths, err := config.Resolve()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop watch: %v\n", err)
		return 1
	}

	// v1.13.0-rc7 — audit log leak plug. Pre-rc7 anyone with
	// filesystem access could tail the audit log and see every
	// agent's lookup_ids, SAS codes, issue/claim trail. Now:
	//   - admin session unlocks the full feed
	//   - a bearer in $DOP_TOKEN or --token-file unlocks ONLY events
	//     scoped to that bearer's lookup_id
	//   - no admin + no bearer → access denied
	bearerLookup, isAdmin := watchAccessContext(paths)
	if !isAdmin && bearerLookup == "" {
		fmt.Fprintln(os.Stderr, "dop watch: refusing without admin session or bearer context (set $DOP_TOKEN to see your own events, or `dop admin login` for the full feed)")
		return 1
	}
	path := audit.Path(paths)

	f, err := os.Open(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			fmt.Fprintf(os.Stderr, "dop watch: %v\n", err)
			return 1
		}
		// Log doesn't exist yet — that's fine, just wait for the first write.
		fmt.Fprintln(os.Stderr, "dop watch: no audit log yet — waiting for events")
	} else {
		defer f.Close()
		cutoff := time.Now().Add(-*since)
		filterSet := parseFilterSet(*filter)
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 0, 1024), 64*1024)
		for scanner.Scan() {
			line := scanner.Bytes()
			var ev audit.Event
			if err := json.Unmarshal(line, &ev); err != nil {
				continue
			}
			if !*all && ev.TS.Before(cutoff) {
				continue
			}
			if !passFilter(ev.Kind, filterSet) {
				continue
			}
			// v1.13.0-rc7 — bearer-scoped feed drops events whose
			// LookupID doesn't match the current bearer. Admin feed
			// shows everything.
			if !isAdmin && ev.LookupID != bearerLookup {
				continue
			}
			fmt.Println(renderEvent(ev, !*noColor))
		}
	}

	if !*follow {
		return 0
	}

	// Follow mode: reopen and seek to end, then poll for growth.
	return followLog(path, parseFilterSet(*filter), !*noColor, bearerLookup, isAdmin)
}

func followLog(path string, filterSet map[string]bool, colored bool, bearerLookup string, isAdmin bool) int {
	// Handle Ctrl-C gracefully.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	var (
		f       *os.File
		reader  *bufio.Reader
		lastIno uint64
		lastPos int64
	)
	openIt := func() error {
		if f != nil {
			f.Close()
		}
		var err error
		f, err = os.Open(path)
		if err != nil {
			return err
		}
		if _, err := f.Seek(0, io.SeekEnd); err != nil {
			return err
		}
		fi, err := f.Stat()
		if err == nil {
			lastPos = fi.Size()
			if sysStat, ok := fi.Sys().(*syscall.Stat_t); ok {
				lastIno = sysStat.Ino
			}
		}
		reader = bufio.NewReader(f)
		return nil
	}
	// Initial open: don't fail if the file doesn't exist yet.
	if err := openIt(); err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(os.Stderr, "dop watch: %v\n", err)
		return 1
	}

	tick := time.NewTicker(400 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case <-sigCh:
			return 0
		case <-tick.C:
		}
		if f == nil {
			// Wait for file to appear.
			if _, err := os.Stat(path); err == nil {
				_ = openIt()
			}
			continue
		}
		// Detect log rotation: file replaced or truncated.
		fi, err := os.Stat(path)
		if err != nil || (lastIno != 0 && sysIno(fi) != lastIno) || fi.Size() < lastPos {
			_ = openIt()
			continue
		}
		for {
			line, err := reader.ReadBytes('\n')
			if len(line) > 0 {
				var ev audit.Event
				if json.Unmarshal(line, &ev) == nil && passFilter(ev.Kind, filterSet) {
					// v1.13.0-rc7 — bearer-scoped follow mode.
					if !isAdmin && ev.LookupID != bearerLookup {
						lastPos += int64(len(line))
						continue
					}
					fmt.Println(renderEvent(ev, colored))
				}
				lastPos += int64(len(line))
			}
			if err != nil {
				break
			}
		}
	}
}

func sysIno(fi os.FileInfo) uint64 {
	if s, ok := fi.Sys().(*syscall.Stat_t); ok {
		return s.Ino
	}
	return 0
}

func parseFilterSet(s string) map[string]bool {
	if s == "" {
		return nil
	}
	out := map[string]bool{}
	for _, k := range strings.Split(s, ",") {
		k = strings.TrimSpace(k)
		if k != "" {
			out[k] = true
		}
	}
	return out
}

func passFilter(kind string, set map[string]bool) bool {
	if set == nil {
		return true
	}
	return set[kind]
}

// renderEvent formats one event as a single line, optionally colored.
func renderEvent(ev audit.Event, colored bool) string {
	ts := ev.TS.Local().Format("15:04:05")
	kind := ev.Kind
	subj := ev.Subject
	if subj == "" {
		subj = "-"
	}
	rest := formatExtra(ev)
	if !colored {
		return fmt.Sprintf("%s  %-14s %-24s %s", ts, kind, subj, rest)
	}
	kindC := colorForKind(kind)
	return fmt.Sprintf("%s%s%s  %s%-14s%s %s%-24s%s %s%s%s",
		ansiDim, ts, ansiReset,
		kindC, kind, ansiReset,
		ansiBold, subj, ansiReset,
		ansiDim, rest, ansiReset)
}

func colorForKind(kind string) string {
	switch kind {
	case audit.EventClaim:
		return ansiGreen + ansiBold
	case audit.EventClaimDenied:
		return ansiRed + ansiBold
	case audit.EventIssue:
		return ansiCyan
	case audit.EventRepin:
		return ansiYellow
	case audit.EventRevoke:
		return ansiRed
	case audit.EventAdminLogin, audit.EventAdminLogout:
		return ansiBlue
	default:
		return ""
	}
}

func formatExtra(ev audit.Event) string {
	parts := []string{}
	if ev.Actor != "" {
		short := ev.Actor
		if len(short) > 12 {
			short = short[:12] + "…"
		}
		parts = append(parts, "pubkey="+short)
	}
	for k, v := range ev.Extra {
		parts = append(parts, k+"="+v)
	}
	return strings.Join(parts, " ")
}

// isatty — true if fd is a terminal (not piped / redirected).
func isatty(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}

// v1.13.0-rc7 — watchAccessContext decides who can see what in the
// audit feed.
//
// Priority:
//   1. Admin session present → return ("", true). Admin sees the full
//      log.
//   2. $DOP_TOKEN (or $DOP_TOKEN_FILE) present → compute lookupID,
//      return (lookupID, false). Non-admin sees only events for
//      their own bearer.
//   3. Neither → return ("", false). Caller refuses access.
//
// We deliberately do NOT ask the admin daemon for session status via
// a bringing-up call that would prompt for a passphrase: if the
// daemon is unreachable or locked, treat it as "no admin session".
func watchAccessContext(paths *config.Paths) (string, bool) {
	// Quick admin check — talk to the daemon if it's already up and
	// unlocked. Any failure means "not an admin session" (silent).
	if client, err := requireAdminSession(paths); err == nil && client != nil {
		return "", true
	}
	// Fall back to bearer-scoped mode.
	bearer, _, _ := readBearerWithSource("")
	if bearer == "" {
		return "", false
	}
	vaultCtx, err := loadVaultContextForWatch(paths)
	if err != nil {
		return "", false
	}
	return capability.LookupID(vaultCtx, bearer), false
}

// loadVaultContextForWatch returns the vault_context bytes needed to
// compute a bearer's lookupID. Agent installs keep this as a sidecar
// (vault-context.bin) so they don't need to decrypt vault.yaml.
func loadVaultContextForWatch(paths *config.Paths) ([]byte, error) {
	ctxPath := filepath.Join(paths.Vault, "vault-context.bin")
	ctx, err := os.ReadFile(ctxPath)
	if err == nil {
		return ctx, nil
	}
	// Last resort: admin install may have it inside vault.yaml. If
	// we're here, admin session already failed, so we can't decrypt
	// vault.yaml — just surface the missing-sidecar error.
	return nil, fmt.Errorf("no vault_context sidecar (%s): %w", ctxPath, err)
}
