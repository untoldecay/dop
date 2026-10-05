// `dop trust list / dop trust revoke` — v1.14.0-rc6i.
//
// The daemon caches operator approvals in a map keyed by
// (ContextKind, ContextValue, Subject). This CLI surface lets the
// operator see which contexts are active and drop them without
// restarting the daemon.
//
// Scope-matched: read-only visibility + a one-shot revoke. Does not
// expose grant lifetime or TTL controls — those live in the daemon
// as constants for now (counselor-recommended; expose later if
// operators report friction).

package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/sessiontrust"
	"github.com/fray/dop/internal/userprefs"
)

func runTrust(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: dop trust <list|revoke> [args]")
		return 2
	}
	switch args[0] {
	case "list":
		return runTrustList(args[1:])
	case "revoke":
		return runTrustRevoke(args[1:])
	case "context":
		// Hidden-ish diagnostic: show what sessiontrust.Resolve
		// returns for the CURRENT invocation. Useful when debugging
		// "why is my cache missing?" without extracting the daemon
		// state. Not advertised in --help; operators who need it will
		// find it from the trust list output's descriptions.
		return runTrustContext(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "dop trust: unknown subcommand %q\n", args[0])
		return 2
	}
}

func runTrustList(args []string) int {
	fs := flag.NewFlagSet("trust list", flag.ExitOnError)
	_ = fs.Parse(args)

	paths, _ := config.Resolve()
	client := admin.NewClient(admin.SockPath(paths))
	if !client.SessionActive() {
		fmt.Fprintln(os.Stderr, "dop trust list: no active admin session — run `dop admin login` first")
		return 1
	}
	grants, err := client.TrustContextList()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop trust list: %v\n", err)
		return 1
	}
	if len(grants) == 0 {
		fmt.Fprintln(os.Stderr, "dop trust list: no active grants (approvals cache is empty)")
		fmt.Fprintln(os.Stderr, "  Grants land here after an approval popup goes through on `dop use` or `dop env`.")
		return 0
	}
	// Sort by context kind, then subject, so output is stable.
	sort.Slice(grants, func(i, j int) bool {
		if grants[i].ContextKind != grants[j].ContextKind {
			return grants[i].ContextKind < grants[j].ContextKind
		}
		return grants[i].Subject < grants[j].Subject
	})
	w := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
	fmt.Fprintln(w, "CONTEXT\tVALUE\tSUBJECT\tAGE\tIDLE")
	now := time.Now()
	for _, g := range grants {
		age := now.Sub(time.Unix(g.CreatedUnix, 0)).Truncate(time.Second)
		idle := now.Sub(time.Unix(g.LastUsedUnix, 0)).Truncate(time.Second)
		value := g.ContextValue
		// Keep the printed value short — the full value isn't a
		// secret but it's long and noisy for most context kinds.
		if len(value) > 36 {
			value = value[:33] + "…"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", g.ContextKind, value, g.Subject, age, idle)
	}
	w.Flush()
	fmt.Fprintln(os.Stderr, "\n  AGE  = time since first approval")
	fmt.Fprintln(os.Stderr, "  IDLE = time since last cache hit (grants idle-expire after 30m)")
	return 0
}

func runTrustRevoke(args []string) int {
	fs := flag.NewFlagSet("trust revoke", flag.ExitOnError)
	all := fs.Bool("all", false, "drop every grant (clears the whole cache)")
	_ = fs.Parse(args)

	paths, _ := config.Resolve()
	client := admin.NewClient(admin.SockPath(paths))
	if !client.SessionActive() {
		fmt.Fprintln(os.Stderr, "dop trust revoke: no active admin session — run `dop admin login` first")
		return 1
	}
	if *all {
		n, err := client.TrustContextRevoke("", "", "", true)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dop trust revoke --all: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "dop trust revoke: dropped %d grant(s)\n", n)
		return 0
	}
	rest := fs.Args()
	if len(rest) != 3 {
		fmt.Fprintln(os.Stderr, "usage: dop trust revoke [--all] [KIND VALUE SUBJECT]")
		fmt.Fprintln(os.Stderr, "  --all               drop every cached grant")
		fmt.Fprintln(os.Stderr, "  KIND VALUE SUBJECT  drop one specific grant (match the columns in `dop trust list`)")
		return 2
	}
	n, err := client.TrustContextRevoke(rest[0], rest[1], rest[2], false)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop trust revoke: %v\n", err)
		return 1
	}
	if n == 0 {
		fmt.Fprintf(os.Stderr, "dop trust revoke: no matching grant for %s/%s/%s\n", rest[0], rest[1], rest[2])
		return 1
	}
	fmt.Fprintf(os.Stderr, "dop trust revoke: dropped %d grant(s)\n", n)
	return 0
}

// runTrustContext prints what sessiontrust.Resolve returns for the
// current invocation. Useful for operators debugging "why does my
// approval keep re-prompting" without having to grep source.
func runTrustContext(args []string) int {
	// rc7i — thread userprefs.Harness through to the resolver so the
	// diagnostic matches what printguard sees.
	paths, _ := config.Resolve()
	if prefs := userprefs.Load(paths); prefs.Harness != "" {
		os.Setenv("DOP_HARNESS", userprefs.DOPHarnessEnvValue(prefs.Harness))
	}
	ctx := sessiontrust.Resolve()
	fmt.Fprintln(os.Stderr, "dop trust context (what this shell looks like to the trust cache):")
	fmt.Fprintf(os.Stderr, "  kind:        %s\n", ctx.Kind)
	fmt.Fprintf(os.Stderr, "  description: %s\n", ctx.Describe())
	fmt.Fprintln(os.Stderr, "  (the raw value is not printed — it may be an opaque session id.")
	fmt.Fprintln(os.Stderr, "   find the matching row in `dop trust list` to see the shortened form.)")
	return 0
}
