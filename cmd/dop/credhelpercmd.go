// `dop credential-helper map|list|remove` — manages the host→grant
// mapping consumed by `dop-credential-git` (and future shims).
//
// Stays in the primary `dop` binary so users get one CLI surface. The
// shim binary reads the same file.

package main

import (
	"flag"
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/credmap"
)

func runCredentialHelper(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: dop credential-helper <map|list|remove> ...")
		return 2
	}
	switch args[0] {
	case "map":
		return runCredMap(args[1:])
	case "list":
		return runCredList(args[1:])
	case "remove":
		return runCredRemove(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "dop credential-helper: unknown subcommand %q\n", args[0])
		return 2
	}
}

func runCredMap(args []string) int {
	fs := flag.NewFlagSet("credential-helper map", flag.ExitOnError)
	host := fs.String("host", "", "host to answer credential requests for (required)")
	grant := fs.String("grant", "", "grant id whose TOKEN env var should be returned (required)")
	username := fs.String("username", "dop", "username field returned to git")
	envPrefix := fs.String("env-prefix", "", "override auto-derived env prefix (rare)")
	_ = fs.Parse(args)

	if *host == "" || *grant == "" {
		fmt.Fprintln(os.Stderr, "dop credential-helper map: --host and --grant are required")
		return 2
	}
	paths, _ := config.Resolve()
	cmap, err := credmap.Load(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop credential-helper map: %v\n", err)
		return 1
	}
	replaced := cmap.Add(credmap.Entry{
		Host:      *host,
		Grant:     *grant,
		Username:  *username,
		EnvPrefix: *envPrefix,
	})
	if err := credmap.Save(paths, cmap); err != nil {
		fmt.Fprintf(os.Stderr, "dop credential-helper map: %v\n", err)
		return 1
	}
	verb := "added"
	if replaced {
		verb = "updated"
	}
	fmt.Fprintf(os.Stderr, "dop credential-helper: %s %s → %s (username=%s)\n",
		verb, *host, *grant, *username)
	fmt.Fprintf(os.Stderr, "  to wire into git: git config --global credential.helper 'dop-credential-git'\n")
	return 0
}

func runCredList(args []string) int {
	_ = args
	paths, _ := config.Resolve()
	cmap, err := credmap.Load(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop credential-helper list: %v\n", err)
		return 1
	}
	if len(cmap.Entries) == 0 {
		fmt.Println("(no credential-helper mappings)")
		return 0
	}
	entries := make([]credmap.Entry, len(cmap.Entries))
	copy(entries, cmap.Entries)
	sort.Slice(entries, func(i, j int) bool { return entries[i].Host < entries[j].Host })

	w := tabwriter.NewWriter(os.Stdout, 2, 4, 2, ' ', 0)
	fmt.Fprintln(w, "HOST\tGRANT\tUSERNAME\tPREFIX")
	for _, e := range entries {
		prefix := e.EnvPrefix
		if prefix == "" {
			prefix = "(auto)"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", e.Host, e.Grant, e.Username, prefix)
	}
	_ = w.Flush()
	return 0
}

func runCredRemove(args []string) int {
	fs := flag.NewFlagSet("credential-helper remove", flag.ExitOnError)
	host := fs.String("host", "", "host to remove (required)")
	_ = fs.Parse(args)
	if *host == "" {
		fmt.Fprintln(os.Stderr, "dop credential-helper remove: --host required")
		return 2
	}
	paths, _ := config.Resolve()
	cmap, err := credmap.Load(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop credential-helper remove: %v\n", err)
		return 1
	}
	if !cmap.Remove(*host) {
		fmt.Fprintf(os.Stderr, "dop credential-helper remove: no mapping for %s\n", *host)
		return 1
	}
	if err := credmap.Save(paths, cmap); err != nil {
		fmt.Fprintf(os.Stderr, "dop credential-helper remove: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "dop credential-helper remove: removed %s\n", *host)
	return 0
}
