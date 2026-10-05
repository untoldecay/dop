// `dop admin reset` — v1.9.2. Wipes ALL local DOP state under the
// user's config root: admin keys, approval hash, vault clone,
// agent keys, gen-cache, pending files, audit log, credential map.
// The binary itself is NOT removed.
//
// Interactive by default: prints the exact paths that will be
// deleted and requires typing "RESET" to confirm.
// --force to skip the prompt (scripting).

package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/config"
)

func runAdminReset(args []string) int {
	fs := flag.NewFlagSet("admin reset", flag.ExitOnError)
	force := fs.Bool("force", false, "skip confirmation prompt")
	_ = fs.Parse(args)

	paths, err := config.Resolve()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop admin reset: %v\n", err)
		return 1
	}

	// Enumerate what will be deleted.
	victims := []string{paths.Root}
	fmt.Fprintln(os.Stderr, "dop admin reset will DELETE the following:")
	for _, p := range victims {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		fmt.Fprintf(os.Stderr, "  - %s\n", p)
	}
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "Contents that go away:")
	fmt.Fprintln(os.Stderr, "  · wrapped admin keys (admin.age.enc)")
	fmt.Fprintln(os.Stderr, "  · approval passphrase hash")
	fmt.Fprintln(os.Stderr, "  · vault clone (safe — encrypted at rest)")
	fmt.Fprintln(os.Stderr, "  · agent private keys (agent-keys/)")
	fmt.Fprintln(os.Stderr, "  · generation cache")
	fmt.Fprintln(os.Stderr, "  · pending PIN + remote claims + admin invites (local copies)")
	fmt.Fprintln(os.Stderr, "  · this machine's audit log")
	fmt.Fprintln(os.Stderr, "  · credential-map.yaml")
	fmt.Fprintln(os.Stderr, "  · DOP Claude Code skill + /dop-use command (loose files + plugin)")
	fmt.Fprintln(os.Stderr)
	fmt.Fprintln(os.Stderr, "The `dop` binary at "+binaryPath()+" is NOT removed.")
	fmt.Fprintln(os.Stderr, "Nothing on any OTHER admin machine is affected. If you had an")
	fmt.Fprintln(os.Stderr, "admin entry for this machine in the vault, run")
	fmt.Fprintln(os.Stderr, "  `dop team remove --name <label> --force`")
	fmt.Fprintln(os.Stderr, "from your other admin machine to prune it.")
	fmt.Fprintln(os.Stderr)

	// Stop the daemon if running (so the socket doesn't linger and so
	// deletion isn't fighting an open file handle).
	client := admin.NewClient(admin.SockPath(paths))
	if client.SessionActive() {
		fmt.Fprintln(os.Stderr, "Stopping active admin session first…")
		if err := client.Logout(); err != nil {
			fmt.Fprintf(os.Stderr, "  warning: logout: %v (continuing anyway)\n", err)
		}
	}

	if !*force {
		fmt.Fprint(os.Stderr, "Type RESET (all caps) to confirm: ")
		reader := bufio.NewReader(os.Stdin)
		line, _ := reader.ReadString('\n')
		if strings.TrimSpace(line) != "RESET" {
			fmt.Fprintln(os.Stderr, "dop admin reset: aborted (confirmation did not match).")
			return 1
		}
	}

	// rc7e — tear down the Claude Code plugin bundle + loose files
	// alongside the DOP state wipe. Best-effort; failures log but
	// don't block the main wipe below.
	uninstallPlugin()

	// Do the wipe.
	if err := os.RemoveAll(paths.Root); err != nil {
		fmt.Fprintf(os.Stderr, "dop admin reset: remove: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "  ✓ done. This machine is back to a fresh state.")
	fmt.Fprintln(os.Stderr, "    next: `dop admin init` (fresh admin) or `dop admin join <URL> <PIN>` (attach to a vault).")
	return 0
}

func binaryPath() string {
	self, err := os.Executable()
	if err != nil {
		return "<dop binary>"
	}
	return filepath.Clean(self)
}
