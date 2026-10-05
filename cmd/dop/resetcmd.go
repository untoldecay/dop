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
	// rc6n — total uninstall: additionally remove the dop binary from
	// the filesystem (not just the config state). Default off because
	// an operator running `dop admin reset` from a terminal usually
	// wants to re-init on the same binary. The TUI's Uninstall menu
	// item passes --purge because "uninstall" implies removal of
	// everything including the binary.
	purge := fs.Bool("purge", false, "also remove the dop binary from the filesystem (total uninstall; TUI uses this)")
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
	if *purge {
		fmt.Fprintf(os.Stderr, "  - %s  (binary — --purge)\n", binaryPath())
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
	if *purge {
		fmt.Fprintln(os.Stderr, "The `dop` binary at "+binaryPath()+" WILL be removed (--purge).")
	} else {
		fmt.Fprintln(os.Stderr, "The `dop` binary at "+binaryPath()+" is NOT removed (pass --purge to also wipe the binary).")
	}
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
	// rc6n — on --purge, also remove the binary itself. Unix lets us
	// unlink an open file (the inode stays live for any process that
	// holds it); the running process can finish printing before it
	// exits. Removal failure is non-fatal — the state wipe already
	// succeeded; print the sudo hint and return 0 anyway.
	if *purge {
		bin := binaryPath()
		if err := os.Remove(bin); err != nil {
			fmt.Fprintln(os.Stderr, "  ✓ done. State wiped.")
			fmt.Fprintf(os.Stderr, "  ! could not remove the dop binary at %s: %v\n", bin, err)
			fmt.Fprintf(os.Stderr, "    run manually: sudo rm %s\n", bin)
			return 0
		}
		fmt.Fprintln(os.Stderr, "  ✓ done. State + binary wiped — DOP is gone from this machine.")
		fmt.Fprintln(os.Stderr, "    re-install with the one-liner at https://github.com/untoldecay/dop")
		return 0
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
