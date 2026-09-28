// Stubs / minimal implementations for team + doctor + exec. Phase 4
// fleshes out `exec`; Phase 5 adds --security to doctor.

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

// --- dop team ---

func runTeam(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: dop team <add-key|list>")
		return 2
	}
	switch args[0] {
	case "add-key":
		return runTeamAddKey(args[1:])
	case "list":
		return runTeamList(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "dop team: unknown subcommand %q\n", args[0])
		return 2
	}
}

func runTeamAddKey(args []string) int {
	fs := flag.NewFlagSet("team add-key", flag.ExitOnError)
	name := fs.String("name", "", "human-readable admin label")
	pubkey := fs.String("pubkey", "", "age recipient (age1...)")
	ed25519pk := fs.String("ed25519", "", "admin ed25519 pubkey (optional; for signature verification)")
	note := fs.String("note", "", "note")
	_ = fs.Parse(args)

	if *name == "" || *pubkey == "" {
		fmt.Fprintln(os.Stderr, "dop team add-key: --name and --pubkey required")
		return 2
	}
	if !strings.HasPrefix(*pubkey, "age1") {
		fmt.Fprintln(os.Stderr, "dop team add-key: --pubkey must start with age1")
		return 2
	}
	paths, _ := config.Resolve()
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop team add-key: %v\n", err)
		return 1
	}
	v, vp, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop team add-key: %v\n", err)
		return 1
	}
	if v.Admins == nil {
		v.Admins = map[string]vault.Admin{}
	}
	v.Admins[*name] = vault.Admin{
		AgeRecipient:  *pubkey,
		Ed25519Pubkey: *ed25519pk,
		AddedAt:       time.Now().UTC().Truncate(time.Second),
		Note:          *note,
	}
	if err := saveVaultViaDaemon(client, paths, vp, v); err != nil {
		fmt.Fprintf(os.Stderr, "dop team add-key: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "dop team add-key: %s added as admin\n", *name)
	return 0
}

func runTeamList(args []string) int {
	paths, _ := config.Resolve()
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop team list: %v\n", err)
		return 1
	}
	v, _, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop team list: %v\n", err)
		return 1
	}
	if len(v.Admins) == 0 {
		fmt.Println("(no admins)")
		return 0
	}
	names := make([]string, 0, len(v.Admins))
	for n := range v.Admins {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		a := v.Admins[n]
		note := a.Note
		if note == "" {
			note = "-"
		}
		fmt.Printf("- %s  age=%s  ed25519=%s  note=%s\n", n, a.AgeRecipient, a.Ed25519Pubkey, note)
	}
	return 0
}

// --- dop doctor --- minimal until Phase 5.

func runDoctor(args []string) int {
	paths, _ := config.Resolve()
	// Basic checks — enough to prove a v1 install is coherent.
	fmt.Println("dop doctor:")
	adminOK := admin.KeyFileExists(paths)
	if adminOK {
		fmt.Println("  ✓ admin key present")
	} else {
		fmt.Println("  ! no admin key (agent install)")
	}
	vpath := vaultFilePath(paths)
	if _, err := os.Stat(vpath); err == nil {
		fmt.Println("  ✓ vault attached at", vpath)
	} else {
		fmt.Println("  ! no vault at", vpath)
	}
	c := admin.NewClient(admin.SockPath(paths))
	if c.SessionActive() {
		fmt.Println("  ✓ admin session active")
	} else {
		fmt.Println("  ⋯ admin session locked")
	}
	return 0
}

// hexEncodeBytes returns the lowercase hex of b. Used by tokencmd.
func hexEncodeBytes(b []byte) string { return hex.EncodeToString(b) }
