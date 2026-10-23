// `dop integration protect` — v1.21. Who may act on a protected
// integration. The admin who protected it stays the protector (Owner);
// this command adds or removes co-owners (Owners) and keeps the
// integration's grants in step. Any owner may run it; their own
// approval passphrase gates the change.

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/fray/dop/internal/audit"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

func runIntegrationProtect(args []string) int {
	fs := flag.NewFlagSet("integration protect", flag.ExitOnError)
	name := fs.String("name", "", "integration (required)")
	addCSV := fs.String("add-owner", "", "admins to add, comma-separated (team name or ed25519 pubkey prefix)")
	rmCSV := fs.String("remove-owner", "", "admins to remove, comma-separated")
	pfromStdin := fs.Bool("passphrase-stdin", false, "read the approval passphrase from stdin")
	_ = fs.Parse(args)
	if *name == "" {
		fmt.Fprintln(os.Stderr, "usage: dop integration protect --name N [--add-owner A,B] [--remove-owner C] [--passphrase-stdin]")
		return 2
	}
	paths, _ := config.Resolve()
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop integration protect: %v\n", err)
		return 1
	}
	v, vp, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop integration protect: %v\n", err)
		return 1
	}
	key, ok := v.FindIntegrationKey(*name)
	if !ok {
		fmt.Fprintf(os.Stderr, "dop integration protect: unknown integration %q\n", *name)
		return 1
	}
	integ := v.Integrations[key]
	if !integ.Protected {
		fmt.Fprintf(os.Stderr, "dop integration protect: %s is not protected — protect it first: dop integration add --name %s --protected\n", key, key)
		return 1
	}
	if err := requireProtectionOwner(client, "integration "+key, true, integ.OwnerSet()); err != nil {
		fmt.Fprintf(os.Stderr, "dop integration protect: %v\n", err)
		return 1
	}

	adds, rms := splitCSV(*addCSV), splitCSV(*rmCSV) // shared with token issue
	if len(adds) == 0 && len(rms) == 0 {
		fmt.Printf("%s is protected by %s\n", key, adminNames(v, integ.OwnerSet()))
		return 0
	}
	next := append([]string(nil), integ.Owners...)
	for _, ref := range adds {
		pub, err := resolveAdminRef(v, ref)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dop integration protect: %v\n", err)
			return 1
		}
		if !integ.OwnedBy(pub) && !ownedByList(next, pub) {
			next = append(next, pub)
		}
	}
	for _, ref := range rms {
		pub, err := resolveAdminRef(v, ref)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dop integration protect: %v\n", err)
			return 1
		}
		if strings.EqualFold(pub, integ.Owner) {
			fmt.Fprintf(os.Stderr, "dop integration protect: %s protected %s and cannot be removed — unprotect it instead (dop integration add --name %s --protected=false)\n", adminNames(v, []string{pub}), key, key)
			return 1
		}
		kept := next[:0]
		for _, o := range next {
			if !strings.EqualFold(o, pub) {
				kept = append(kept, o)
			}
		}
		next = kept
	}

	if err := promptProtectionPassphrase(paths, "approval passphrase (owners of "+key+"): ", *pfromStdin); err != nil {
		fmt.Fprintf(os.Stderr, "dop integration protect: %v\n", err)
		return 1
	}
	integ.Owners = next
	v.Integrations[key] = integ
	followed := 0
	for id, g := range v.Grants {
		if g.Integration == key && g.Protected && strings.EqualFold(g.Owner, integ.Owner) {
			g.Owners = append([]string(nil), next...)
			v.Grants[id] = g
			followed++
		}
	}
	if err := saveVaultViaDaemon(client, paths, vp, v); err != nil {
		fmt.Fprintf(os.Stderr, "dop integration protect: %v\n", err)
		return 1
	}
	audit.Append(paths, audit.Event{
		Kind:    audit.EventProtectedOwners,
		Subject: key,
		Extra: map[string]string{
			"owners":  strings.Join(integ.OwnerSet(), ","),
			"added":   strings.Join(adds, ","),
			"removed": strings.Join(rms, ","),
			"grants":  fmt.Sprintf("%d", followed),
		},
	})
	fmt.Fprintf(os.Stderr, "dop integration protect: %s is protected by %s (%d grant(s) follow)\n", key, adminNames(v, integ.OwnerSet()), followed)
	return 0
}

// resolveAdminRef turns a team name or an ed25519 pubkey prefix into
// the admin's pubkey. Ambiguous prefixes are refused.
func resolveAdminRef(v *vault.Vault, ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if a, ok := v.Admins[ref]; ok && a.Ed25519Pubkey != "" {
		return a.Ed25519Pubkey, nil
	}
	var hits []string
	for n, a := range v.Admins {
		if strings.EqualFold(n, ref) || (len(ref) >= 6 && strings.HasPrefix(strings.ToLower(a.Ed25519Pubkey), strings.ToLower(ref))) {
			hits = append(hits, a.Ed25519Pubkey)
		}
	}
	switch len(hits) {
	case 1:
		return hits[0], nil
	case 0:
		return "", fmt.Errorf("no admin %q in the team (dop team list)", ref)
	default:
		return "", fmt.Errorf("%q matches %d admins — use the name or a longer pubkey prefix", ref, len(hits))
	}
}

// adminNames renders pubkeys as team names where known, else a short
// pubkey; the first entry (the protector) is marked.
func adminNames(v *vault.Vault, pubs []string) string {
	byPub := map[string]string{}
	for n, a := range v.Admins {
		byPub[strings.ToLower(a.Ed25519Pubkey)] = n
	}
	var out []string
	for i, p := range pubs {
		n, ok := byPub[strings.ToLower(p)]
		if !ok {
			n = short(p) + "…"
		}
		if i == 0 {
			n += " (protector)"
		}
		out = append(out, n)
	}
	return strings.Join(out, ", ")
}

func ownedByList(owners []string, pub string) bool {
	for _, o := range owners {
		if strings.EqualFold(o, pub) {
			return true
		}
	}
	return false
}
