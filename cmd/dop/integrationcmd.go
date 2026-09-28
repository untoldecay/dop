// `dop integration add` — add or update a service definition in the vault.
// Admin-session required. This is the CLI path the TUI wraps.

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

// runIntegration is the subcommand dispatcher.
func runIntegration(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: dop integration <add|list|remove>")
		return 2
	}
	switch args[0] {
	case "add":
		return runIntegrationAdd(args[1:])
	case "list":
		return runIntegrationList(args[1:])
	case "remove":
		return runIntegrationRemove(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "dop integration: unknown subcommand %q\n", args[0])
		return 2
	}
}

func runIntegrationList(args []string) int {
	paths, _ := config.Resolve()
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop integration list: %v\n", err)
		return 1
	}
	v, _, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop integration list: %v\n", err)
		return 1
	}
	if len(v.Integrations) == 0 {
		fmt.Println("(no integrations)")
		return 0
	}
	names := make([]string, 0, len(v.Integrations))
	for n := range v.Integrations {
		names = append(names, n)
	}
	sortStrings(names)
	for _, n := range names {
		integ := v.Integrations[n]
		desc := integ.Description
		if desc == "" {
			desc = "-"
		}
		fmt.Printf("- %s  (%s)\n", n, desc)
		for k, vv := range integ.Metadata {
			fmt.Printf("    %s: %s\n", k, vv)
		}
		toks := make([]string, 0, len(integ.Tokens))
		for tn := range integ.Tokens {
			toks = append(toks, tn)
		}
		sortStrings(toks)
		for _, tn := range toks {
			t := integ.Tokens[tn]
			// Never print value — just the scope note.
			note := t.ScopeNote
			if note == "" {
				note = "read-only"
			}
			fmt.Printf("    token %s: (%s)\n", tn, note)
		}
	}
	return 0
}

func runIntegrationRemove(args []string) int {
	fs := flag.NewFlagSet("integration remove", flag.ExitOnError)
	name := fs.String("name", "", "integration to remove (required)")
	force := fs.Bool("force", false, "remove even if grants reference it")
	_ = fs.Parse(args)
	if *name == "" {
		fmt.Fprintln(os.Stderr, "dop integration remove: --name required")
		return 2
	}
	paths, _ := config.Resolve()
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop integration remove: %v\n", err)
		return 1
	}
	v, vp, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop integration remove: %v\n", err)
		return 1
	}
	if _, ok := v.Integrations[*name]; !ok {
		fmt.Fprintf(os.Stderr, "dop integration remove: no integration named %q\n", *name)
		return 1
	}
	// Check for referring grants.
	referrers := []string{}
	for gid, g := range v.Grants {
		if g.Integration == *name {
			referrers = append(referrers, gid)
		}
	}
	if len(referrers) > 0 && !*force {
		fmt.Fprintf(os.Stderr, "dop integration remove: grants still reference %q: %v\n", *name, referrers)
		fmt.Fprintln(os.Stderr, "  Remove those grants first, or use --force to remove both.")
		return 1
	}
	delete(v.Integrations, *name)
	if *force {
		for _, gid := range referrers {
			delete(v.Grants, gid)
		}
	}
	if err := saveVaultViaDaemon(client, paths, vp, v); err != nil {
		fmt.Fprintf(os.Stderr, "dop integration remove: %v\n", err)
		return 1
	}
	msg := "removed"
	if len(referrers) > 0 {
		msg = fmt.Sprintf("removed (plus %d grants: %v)", len(referrers), referrers)
	}
	fmt.Fprintf(os.Stderr, "dop integration remove: %s %s\n", *name, msg)
	return 0
}

// sortStrings is a lightweight helper — kept local so we don't grow the
// import list for one function.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// stringSliceFlag is a flag that can be given multiple times.
type stringSliceFlag []string

func (s *stringSliceFlag) String() string     { return strings.Join(*s, ",") }
func (s *stringSliceFlag) Set(v string) error { *s = append(*s, v); return nil }

func runIntegrationAdd(args []string) int {
	fs := flag.NewFlagSet("integration add", flag.ExitOnError)
	name := fs.String("name", "", "integration name (required, e.g. notion)")
	desc := fs.String("description", "", "optional description")
	baseURL := fs.String("base-url", "", "optional base URL for the service")
	var tokens stringSliceFlag
	fs.Var(&tokens, "token", "upstream token in the form NAME=VALUE:SCOPE_NOTE (repeatable)")
	var metadata stringSliceFlag
	fs.Var(&metadata, "metadata", "extra metadata KEY=VALUE (repeatable)")
	_ = fs.Parse(args)

	if *name == "" {
		fmt.Fprintln(os.Stderr, "dop integration add: --name required")
		return 2
	}
	if len(tokens) == 0 {
		fmt.Fprintln(os.Stderr, "dop integration add: at least one --token required")
		return 2
	}

	paths, _ := config.Resolve()
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop integration add: %v\n", err)
		return 1
	}
	v, vaultPath, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop integration add: %v\n", err)
		return 1
	}

	// Parse tokens.
	parsedTokens := map[string]vault.Token{}
	for _, spec := range tokens {
		tn, tv, tnote, err := parseTokenSpec(spec)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dop integration add: --token %q: %v\n", spec, err)
			return 2
		}
		parsedTokens[tn] = vault.Token{Value: tv, ScopeNote: tnote}
	}

	// Parse metadata.
	meta := map[string]string{}
	if *baseURL != "" {
		meta["base_url"] = *baseURL
	}
	for _, m := range metadata {
		if i := strings.IndexByte(m, '='); i > 0 {
			meta[m[:i]] = m[i+1:]
		}
	}

	if v.Integrations == nil {
		v.Integrations = map[string]vault.Integration{}
	}
	action := "added"
	if _, exists := v.Integrations[*name]; exists {
		action = "updated"
	}
	v.Integrations[*name] = vault.Integration{
		Description: *desc,
		Metadata:    meta,
		Tokens:      parsedTokens,
	}

	if err := saveVaultViaDaemon(client, paths, vaultPath, v); err != nil {
		fmt.Fprintf(os.Stderr, "dop integration add: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "dop integration add: %s integration %q with %d token(s)\n", action, *name, len(parsedTokens))
	return 0
}

// parseTokenSpec splits `NAME=VALUE:SCOPE_NOTE` where SCOPE_NOTE is optional.
// If VALUE contains a colon (e.g. a URL), the LAST colon is the split point.
// Value cannot itself contain `=` before its first `=` separator — that's the
// name delimiter.
func parseTokenSpec(spec string) (name, value, scope string, err error) {
	eq := strings.IndexByte(spec, '=')
	if eq <= 0 {
		return "", "", "", fmt.Errorf("missing '=' between name and value")
	}
	name = spec[:eq]
	rest := spec[eq+1:]
	// Split VALUE:SCOPE on last colon so URLs (https:...) work.
	last := strings.LastIndex(rest, ":")
	if last < 0 {
		return name, rest, "read-only", nil
	}
	value = rest[:last]
	scope = rest[last+1:]
	// If SCOPE looks like a URL suffix (starts with digits like port), we
	// probably mis-split — fall back to no scope.
	if strings.ContainsAny(scope, "/@") {
		return name, rest, "read-only", nil
	}
	return name, value, scope, nil
}

// --- dop grant add ---

func runGrant(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: dop grant <add|list|remove>")
		return 2
	}
	switch args[0] {
	case "add":
		return runGrantAdd(args[1:])
	case "list":
		return runGrantList(args[1:])
	case "remove":
		return runGrantRemove(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "dop grant: unknown subcommand %q\n", args[0])
		return 2
	}
}

func runGrantList(args []string) int {
	paths, _ := config.Resolve()
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop grant list: %v\n", err)
		return 1
	}
	v, _, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop grant list: %v\n", err)
		return 1
	}
	if len(v.Grants) == 0 {
		fmt.Println("(no grants)")
		return 0
	}
	ids := make([]string, 0, len(v.Grants))
	for id := range v.Grants {
		ids = append(ids, id)
	}
	sortStrings(ids)
	for _, id := range ids {
		g := v.Grants[id]
		fmt.Printf("- %s  → %s.%s  env_prefix=%s\n", id, g.Integration, g.Token, g.EnvPrefix)
	}
	return 0
}

func runGrantRemove(args []string) int {
	fs := flag.NewFlagSet("grant remove", flag.ExitOnError)
	id := fs.String("id", "", "grant id to remove (required)")
	_ = fs.Parse(args)
	if *id == "" {
		fmt.Fprintln(os.Stderr, "dop grant remove: --id required")
		return 2
	}
	paths, _ := config.Resolve()
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop grant remove: %v\n", err)
		return 1
	}
	v, vp, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop grant remove: %v\n", err)
		return 1
	}
	if _, ok := v.Grants[*id]; !ok {
		fmt.Fprintf(os.Stderr, "dop grant remove: no grant named %q\n", *id)
		return 1
	}
	delete(v.Grants, *id)
	if err := saveVaultViaDaemon(client, paths, vp, v); err != nil {
		fmt.Fprintf(os.Stderr, "dop grant remove: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "dop grant remove: removed %s\n", *id)
	return 0
}

func runGrantAdd(args []string) int {
	fs := flag.NewFlagSet("grant add", flag.ExitOnError)
	id := fs.String("id", "", "grant id (required, e.g. notion.read)")
	integration := fs.String("integration", "", "integration name (required)")
	token := fs.String("token", "", "upstream token name (required)")
	envPrefix := fs.String("env-prefix", "", "env var prefix (defaults to uppercased integration name)")
	_ = fs.Parse(args)

	if *id == "" || *integration == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "dop grant add: --id, --integration, --token required")
		return 2
	}
	if *envPrefix == "" {
		*envPrefix = strings.ToUpper(*integration)
	}

	paths, _ := config.Resolve()
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop grant add: %v\n", err)
		return 1
	}
	v, vp, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop grant add: %v\n", err)
		return 1
	}

	// Validate integration + token exist.
	integ, ok := v.Integrations[*integration]
	if !ok {
		fmt.Fprintf(os.Stderr, "dop grant add: unknown integration %q\n", *integration)
		return 1
	}
	if _, ok := integ.Tokens[*token]; !ok {
		names := make([]string, 0, len(integ.Tokens))
		for k := range integ.Tokens {
			names = append(names, k)
		}
		fmt.Fprintf(os.Stderr, "dop grant add: integration %q has no token %q (has: %v)\n", *integration, *token, names)
		return 1
	}

	if v.Grants == nil {
		v.Grants = map[string]vault.Grant{}
	}
	action := "added"
	if _, ok := v.Grants[*id]; ok {
		action = "updated"
	}
	v.Grants[*id] = vault.Grant{
		Integration: *integration,
		Token:       *token,
		EnvPrefix:   *envPrefix,
	}
	if err := saveVaultViaDaemon(client, paths, vp, v); err != nil {
		fmt.Fprintf(os.Stderr, "dop grant add: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "dop grant add: %s grant %q → %s.%s (env prefix %s)\n", action, *id, *integration, *token, *envPrefix)
	return 0
}

