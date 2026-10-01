// `dop integration add` — add or update a service definition in the vault.
// Admin-session required. This is the CLI path the TUI wraps.

package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/fray/dop/internal/capability"
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
	// v1.13.0-rc4 — normalize-aware lookup so "Notion" removes the
	// integration even when its stored key is "notion".
	key, ok := v.FindIntegrationKey(*name)
	if !ok {
		fmt.Fprintf(os.Stderr, "dop integration remove: no integration named %q\n", *name)
		return 1
	}
	*name = key
	// Check for referring grants (match both legacy verbatim refs and
	// post-rc4 normalized refs).
	referrers := []string{}
	for gid, g := range v.Grants {
		if g.Integration == *name || vault.NormalizeIntegrationName(g.Integration) == key {
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
	// v1.13.0-rc4 — MERGE into an existing integration if one by the
	// same name already exists. Pre-rc4, this path overwrote the whole
	// Integration struct (losing any previously-stored tokens that
	// weren't on the current command line). Field case: Cam added
	// "Notion" twice and lost the first add's tokens silently.
	//
	// Also normalizes the integration name: "Boiler Pensieve" → "boiler-pensieve",
	// "Notion" and "notion" collapse to the same key, no more invalid
	// chars propagating into derived env var names.
	//
	// New semantics:
	//   - metadata keys are UPDATED (new values win; untouched keys stay)
	//   - description is updated when non-empty (empty keeps existing)
	//   - tokens are merged by name (new values replace existing; untouched
	//     tokens stay). Removing a token still requires a separate
	//     `dop integration remove-token` (not yet added) or vault edit.
	key, exists := v.FindIntegrationKey(*name)
	action := "added"
	var existing vault.Integration
	if exists {
		action = "updated"
		existing = v.Integrations[key]
		// Merge metadata.
		if existing.Metadata != nil {
			for k, v := range existing.Metadata {
				if _, newer := meta[k]; !newer {
					meta[k] = v
				}
			}
		}
		// Merge tokens: new values win; untouched entries stay.
		if existing.Tokens != nil {
			for tn, tv := range existing.Tokens {
				if _, newer := parsedTokens[tn]; !newer {
					parsedTokens[tn] = tv
				}
			}
		}
		// Description: keep existing when new is empty.
		if *desc == "" {
			*desc = existing.Description
		}
	}
	v.Integrations[key] = vault.Integration{
		Description: *desc,
		Metadata:    meta,
		Tokens:      parsedTokens,
	}

	if err := saveVaultViaDaemon(client, paths, vaultPath, v); err != nil {
		fmt.Fprintf(os.Stderr, "dop integration add: %v\n", err)
		return 1
	}
	// Surface the normalized key so operators learn the saved form.
	if key != *name {
		fmt.Fprintf(os.Stderr, "dop integration add: %s integration %q (saved as %q) with %d token(s)\n", action, *name, key, len(parsedTokens))
	} else {
		fmt.Fprintf(os.Stderr, "dop integration add: %s integration %q with %d token(s)\n", action, *name, len(parsedTokens))
	}
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
	case "show":
		return runGrantShow(args[1:])
	case "remove":
		return runGrantRemove(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "dop grant: unknown subcommand %q\n", args[0])
		return 2
	}
}

// runGrantShow prints a single grant's details + every active token
// that references it. Read-only; add/remove token from this view is
// deferred to v1.12 (requires transparent bearer rotation).
func runGrantShow(args []string) int {
	fs := flag.NewFlagSet("grant show", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "emit JSON instead of human-readable")
	includeRevoked := fs.Bool("all", false, "also list revoked tokens (default: active only)")
	// Allow flag-after-positional (Go's stdlib parser doesn't by default).
	flagArgs, posArgs := splitFlagsAndPositionals(fs, args)
	_ = fs.Parse(flagArgs)
	if len(posArgs) != 1 {
		fmt.Fprintln(os.Stderr, "usage: dop grant show <grant-id> [--all] [--json]")
		return 2
	}
	gid := posArgs[0]

	paths, _ := config.Resolve()
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop grant show: %v\n", err)
		return 1
	}
	v, _, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop grant show: %v\n", err)
		return 1
	}
	g, ok := v.Grants[gid]
	if !ok {
		fmt.Fprintf(os.Stderr, "dop grant show: no grant named %q\n", gid)
		return 1
	}
	type tokView struct {
		CapID   string `json:"cap_id"`
		Subject string `json:"subject"`
		Status  string `json:"status"`
		Expires string `json:"expires"`
		Gen     uint64 `json:"generation"`
	}
	var toks []tokView
	for id, c := range v.Capabilities {
		found := false
		for _, cgid := range c.Grants {
			if cgid == gid {
				found = true
				break
			}
		}
		if !found {
			continue
		}
		if !*includeRevoked && c.Status != capability.RecordStatusActive {
			continue
		}
		toks = append(toks, tokView{
			CapID: id[:12], Subject: c.Subject, Status: c.Status,
			Expires: tokenExpiryDisplay(c.ExpiresAt), Gen: c.Generation,
		})
	}

	if *asJSON {
		emitJSON(map[string]any{
			"id":          gid,
			"integration": g.Integration,
			"token":       g.Token,
			"env_var":     g.EffectivePrefix() + "_TOKEN",
			"projects":    g.Projects,
			"tags":        g.Tags,
			"tokens":      toks,
		})
		return 0
	}
	fmt.Printf("grant:       %s\n", gid)
	fmt.Printf("integration: %s\n", g.Integration)
	fmt.Printf("token:       %s\n", g.Token)
	fmt.Printf("env_var:     %s_TOKEN\n", g.EffectivePrefix())
	if len(g.Projects) > 0 {
		fmt.Printf("projects:    %v\n", g.Projects)
	}
	if len(g.Tags) > 0 {
		fmt.Printf("tags:        %v\n", g.Tags)
	}
	fmt.Printf("tokens (%d)", len(toks))
	if !*includeRevoked {
		fmt.Print("  (active only — use --all to include revoked)")
	}
	fmt.Println(":")
	for _, t := range toks {
		fmt.Printf("  - %s  subject=%s  status=%s  gen=%d  expires=%s\n",
			t.CapID, t.Subject, t.Status, t.Gen, t.Expires)
	}
	return 0
}

func runGrantList(args []string) int {
	fs := flag.NewFlagSet("grant list", flag.ExitOnError)
	projectFilter := fs.String("project", "", "only show grants that belong to this project")
	tagFilter := fs.String("tag", "", "only show grants carrying this tag")
	_ = fs.Parse(args)

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

	// v1.8: group by project when no filter. A grant belonging to
	// multiple projects appears under each.
	buckets := map[string][]string{} // project → sorted grant IDs
	tag := strings.TrimSpace(*tagFilter)
	pf := strings.TrimSpace(*projectFilter)
	for id, g := range v.Grants {
		if tag != "" && !containsFold(g.Tags, tag) {
			continue
		}
		if pf != "" && !containsFold(g.Projects, pf) {
			continue
		}
		if len(g.Projects) == 0 {
			buckets[""] = append(buckets[""], id)
			continue
		}
		for _, p := range g.Projects {
			buckets[p] = append(buckets[p], id)
		}
	}
	if len(buckets) == 0 {
		fmt.Println("(no grants match)")
		return 0
	}
	projs := make([]string, 0, len(buckets))
	for p := range buckets {
		projs = append(projs, p)
	}
	sortStrings(projs)
	for _, p := range projs {
		if p == "" {
			fmt.Println("(ungrouped)")
		} else {
			fmt.Printf("project: %s\n", p)
		}
		ids := buckets[p]
		sortStrings(ids)
		for _, id := range ids {
			g := v.Grants[id]
			tagSuffix := ""
			if len(g.Tags) > 0 {
				tagSuffix = "  tags=[" + strings.Join(g.Tags, ",") + "]"
			}
			fmt.Printf("  - %s  → %s.%s  env=%s_TOKEN%s\n",
				id, g.Integration, g.Token, g.EffectivePrefix(), tagSuffix)
		}
	}
	return 0
}

// containsFold is case-insensitive slice membership.
func containsFold(hay []string, needle string) bool {
	for _, s := range hay {
		if strings.EqualFold(s, needle) {
			return true
		}
	}
	return false
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
	envPrefix := fs.String("env-prefix", "", "env var prefix (defaults to <INTEGRATION>_<TOKEN>, sanitized)")
	projectsCSV := fs.String("projects", "", "comma-separated project tags (cosmetic grouping; a grant can belong to multiple)")
	tagsCSV := fs.String("tags", "", "comma-separated free-form tags (e.g. read,write,admin)")
	_ = fs.Parse(args)

	if *id == "" || *integration == "" || *token == "" {
		fmt.Fprintln(os.Stderr, "dop grant add: --id, --integration, --token required")
		return 2
	}
	// v1.8: leave env_prefix empty on the record — EffectivePrefix()
	// derives <INTEGRATION>_<TOKEN> at resolution time. Only persist an
	// explicit value when the operator overrode the default.
	projects := splitCSV(*projectsCSV)
	tags := splitCSV(*tagsCSV)

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

	// v1.13.0-rc4 — resolve the integration key through FindIntegrationKey
	// so "Boiler Pensieve", "boiler-pensieve", "BOILER_PENSIEVE" all map to
	// the same stored integration. Also normalizes the stored
	// Grant.Integration reference so grants stay in sync with the key.
	integKey, ok := v.FindIntegrationKey(*integration)
	if !ok {
		fmt.Fprintf(os.Stderr, "dop grant add: unknown integration %q\n", *integration)
		return 1
	}
	integ := v.Integrations[integKey]
	*integration = integKey
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
	// v1.13.0-rc4 — sanitize --env-prefix at save time so the vault
	// stores the exact string that will become the env var at runtime.
	// Pre-rc4 the operator could set `--env-prefix "BOILER PENSIEVE"`
	// and the space would propagate into the resulting env var name.
	// EffectivePrefix() also sanitizes defensively but normalizing on
	// save keeps `dop grant show` honest about what will actually be
	// delivered.
	normalizedPrefix := *envPrefix
	if normalizedPrefix != "" {
		normalizedPrefix = vault.SanitizeEnvKey(normalizedPrefix)
	}
	v.Grants[*id] = vault.Grant{
		Integration: *integration,
		Token:       *token,
		EnvPrefix:   normalizedPrefix,
		Projects:    projects,
		Tags:        tags,
	}
	if err := saveVaultViaDaemon(client, paths, vp, v); err != nil {
		fmt.Fprintf(os.Stderr, "dop grant add: %v\n", err)
		return 1
	}
	// Preview what the child env will actually look like.
	effective := v.Grants[*id].EffectivePrefix()
	fmt.Fprintf(os.Stderr, "dop grant add: %s grant %q → %s.%s (env: %s_TOKEN)\n",
		action, *id, *integration, *token, effective)
	if len(projects) > 0 {
		fmt.Fprintf(os.Stderr, "  projects: %s\n", strings.Join(projects, ", "))
	}
	if len(tags) > 0 {
		fmt.Fprintf(os.Stderr, "  tags: %s\n", strings.Join(tags, ", "))
	}
	return 0
}

