// `dop integration add` — add or update a service definition in the vault.
// Admin-session required. This is the CLI path the TUI wraps.

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/fray/dop/internal/audit"
	"github.com/fray/dop/internal/capability"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/probe"
	"github.com/fray/dop/internal/vault"
)

// runIntegration is the subcommand dispatcher.
func runIntegration(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: dop integration <add|list|remove|remove-token|set-token>")
		return 2
	}
	switch args[0] {
	case "add":
		return runIntegrationAdd(args[1:])
	case "list":
		return runIntegrationList(args[1:])
	case "remove":
		return runIntegrationRemove(args[1:])
	case "remove-token":
		return runIntegrationRemoveToken(args[1:])
	case "set-token":
		return runIntegrationSetToken(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "dop integration: unknown subcommand %q\n", args[0])
		return 2
	}
}

func runIntegrationList(args []string) int {
	paths, _ := config.Resolve()
	// v1.13.0-rc7 — admin unlocks the full catalog. Bearers see only
	// integrations referenced by grants on their own capability.
	v, bearerLookup, isAdmin, err := loadVaultForListingWithBearer(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop integration list: %v\n", err)
		return 1
	}
	var allowed map[string]bool
	if !isAdmin {
		allowed = bearerIntegrationSet(v, bearerLookup)
		if len(allowed) == 0 {
			fmt.Println("(bearer references no integrations — or `dop admin login` for the full catalog)")
			return 0
		}
	}
	if len(v.Integrations) == 0 {
		fmt.Println("(no integrations)")
		return 0
	}
	names := make([]string, 0, len(v.Integrations))
	for n := range v.Integrations {
		if allowed != nil && !allowed[n] {
			continue
		}
		names = append(names, n)
	}
	sortStrings(names)
	for _, n := range names {
		integ := v.Integrations[n]
		desc := integ.Description
		if desc == "" {
			desc = "-"
		}
		// v1.13.0-rc12 — lock glyph + owner on protected rows so the
		// state is scannable from the CLI, parity with the TUI list.
		lock := ""
		if integ.Protected {
			owner := integ.Owner
			if len(owner) > 8 {
				owner = owner[:8] + "…"
			}
			lock = fmt.Sprintf(" 🔒 owner=%s", owner)
		}
		// v1.13.0-rc13 — kind prefix so operators scan what each row IS.
		kind := vault.IntegrationKindOf(integ)
		fmt.Printf("- [%s] %s  (%s)%s\n", kind, n, desc, lock)
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
	// v1.13.0-rc12 — refuse removal of a protected integration you
	// don't own. Catches the common case cleanly; the save-guard is
	// the belt-and-braces fallback for `vault edit` paths.
	existing := v.Integrations[key]
	if err := requireProtectionOwner(client, "integration "+key, existing.Protected, existing.Owner); err != nil {
		fmt.Fprintf(os.Stderr, "dop integration remove: %v\n", err)
		return 1
	}
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

// runIntegrationRemoveToken removes one or more tokens from a single
// integration and cascades through every grant that referenced those
// tokens (and every active capability whose Grants list touched those
// grants). Shape:
//
//   dop integration remove-token --name boiler --token pensieve --token writes
//     [--force-revoke-ed25519]
//
// If removing the selected tokens empties the integration, the
// integration is deleted too — a service entry with no credentials
// is useless.
func runIntegrationRemoveToken(args []string) int {
	fs := flag.NewFlagSet("integration remove-token", flag.ExitOnError)
	name := fs.String("name", "", "integration name (required)")
	var tokens stringSliceFlag
	fs.Var(&tokens, "token", "upstream token name to remove (repeatable, required)")
	forceRevokeEd25519 := fs.Bool("force-revoke-ed25519", false, "revoke ed25519 bearers whose bundle env can't be resealed")
	_ = fs.Parse(args)
	if *name == "" {
		fmt.Fprintln(os.Stderr, "dop integration remove-token: --name required")
		return 2
	}
	if len(tokens) == 0 {
		fmt.Fprintln(os.Stderr, "dop integration remove-token: at least one --token required")
		return 2
	}
	paths, _ := config.Resolve()
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop integration remove-token: %v\n", err)
		return 1
	}
	v, vaultPath, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop integration remove-token: %v\n", err)
		return 1
	}
	key, ok := v.FindIntegrationKey(*name)
	if !ok {
		fmt.Fprintf(os.Stderr, "dop integration remove-token: no integration named %q\n", *name)
		return 1
	}
	integ := v.Integrations[key]
	// v1.13.0-rc12 — refuse mutation on a protected integration you
	// don't own.
	if err := requireProtectionOwner(client, "integration "+key, integ.Protected, integ.Owner); err != nil {
		fmt.Fprintf(os.Stderr, "dop integration remove-token: %v\n", err)
		return 1
	}
	// Validate every requested token exists before mutating.
	missing := []string{}
	for _, tn := range tokens {
		if _, ok := integ.Tokens[tn]; !ok {
			missing = append(missing, tn)
		}
	}
	if len(missing) > 0 {
		fmt.Fprintf(os.Stderr, "dop integration remove-token: integration %q has no token(s): %v\n", key, missing)
		return 1
	}
	// Find grants that reference any (key, token) pair.
	tokenSet := map[string]bool{}
	for _, tn := range tokens {
		tokenSet[tn] = true
	}
	affectedGrants := []string{}
	for gid, g := range v.Grants {
		if g.Integration != key {
			if normalized, found := v.FindIntegrationKey(g.Integration); !found || normalized != key {
				continue
			}
		}
		if tokenSet[g.Token] {
			affectedGrants = append(affectedGrants, gid)
		}
	}
	// Cascade through capabilities.
	cascade, err := cascadeGrantRemoval(client, paths, v, affectedGrants, *forceRevokeEd25519)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop integration remove-token: cascade: %v\n", err)
		return 1
	}
	// Delete affected grants.
	for _, gid := range affectedGrants {
		delete(v.Grants, gid)
	}
	// Delete the tokens.
	for _, tn := range tokens {
		delete(integ.Tokens, tn)
	}
	// If no tokens remain, drop the integration entirely.
	integrationRemoved := false
	if len(integ.Tokens) == 0 {
		delete(v.Integrations, key)
		integrationRemoved = true
	} else {
		v.Integrations[key] = integ
	}
	if err := saveVaultViaDaemon(client, paths, vaultPath, v); err != nil {
		fmt.Fprintf(os.Stderr, "dop integration remove-token: %v\n", err)
		return 1
	}
	suffix := cascade.summary()
	if integrationRemoved {
		fmt.Fprintf(os.Stderr, "dop integration remove-token: removed %d token(s) from %q (integration had no remaining tokens — removed) · %d grant(s) dropped%s\n",
			len(tokens), key, len(affectedGrants), suffix)
	} else {
		fmt.Fprintf(os.Stderr, "dop integration remove-token: removed %d token(s) from %q · %d grant(s) dropped%s\n",
			len(tokens), key, len(affectedGrants), suffix)
	}
	return 0
}

// runIntegrationSetToken rotates a token's value and/or edits its
// scope note on an existing integration. Explicit "mutate a thing"
// counterpart to `integration add` which is really "create or merge."
// v1.13.0-rc16.
//
//	dop integration set-token --name <integ> --token-name <tok>
//	    [--value <new-value>] [--scope-note <new-scope>]
//
// At least one of --value / --scope-note is required. Omitting either
// leaves that field untouched. Owner-gated for protected integrations
// (same gate as other mutations). Emits EventIntegrationTokenSet with
// flags indicating what changed; NEVER logs the new value.
func runIntegrationSetToken(args []string) int {
	fs := flag.NewFlagSet("integration set-token", flag.ExitOnError)
	name := fs.String("name", "", "integration name (required)")
	tokenName := fs.String("token-name", "", "upstream token to mutate (required)")
	newValue := fs.String("value", "", "new value for the token (rotate). omit to leave unchanged.")
	newScope := fs.String("scope-note", "", "new scope note for the token. omit to leave unchanged.")
	valueStdin := fs.Bool("value-stdin", false, "read the new value from stdin instead of --value (used by TUI + scripts to keep secrets off the command line)")
	_ = fs.Parse(args)

	if *name == "" || *tokenName == "" {
		fmt.Fprintln(os.Stderr, "dop integration set-token: --name and --token-name are required")
		return 2
	}
	rotating := *newValue != "" || *valueStdin
	editingScope := fs.Lookup("scope-note").Value.String() != "" || hasFlagExplicit(fs, "scope-note")
	if !rotating && !editingScope {
		fmt.Fprintln(os.Stderr, "dop integration set-token: supply at least one of --value / --value-stdin / --scope-note")
		return 2
	}

	paths, _ := config.Resolve()
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop integration set-token: %v\n", err)
		return 1
	}
	v, vaultPath, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop integration set-token: %v\n", err)
		return 1
	}

	key, ok := v.FindIntegrationKey(*name)
	if !ok {
		fmt.Fprintf(os.Stderr, "dop integration set-token: no integration named %q\n", *name)
		return 1
	}
	integ := v.Integrations[key]
	// v1.13.0-rc12 — owner gate on protected integrations.
	if err := requireProtectionOwner(client, "integration "+key, integ.Protected, integ.Owner); err != nil {
		fmt.Fprintf(os.Stderr, "dop integration set-token: %v\n", err)
		return 1
	}
	tok, ok := integ.Tokens[*tokenName]
	if !ok {
		names := make([]string, 0, len(integ.Tokens))
		for k := range integ.Tokens {
			names = append(names, k)
		}
		fmt.Fprintf(os.Stderr, "dop integration set-token: integration %q has no token %q (has: %v)\n", key, *tokenName, names)
		return 1
	}

	// Resolve the new value — either flag or stdin.
	resolvedValue := *newValue
	if *valueStdin {
		stdinBytes, err := readValueStdin()
		if err != nil {
			fmt.Fprintf(os.Stderr, "dop integration set-token: read value from stdin: %v\n", err)
			return 1
		}
		resolvedValue = stdinBytes
		rotating = resolvedValue != ""
	}

	// Apply the mutation.
	rotated := rotating && resolvedValue != tok.Value
	scopeChanged := false
	if rotating {
		tok.Value = resolvedValue
	}
	if editingScope {
		if *newScope != tok.ScopeNote {
			scopeChanged = true
		}
		tok.ScopeNote = *newScope
	}
	if !rotated && !scopeChanged {
		fmt.Fprintln(os.Stderr, "dop integration set-token: nothing to change (value + scope unchanged)")
		return 0
	}
	integ.Tokens[*tokenName] = tok
	v.Integrations[key] = integ

	if err := saveVaultViaDaemon(client, paths, vaultPath, v); err != nil {
		fmt.Fprintf(os.Stderr, "dop integration set-token: %v\n", err)
		return 1
	}

	// Audit — never carries the value, only flags about what changed.
	audit.Append(paths, audit.Event{
		Kind:    audit.EventIntegrationTokenSet,
		Subject: key,
		Extra: map[string]string{
			"token":         *tokenName,
			"rotated":       boolStr(rotated),
			"scope_changed": boolStr(scopeChanged),
		},
	})

	parts := []string{}
	if rotated {
		parts = append(parts, "value rotated")
	}
	if scopeChanged {
		parts = append(parts, fmt.Sprintf("scope %q", tok.ScopeNote))
	}
	fmt.Fprintf(os.Stderr, "dop integration set-token: %s/%s → %s\n", key, *tokenName, strings.Join(parts, ", "))
	fmt.Fprintln(os.Stderr, "  bearers currently holding this token see the new value on their NEXT exec (direct availability) — or after `dop token reseal <subject>` for ed25519-bound bearers.")
	return 0
}

// readValueStdin reads a single line (sans trailing newline) from
// stdin. Used by set-token --value-stdin so the TUI can rotate a
// value without ever placing it on a command line.
func readValueStdin() (string, error) {
	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(data), "\r\n"), nil
}

// hasFlagExplicit reports whether a boolean/string flag was passed
// explicitly (vs just carrying its zero value). flag.FlagSet doesn't
// expose "was this set", so we walk the parsed set.
func hasFlagExplicit(fs *flag.FlagSet, name string) bool {
	found := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
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
	// v1.13.0-rc12 — protected credentials. Admin passphrase required
	// at save when set. Owner locked to current admin pubkey.
	protected := fs.Bool("protected", false, "mark this integration as owner-locked — only the current admin can modify it (requires approval passphrase)")
	passphraseStdin := fs.Bool("passphrase-stdin", false, "read the approval passphrase from stdin instead of the tty (used by scripts and TUI)")
	// v1.13.0-rc13 — kind + per-kind hint flags. These promote to
	// canonical env keys for the agent (see resolveGrantsToEnv).
	kind := fs.String("kind", "", "integration kind — api (default) · cli · mcp · other. Shapes the env bundle the agent sees.")
	endpointsURL := fs.String("endpoints-url", "", "api kind — URL where the service documents its endpoints (OpenAPI, discovery page, etc). Just a hint, DOP does not fetch it.")
	authHeader := fs.String("auth-header", "", "api kind — auth-header template, defaults to `Bearer` on the agent side.")
	cliCmd := fs.String("cmd", "", "cli kind — the binary name the agent should invoke (e.g. dop, boiler).")
	cliArgsHint := fs.String("args-hint", "", "cli kind — a free-form usage snippet surfaced to the agent (e.g. 'exec --inherit-env').")
	mcpURL := fs.String("mcp-url", "", "mcp kind — HTTP URL for the MCP server.")
	mcpCmd := fs.String("mcp-cmd", "", "mcp kind — stdio launcher command for the MCP server.")
	// v1.13.0-rc15 — opt-in endpoints-doc probe. OFF by default (DOP
	// never auto-fetches). When set + kind=api + no --endpoints-url,
	// try the common OpenAPI paths against --base-url and stamp the
	// first match. For kind=mcp + --mcp-url set, probe tools/list.
	probeEndpoints := fs.Bool("probe-endpoints", false, "opt-in: scan common OpenAPI paths (api) or tools/list (mcp) and stamp the result on the integration metadata. Short per-request timeout; never auto-run.")
	// v1.13.0-rc17 — 6 new advanced fields from the ClaudeMini field
	// report. All optional. cli_auth_env uses $TOKEN / $SERVER_ROOT /
	// $BASE_URL template substitution at env-resolve time.
	cliAuthEnv := fs.String("cli-auth-env", "", "cli kind — template of KEY=VAL pairs (semicolon-separated) exported DIRECTLY so the CLI picks up its own env names. Supports $TOKEN, $SERVER_ROOT, $BASE_URL substitution. Example: `BOILER_TOKEN=$TOKEN;BOILER_SERVER=$SERVER_ROOT`")
	serverRoot := fs.String("server-root", "", "any kind — server root distinct from base_url (common when base_url is an API path like `/admin/execute` but the CLI wants the root).")
	allowed := fs.String("allowed", "", "any kind — scope allowlist hint (free-form string, e.g. `Agent_Collab,Skills_Registry`). Non-enforced; agents read to avoid 403-probing.")
	authStyle := fs.String("auth-style", "", "api kind — auth-presentation hint, e.g. `bearer-header`, `basic`, `query-param`. Lets agents skip the auth-shape guess.")
	cliInstall := fs.String("cli-install", "", "cli kind — install hint for the binary (free-form, e.g. `go install github.com/you/mycli/cmd/mycli@latest`).")
	cliHelp := fs.String("cli-help", "", "cli kind — command the agent can run to self-discover the CLI (e.g. `mycli --help`).")
	_ = fs.Parse(args)

	if *name == "" {
		fmt.Fprintln(os.Stderr, "dop integration add: --name required")
		return 2
	}
	if *kind != "" && !vault.ValidIntegrationKind(*kind) {
		fmt.Fprintf(os.Stderr, "dop integration add: --kind %q is not one of api, cli, mcp, other\n", *kind)
		return 2
	}
	// v1.13.0-rc13 — --token is required for NEW integrations but
	// optional on updates (so operators can flip kind, add metadata,
	// or change endpoints-url on an existing one without re-stating
	// every token). The existence check happens below after the vault
	// loads; defer the validation until we know if the row exists.

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
	// v1.13.0-rc13 — kind-specific flags fold into metadata under their
	// canonical keys. These get promoted to typed env vars at resolve
	// time (see resolveGrantsToEnv / promotedMetadataKeys).
	if *endpointsURL != "" {
		meta["endpoints_url"] = *endpointsURL
	}
	if *authHeader != "" {
		meta["auth_header"] = *authHeader
	}
	if *cliCmd != "" {
		meta["cli_cmd"] = *cliCmd
	}
	if *cliArgsHint != "" {
		meta["cli_args_hint"] = *cliArgsHint
	}
	if *mcpURL != "" {
		meta["mcp_url"] = *mcpURL
	}
	if *mcpCmd != "" {
		meta["mcp_cmd"] = *mcpCmd
	}
	// v1.13.0-rc17 — advanced fields.
	if *cliAuthEnv != "" {
		meta["cli_auth_env"] = *cliAuthEnv
	}
	if *serverRoot != "" {
		meta["server_root"] = *serverRoot
	}
	if *allowed != "" {
		meta["allowed"] = *allowed
	}
	if *authStyle != "" {
		meta["auth_style"] = *authStyle
	}
	if *cliInstall != "" {
		meta["cli_install"] = *cliInstall
	}
	if *cliHelp != "" {
		meta["cli_help"] = *cliHelp
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
	if !exists && len(tokens) == 0 {
		fmt.Fprintln(os.Stderr, "dop integration add: at least one --token required when creating a new integration")
		return 2
	}
	action := "added"
	var existing vault.Integration
	if exists {
		action = "updated"
		existing = v.Integrations[key]
		// v1.13.0-rc12 — if the existing integration is protected,
		// only its owner can touch it. Refuse before any mutation.
		if err := requireProtectionOwner(client, "integration "+key, existing.Protected, existing.Owner); err != nil {
			fmt.Fprintf(os.Stderr, "dop integration add: %v\n", err)
			return 1
		}
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

	// v1.13.0-rc12 — protection claim path.
	// v1.14.0-rc3 — tri-state semantic for --protected:
	//   flag unset             → inherit existing.Protected
	//   --protected / =true    → set true (prompts passphrase; stamps owner)
	//   --protected=false      → set false (owner-only unlock path)
	// Previously the OR expression made --protected=false a no-op because
	// the Go flag parser can't distinguish "unset" from "set to false" on
	// a plain Bool. We walk fs.Visit to recover that distinction.
	protectedSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "protected" {
			protectedSet = true
		}
	})
	protect := existing.Protected
	if protectedSet {
		protect = *protected
	}
	owner := existing.Owner
	switch {
	case protect && !existing.Protected:
		// New lock or re-lock after unlock. Prompt passphrase + stamp owner.
		if err := promptProtectionPassphrase(paths, "approval passphrase (protect integration "+key+"): ", *passphraseStdin); err != nil {
			fmt.Fprintf(os.Stderr, "dop integration add: %v\n", err)
			return 1
		}
		st, err := client.Status()
		if err != nil {
			fmt.Fprintf(os.Stderr, "dop integration add: session: %v\n", err)
			return 1
		}
		owner = st.AdminPubkey
	case protect && existing.Protected:
		// Already-protected no-op (owner stays). enforceProtectedOnSave
		// would have refused us upstream if we weren't the owner.
	case !protect && existing.Protected:
		// Explicit unlock. enforceProtectedOnSave gates on ownership —
		// a non-owner's save attempt reverts and audits as bypass. Clear
		// the owner field so no stale pointer survives the flip.
		owner = ""
	}
	// v1.13.0-rc13 — mutable kind: explicit --kind wins; else keep the
	// existing stored kind; else fall through to empty, which readers
	// treat as api (IntegrationKindOf). An operator can flip kind by
	// passing --kind alone on an existing integration.
	effectiveKind := existing.Kind
	if *kind != "" {
		effectiveKind = *kind
	}

	// v1.13.0-rc15 — opt-in probe. Runs AFTER kind is resolved so we
	// know which kind of probe to try. Updates `meta` in place (adds
	// endpoints_url for api, or a boolean-ish mcp_probed_ok flag for
	// mcp). Never fatal: a failed probe still lets the add proceed
	// but emits an audit event with the failure cause.
	if *probeEndpoints {
		runProbe(paths, &meta, effectiveKind, key)
	}
	v.Integrations[key] = vault.Integration{
		Description: *desc,
		Metadata:    meta,
		Tokens:      parsedTokens,
		Protected:   protect,
		Owner:       owner,
		Kind:        effectiveKind,
	}

	if err := saveVaultViaDaemon(client, paths, vaultPath, v); err != nil {
		fmt.Fprintf(os.Stderr, "dop integration add: %v\n", err)
		return 1
	}
	// Audit the protection claim (only on flip or new-protected).
	if protect && !existing.Protected {
		logProtectedCreate(paths, "integration", key, owner)
	}
	// v1.14.0-rc3 — audit the inverse flip (unlock) so operators have
	// a trail. Fires only on an actual existing.Protected → false
	// transition, not on repeated --protected=false against an already
	// unprotected integration.
	if !protect && existing.Protected {
		audit.Append(paths, audit.Event{
			Kind:    audit.EventProtectedUnlock,
			Subject: key,
			Extra: map[string]string{
				"kind":        "integration",
				"prior_owner": existing.Owner,
			},
		})
	}
	// Surface the normalized key so operators learn the saved form.
	if key != *name {
		fmt.Fprintf(os.Stderr, "dop integration add: %s integration %q (saved as %q) with %d token(s)\n", action, *name, key, len(parsedTokens))
	} else {
		fmt.Fprintf(os.Stderr, "dop integration add: %s integration %q with %d token(s)\n", action, *name, len(parsedTokens))
	}
	return 0
}

// runProbe performs the opt-in endpoints-doc discovery for `integration add
// --probe-endpoints`. Updates meta in place with the resolved URL / outcome
// and emits an EventIntegrationProbed audit event. Non-fatal: a probe
// failure never blocks the save path — the integration is created either
// way and the operator can set --endpoints-url manually later.
func runProbe(paths *config.Paths, meta *map[string]string, kind, key string) {
	kindAPI := kind == "" || kind == vault.IntegrationKindAPI
	kindMCP := kind == vault.IntegrationKindMCP
	switch {
	case kindAPI:
		baseURL := (*meta)["base_url"]
		if baseURL == "" {
			fmt.Fprintln(os.Stderr, "dop integration add: --probe-endpoints skipped (no --base-url set)")
			return
		}
		if (*meta)["endpoints_url"] != "" {
			fmt.Fprintln(os.Stderr, "dop integration add: --probe-endpoints skipped (endpoints_url already set)")
			return
		}
		fmt.Fprintln(os.Stderr, "dop integration add: probing OpenAPI paths…")
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		res, err := probe.OpenAPI(ctx, baseURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "dop integration add: probe setup: %v\n", err)
			audit.Append(paths, audit.Event{
				Kind:    audit.EventIntegrationProbed,
				Subject: key,
				Extra:   map[string]string{"kind": "api", "result": "setup_error", "err": err.Error()},
			})
			return
		}
		if res.FoundURL != "" {
			(*meta)["endpoints_url"] = res.FoundURL
			(*meta)["endpoints_probed_at"] = time.Now().UTC().Format(time.RFC3339)
			fmt.Fprintf(os.Stderr, "dop integration add: probe → %s (%s)\n", res.FoundURL, res.Duration.Round(time.Millisecond))
			audit.Append(paths, audit.Event{
				Kind:    audit.EventIntegrationProbed,
				Subject: key,
				Extra:   map[string]string{"kind": "api", "result": "found", "endpoints_url": res.FoundURL},
			})
		} else {
			fmt.Fprintf(os.Stderr, "dop integration add: probe → no match on %d paths (%s). Set --endpoints-url manually if the service exposes a doc at a non-standard path.\n", len(res.Attempts), res.Duration.Round(time.Millisecond))
			audit.Append(paths, audit.Event{
				Kind:    audit.EventIntegrationProbed,
				Subject: key,
				Extra:   map[string]string{"kind": "api", "result": "no_match", "attempts": fmt.Sprintf("%d", len(res.Attempts))},
			})
		}
	case kindMCP:
		mcpURL := (*meta)["mcp_url"]
		if mcpURL == "" {
			fmt.Fprintln(os.Stderr, "dop integration add: --probe-endpoints skipped (mcp kind needs --mcp-url for probe)")
			return
		}
		fmt.Fprintln(os.Stderr, "dop integration add: probing MCP tools/list…")
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		res, _ := probe.MCPToolsList(ctx, mcpURL)
		if res.FoundURL != "" {
			(*meta)["mcp_probed_at"] = time.Now().UTC().Format(time.RFC3339)
			(*meta)["mcp_probe_result"] = "ok"
			fmt.Fprintf(os.Stderr, "dop integration add: probe → MCP tools/list responded (%s)\n", res.Duration.Round(time.Millisecond))
			audit.Append(paths, audit.Event{
				Kind:    audit.EventIntegrationProbed,
				Subject: key,
				Extra:   map[string]string{"kind": "mcp", "result": "ok", "mcp_url": mcpURL},
			})
		} else {
			errTxt := ""
			if len(res.Attempts) > 0 {
				errTxt = res.Attempts[0].ErrText
			}
			fmt.Fprintf(os.Stderr, "dop integration add: probe → MCP tools/list did not match (status=%d, err=%q)\n", res.Attempts[0].Status, errTxt)
			audit.Append(paths, audit.Event{
				Kind:    audit.EventIntegrationProbed,
				Subject: key,
				Extra:   map[string]string{"kind": "mcp", "result": "no_match", "err": errTxt},
			})
		}
	default:
		fmt.Fprintf(os.Stderr, "dop integration add: --probe-endpoints has no meaning for kind=%s\n", kind)
	}
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
	// v1.13.0-rc7 — admin session unlocks the full list. Non-admin
	// bearers see ONLY the grants their own capability references.
	v, bearerLookup, isAdmin, err := loadVaultForListingWithBearer(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop grant list: %v\n", err)
		return 1
	}
	var allowed map[string]bool
	if !isAdmin {
		allowed = bearerGrantSet(v, bearerLookup)
		if len(allowed) == 0 {
			fmt.Println("(bearer has no grants — or `dop admin login` for the full catalog)")
			return 0
		}
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
		// v1.13.0-rc7 — bearer-filtered: skip grants not on the
		// current bearer's capability.
		if allowed != nil && !allowed[id] {
			continue
		}
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
	forceRevokeEd25519 := fs.Bool("force-revoke-ed25519", false, "revoke ed25519 bearers whose bundle env can't be resealed (vs. the default: warn and leave stale)")
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
	existing, ok := v.Grants[*id]
	if !ok {
		fmt.Fprintf(os.Stderr, "dop grant remove: no grant named %q\n", *id)
		return 1
	}
	// v1.13.0-rc12 — refuse removal of a protected grant you don't own.
	if err := requireProtectionOwner(client, "grant "+*id, existing.Protected, existing.Owner); err != nil {
		fmt.Fprintf(os.Stderr, "dop grant remove: %v\n", err)
		return 1
	}
	// v1.13.0-rc8 — cascade: remove the grant from every active
	// capability that references it before deleting the grant itself.
	// P-256 bearers get EnvWrapped resealed with the narrower env;
	// ed25519 bearers get a warning (or revoke with --force-revoke-ed25519)
	// because their bundle env is bearer-encrypted and can't be rewritten
	// without the bearer.
	cascade, err := cascadeGrantRemoval(client, paths, v, []string{*id}, *forceRevokeEd25519)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop grant remove: cascade: %v\n", err)
		return 1
	}
	delete(v.Grants, *id)
	if err := saveVaultViaDaemon(client, paths, vp, v); err != nil {
		fmt.Fprintf(os.Stderr, "dop grant remove: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "dop grant remove: removed %s%s\n", *id, cascade.summary())
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
	// v1.14.0-rc3 — tri-state --protected, parallel to integration add.
	// Pins grant-level protection explicitly instead of relying only on
	// integration-level inheritance. See _rules/_plans/rc3-plan.md Phase 3.
	protected := fs.Bool("protected", false, "mark this grant as owner-locked — only the current admin can modify or issue tokens on it (requires approval passphrase)")
	passphraseStdin := fs.Bool("passphrase-stdin", false, "read the approval passphrase from stdin instead of the tty (used by scripts and TUI)")
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
	// v1.13.0-rc12 — if the parent integration is protected, only its
	// owner can create grants against it. (Someone else creating a
	// grant that references protected tokens is effectively exfiltrating
	// those tokens into their own bundle on next `token issue`.)
	if err := requireProtectionOwner(client, "integration "+integKey, integ.Protected, integ.Owner); err != nil {
		fmt.Fprintf(os.Stderr, "dop grant add: %v\n", err)
		return 1
	}

	if v.Grants == nil {
		v.Grants = map[string]vault.Grant{}
	}
	action := "added"
	var existingGrant vault.Grant
	if g, ok := v.Grants[*id]; ok {
		action = "updated"
		existingGrant = g
		// Can't update a protected grant you don't own.
		if err := requireProtectionOwner(client, "grant "+*id, g.Protected, g.Owner); err != nil {
			fmt.Fprintf(os.Stderr, "dop grant add: %v\n", err)
			return 1
		}
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
	// Protection resolution — grant-level is now independently settable
	// (v1.14.0-rc3), with integration-level inheritance kept as the
	// *default* for a new grant whose parent is protected.
	//
	// Rules:
	//   flag unset, new grant       → inherit from parent integration
	//   flag unset, existing grant  → preserve existing grant.Protected
	//   --protected / =true         → set true (prompts passphrase, stamps owner)
	//   --protected=false           → set false (owner-only unlock path)
	protectedSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "protected" {
			protectedSet = true
		}
	})
	var protect bool
	switch {
	case protectedSet:
		protect = *protected
	case action == "updated":
		protect = existingGrant.Protected
	default: // new grant, flag unset → inherit from integration
		protect = integ.Protected
	}
	owner := existingGrant.Owner
	if owner == "" {
		owner = integ.Owner
	}
	// Distinguish two "new lock" shapes:
	//   - Inheriting from a protected parent integration on create:
	//     owner is already proven at integration-level, no new passphrase.
	//   - Operator explicitly flipped grant to protected (--protected on
	//     an unprotected-integration grant, or on an existing grant with
	//     no prior lock): prompt passphrase + stamp current admin as owner.
	isNewLock := protect && !existingGrant.Protected
	inherited := isNewLock && integ.Protected && !protectedSet
	if isNewLock && !inherited {
		if err := promptProtectionPassphrase(paths, "approval passphrase (protect grant "+*id+"): ", *passphraseStdin); err != nil {
			fmt.Fprintf(os.Stderr, "dop grant add: %v\n", err)
			return 1
		}
		st, err := client.Status()
		if err != nil {
			fmt.Fprintf(os.Stderr, "dop grant add: session: %v\n", err)
			return 1
		}
		owner = st.AdminPubkey
	}
	// Explicit unlock: clear owner so no stale pointer survives the flip.
	// enforceProtectedOnSave upstream still gates on ownership for the
	// save itself, so non-owners can't reach this path.
	if !protect && existingGrant.Protected {
		owner = ""
	}
	v.Grants[*id] = vault.Grant{
		Integration: *integration,
		Token:       *token,
		EnvPrefix:   normalizedPrefix,
		Projects:    projects,
		Tags:        tags,
		Protected:   protect,
		Owner:       owner,
	}
	if err := saveVaultViaDaemon(client, paths, vp, v); err != nil {
		fmt.Fprintf(os.Stderr, "dop grant add: %v\n", err)
		return 1
	}
	// v1.14.0-rc3 — audit grant protection transitions symmetrically
	// with integration (contract 15, mirrors runIntegrationAdd).
	if protect && !existingGrant.Protected {
		logProtectedCreate(paths, "grant", *id, owner)
	}
	if !protect && existingGrant.Protected {
		audit.Append(paths, audit.Event{
			Kind:    audit.EventProtectedUnlock,
			Subject: *id,
			Extra: map[string]string{
				"kind":        "grant",
				"prior_owner": existingGrant.Owner,
			},
		})
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

// v1.13.0-rc7 — loadVaultForListingWithBearer unlocks the vault for a
// read-only listing operation, trying admin session first then
// falling back to the agent-side plaintext sidecar readable by any
// bearer. Returns the vault, the current bearer's lookupID (empty
// when admin), isAdmin flag, and any error. Non-admin callers use
// bearerGrantSet / bearerIntegrationSet to filter down to what their
// bearer's capability actually references.
func loadVaultForListingWithBearer(paths *config.Paths) (*vault.Vault, string, bool, error) {
	if client, err := requireAdminSession(paths); err == nil && client != nil {
		v, _, verr := loadVaultViaDaemon(client, paths)
		if verr != nil {
			return nil, "", false, verr
		}
		return v, "", true, nil
	}
	// Fall back to agent-side load (plaintext vault.yaml). This only
	// works on admin installs where the vault is already decrypted
	// AND on agent installs that keep a plaintext local copy.
	vp := paths.Vault + "/vault.yaml"
	v, err := vault.LoadPlain(vp)
	if err != nil {
		// v1.13.0-rc17 — ErrEncryptedVault means the vault is
		// SOPS-sealed and we have no admin session; return a clean
		// actionable message instead of leaking the YAML parser's
		// confusing "cannot parse ENC[...]" time-parse error.
		if errors.Is(err, vault.ErrEncryptedVault) {
			return nil, "", false, errors.New("vault is locked — run `dop admin login` (admin on this machine), OR set $DOP_TOKEN to a bearer to see what it has access to.\n  Non-admin inspection: `dop watch` tails the local audit log without needing an admin session.")
		}
		return nil, "", false, fmt.Errorf("not an admin session and vault not readable here (%w) — run `dop admin login` or set DOP_TOKEN", err)
	}
	// Compute bearer's lookupID.
	bearer, _, _ := readBearerWithSource("")
	if bearer == "" {
		return nil, "", false, errors.New("not an admin session and no DOP_TOKEN set — nothing to filter against")
	}
	ctxPath := paths.Vault + "/vault-context.bin"
	ctx, cerr := os.ReadFile(ctxPath)
	if cerr != nil {
		return nil, "", false, fmt.Errorf("no vault_context sidecar (%s): %w", ctxPath, cerr)
	}
	return v, capability.LookupID(ctx, bearer), false, nil
}

// bearerGrantSet returns the set of grant IDs the bearer's
// capability (if any) references. Used by `grant list` + `grant show`
// to filter non-admin output.
func bearerGrantSet(v *vault.Vault, bearerLookup string) map[string]bool {
	out := map[string]bool{}
	if bearerLookup == "" {
		return out
	}
	for _, c := range v.Capabilities {
		if c.LookupID != bearerLookup || c.Status != capability.RecordStatusActive {
			continue
		}
		for _, gid := range c.Grants {
			out[gid] = true
		}
	}
	return out
}

// bearerIntegrationSet returns the set of integration names the
// bearer's capability references via its grants.
func bearerIntegrationSet(v *vault.Vault, bearerLookup string) map[string]bool {
	allowedGrants := bearerGrantSet(v, bearerLookup)
	out := map[string]bool{}
	for gid := range allowedGrants {
		g, ok := v.Grants[gid]
		if !ok {
			continue
		}
		if key, found := v.FindIntegrationKey(g.Integration); found {
			out[key] = true
		}
	}
	return out
}

