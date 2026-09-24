// Package resolve turns a bearer auth token into the env vars a child process
// should inherit. This is the core of the DOP scoping model.
package resolve

import (
	"fmt"
	"sort"
	"strings"

	"github.com/fray/dop/internal/vault"
)

// Resolution is the outcome of resolving a bearer token against a vault:
// which grants it unlocked, and which env vars the child should see.
type Resolution struct {
	TokenID     string
	AgentName   string
	GrantsUsed  []string
	Env         []string // "KEY=VALUE" pairs, ready for exec
}

// Resolve looks up a bearer token in the vault, walks its grants, and
// materializes the env vars from each grant's integration.
//
// Errors distinguish unknown-token (auth failure) from misconfigured-grant
// (vault integrity failure) so callers can log them differently.
func Resolve(v *vault.Vault, bearer string) (*Resolution, error) {
	if bearer == "" {
		return nil, fmt.Errorf("no bearer token provided (set $DOP_TOKEN)")
	}
	authTok, ok := v.AuthTokens[bearer]
	if !ok {
		return nil, fmt.Errorf("unknown auth token")
	}

	res := &Resolution{
		TokenID:    bearer,
		GrantsUsed: append([]string(nil), authTok.Grants...),
	}
	sort.Strings(res.GrantsUsed)

	// Env keyed by name for dedup / override semantics.
	// Later grants win on collision — flag when this happens.
	envMap := map[string]string{}
	var collisions []string

	for _, grantID := range authTok.Grants {
		g, ok := v.Grants[grantID]
		if !ok {
			return nil, fmt.Errorf("vault integrity: grant %q referenced by token but not defined", grantID)
		}
		integ, ok := v.Integrations[g.Integration]
		if !ok {
			return nil, fmt.Errorf("vault integrity: grant %q → integration %q not defined", grantID, g.Integration)
		}
		tok, ok := integ.Tokens[g.Token]
		if !ok {
			return nil, fmt.Errorf("vault integrity: grant %q → integration %q token %q not defined", grantID, g.Integration, g.Token)
		}

		prefix := g.EnvPrefix
		if prefix == "" {
			prefix = strings.ToUpper(g.Integration)
		}

		set := func(k, val string) {
			key := prefix + "_" + k
			if prev, exists := envMap[key]; exists && prev != val {
				collisions = append(collisions, key)
			}
			envMap[key] = val
		}

		set("TOKEN", tok.Value)
		for mk, mv := range integ.Metadata {
			set(strings.ToUpper(mk), mv)
		}
	}

	// Flatten envMap deterministically.
	keys := make([]string, 0, len(envMap))
	for k := range envMap {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		res.Env = append(res.Env, k+"="+envMap[k])
	}

	if len(collisions) > 0 {
		return res, fmt.Errorf("env collisions across grants (later grant wins): %s", strings.Join(collisions, ", "))
	}
	return res, nil
}
