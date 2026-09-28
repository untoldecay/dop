package views

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// injectIntegration mutates a plaintext-YAML vault tree in place, adding
// the new integration + its tokens, plus one grant per token following
// the convention `<integration>.<tokenName>` with env_prefix from fields.
//
// Lives in views/ so both AddIntegrationModel and future edit flows share
// the same shape.
func injectIntegration(root *yaml.Node, f addIntFields, tokens []tokenDraft) {
	top := rootMapping(root)
	integrations := ensureMapping(top, "integrations")

	// Build the integration entry.
	entry := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	appendKV(entry, "description", f.description)
	metadata := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	if f.baseURL != "" {
		appendKV(metadata, "base_url", f.baseURL)
	}
	entry.Content = append(entry.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "metadata"},
		metadata)

	tokensNode := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	for _, t := range tokens {
		tok := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		appendKV(tok, "value", t.value)
		note := t.scopeNote
		if note == "" {
			note = "read-only"
		}
		appendKV(tok, "scope_note", note)
		tokensNode.Content = append(tokensNode.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: t.name},
			tok)
	}
	entry.Content = append(entry.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "tokens"},
		tokensNode)

	// Add or replace under integrations.<name>.
	setMappingChild(integrations, f.name, entry)

	// Auto-grants: one per token, id = <integration>.<tokenName>.
	grants := ensureMapping(top, "grants")
	prefix := f.envPrefix
	if prefix == "" {
		prefix = strings.ToUpper(f.name)
	}
	for _, t := range tokens {
		g := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		appendKV(g, "integration", f.name)
		appendKV(g, "token", t.name)
		appendKV(g, "env_prefix", prefix)
		setMappingChild(grants, fmt.Sprintf("%s.%s", f.name, t.name), g)
	}
}

// --- generic yaml.Node helpers (mirrored from tokenio/teamops to avoid
// cross-package cycles; keep in sync when the schema changes) ---

func rootMapping(n *yaml.Node) *yaml.Node {
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		return n.Content[0]
	}
	return n
}

func mappingChild(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

func ensureMapping(m *yaml.Node, key string) *yaml.Node {
	if v := mappingChild(m, key); v != nil {
		return v
	}
	k := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	v := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	m.Content = append(m.Content, k, v)
	return v
}

// setMappingChild replaces the entry keyed by `key` with `val`, or appends
// if missing. Preserves order for updates.
func setMappingChild(m *yaml.Node, key string, val *yaml.Node) {
	for i := 0; i < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content[i+1] = val
			return
		}
	}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		val)
}

func appendKV(m *yaml.Node, key, val string) {
	if val == "" {
		return
	}
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: val})
}
