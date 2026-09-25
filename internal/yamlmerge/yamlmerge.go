// Package yamlmerge implements a three-way structural merge of YAML
// documents. Used by the SOPS-aware git merge driver.
//
// Semantics — for each leaf value keyed at the same path in base/ours/theirs:
//
//	base == ours == theirs   → keep any (unchanged)
//	base == ours             → theirs won (take theirs)
//	base == theirs           → ours won (take ours)
//	ours == theirs           → both made the same edit, no conflict
//	all three differ         → conflict
//
// Mappings recurse. Sequences (lists) are treated as opaque values — if both
// sides changed a list, that's a conflict; we do NOT attempt element-level
// merge because YAML sequences have no natural identity for members. If the
// vault ever grows a list-heavy shape we'll revisit.
//
// New keys added on one side are kept. Deletions on one side are respected
// only if the other side didn't modify the key (else conflict).
package yamlmerge

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Result carries the merged document plus any conflicts encountered. If
// Conflicts is non-empty, callers should treat the merge as failed (git
// merge driver returns non-zero, prints the conflict paths).
type Result struct {
	Merged    *yaml.Node
	Conflicts []string // dotted paths of conflict points
}

// Merge produces a three-way merge of base, ours, theirs. Any of the three
// may be nil (empty branch, deleted file); nil is treated as an empty
// mapping so a merge that adds keys still works.
func Merge(base, ours, theirs []byte) (*Result, error) {
	baseNode, err := parseDoc(base)
	if err != nil {
		return nil, fmt.Errorf("parse base: %w", err)
	}
	oursNode, err := parseDoc(ours)
	if err != nil {
		return nil, fmt.Errorf("parse ours: %w", err)
	}
	theirsNode, err := parseDoc(theirs)
	if err != nil {
		return nil, fmt.Errorf("parse theirs: %w", err)
	}

	merged, conflicts := mergeNode("", baseNode, oursNode, theirsNode)
	return &Result{Merged: merged, Conflicts: conflicts}, nil
}

// EmitBytes serializes a merged yaml.Node back to canonical YAML.
func EmitBytes(node *yaml.Node) ([]byte, error) {
	var doc yaml.Node
	if node.Kind == yaml.DocumentNode {
		doc = *node
	} else {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{node}}
	}
	var sb strings.Builder
	enc := yaml.NewEncoder(&sb)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}

func parseDoc(b []byte) (*yaml.Node, error) {
	if len(b) == 0 {
		// Empty document → empty mapping.
		return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}, nil
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	// Unwrap DocumentNode to its content root.
	if doc.Kind == yaml.DocumentNode && len(doc.Content) > 0 {
		return doc.Content[0], nil
	}
	// Genuinely empty (whitespace-only YAML)
	return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}, nil
}

// mergeNode is the recursive worker. Returns the merged node and any
// conflict paths accumulated below.
func mergeNode(path string, base, ours, theirs *yaml.Node) (*yaml.Node, []string) {
	// Normalize nils to empty mappings so downstream logic doesn't branch on nil.
	base = ifNilMap(base)
	ours = ifNilMap(ours)
	theirs = ifNilMap(theirs)

	// If ours and theirs are structurally identical, either side is fine.
	if nodesEqual(ours, theirs) {
		return ours, nil
	}
	// Only one side changed since base.
	if nodesEqual(base, ours) {
		return theirs, nil
	}
	if nodesEqual(base, theirs) {
		return ours, nil
	}

	// Both sides diverged from base. If both are mappings, recurse per key.
	if ours.Kind == yaml.MappingNode && theirs.Kind == yaml.MappingNode {
		return mergeMapping(path, base, ours, theirs)
	}

	// Non-mapping divergence = conflict.
	return ours, []string{path}
}

func mergeMapping(path string, base, ours, theirs *yaml.Node) (*yaml.Node, []string) {
	// Union of keys across the three nodes.
	keys := unionKeys(base, ours, theirs)

	out := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	var conflicts []string

	for _, k := range keys {
		bv := lookupMapValue(base, k)
		ov := lookupMapValue(ours, k)
		tv := lookupMapValue(theirs, k)

		// Handle presence/absence on each side. A key can be:
		//   - added on one side (bv nil, other side nil)  → additions merge in
		//   - deleted on one side (bv non-nil, that side nil)
		//   - present on all three                          → recurse
		if ov == nil && tv == nil {
			continue // absent from both (either deleted by both, or added-then-both-unaware)
		}
		if ov == nil { // absent from ours
			if bv == nil {
				// theirs added it; ours never saw it → accept theirs' addition
				out.Content = append(out.Content, keyNode(k), copyNode(tv))
				continue
			}
			// bv exists → ours deleted; conflict only if theirs modified
			if !nodesEqual(bv, tv) {
				conflicts = append(conflicts, childPath(path, k))
				out.Content = append(out.Content, keyNode(k), copyNode(tv))
			}
			continue
		}
		if tv == nil { // absent from theirs
			if bv == nil {
				// ours added; theirs never saw it → accept ours' addition
				out.Content = append(out.Content, keyNode(k), copyNode(ov))
				continue
			}
			// bv exists → theirs deleted; conflict only if ours modified
			if !nodesEqual(bv, ov) {
				conflicts = append(conflicts, childPath(path, k))
				out.Content = append(out.Content, keyNode(k), copyNode(ov))
			}
			continue
		}

		merged, subConflicts := mergeNode(childPath(path, k), bv, ov, tv)
		out.Content = append(out.Content, keyNode(k), merged)
		conflicts = append(conflicts, subConflicts...)
	}
	return out, conflicts
}

func unionKeys(nodes ...*yaml.Node) []string {
	seen := map[string]bool{}
	var order []string
	for _, n := range nodes {
		if n == nil || n.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i < len(n.Content); i += 2 {
			k := n.Content[i].Value
			if !seen[k] {
				seen[k] = true
				order = append(order, k)
			}
		}
	}
	return order
}

func lookupMapValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

func keyNode(k string) *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: k}
}

func childPath(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}

// nodesEqual compares two YAML nodes for structural equality on kind/tag/value.
// Position, comments, and line numbers are intentionally ignored.
func nodesEqual(a, b *yaml.Node) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if a.Kind != b.Kind {
		return false
	}
	// Scalar leaves compare by Value + Tag.
	if a.Kind == yaml.ScalarNode {
		return a.Value == b.Value && normTag(a.Tag) == normTag(b.Tag)
	}
	if len(a.Content) != len(b.Content) {
		return false
	}
	// For mappings, order-independent comparison.
	if a.Kind == yaml.MappingNode {
		for i := 0; i < len(a.Content); i += 2 {
			ka := a.Content[i].Value
			va := a.Content[i+1]
			vb := lookupMapValue(b, ka)
			if vb == nil {
				return false
			}
			if !nodesEqual(va, vb) {
				return false
			}
		}
		return true
	}
	// Sequences: order-sensitive.
	for i := range a.Content {
		if !nodesEqual(a.Content[i], b.Content[i]) {
			return false
		}
	}
	return true
}

func normTag(t string) string {
	// yaml.v3 sometimes uses !!str vs empty; treat empty scalar-tag as !!str.
	if t == "" {
		return "!!str"
	}
	return t
}

func ifNilMap(n *yaml.Node) *yaml.Node {
	if n == nil {
		return &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	}
	return n
}

func copyNode(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	c := *n
	if len(n.Content) > 0 {
		c.Content = make([]*yaml.Node, len(n.Content))
		for i := range n.Content {
			c.Content[i] = copyNode(n.Content[i])
		}
	}
	return &c
}
