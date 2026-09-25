// Package teamops handles team-member (SOPS recipient) lifecycle.
//
// The vault stores members under `team_members.<name>.pubkey_age`. The
// canonical age-recipient list for encryption is `.sops.yaml` in the vault
// clone. Both are kept in sync by add-key and remove.
package teamops

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

// SopsConfig is the on-disk shape of `.sops.yaml`. We keep only the fields
// we mutate; unknown fields round-trip through yaml.Node preservation.
type SopsConfig struct {
	CreationRules []SopsRule `yaml:"creation_rules"`
}

type SopsRule struct {
	PathRegex string `yaml:"path_regex"`
	Age       string `yaml:"age"` // comma-separated recipient list
}

// ReadSopsConfig loads `.sops.yaml` from vaultDir. Missing file → empty config.
func ReadSopsConfig(vaultDir string) (*SopsConfig, error) {
	path := filepath.Join(vaultDir, ".sops.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &SopsConfig{}, nil
		}
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var cfg SopsConfig
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &cfg, nil
}

// WriteSopsConfig writes cfg back to `.sops.yaml`.
func WriteSopsConfig(vaultDir string, cfg *SopsConfig) error {
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(cfg); err != nil {
		return err
	}
	enc.Close()
	return os.WriteFile(filepath.Join(vaultDir, ".sops.yaml"), buf.Bytes(), 0o644)
}

// AddRecipient appends pubkey to cfg's age recipient list on all creation
// rules. Idempotent: does nothing if pubkey is already present.
// Returns true if a change happened.
func AddRecipient(cfg *SopsConfig, pubkey string) bool {
	changed := false
	for i := range cfg.CreationRules {
		existing := splitCSV(cfg.CreationRules[i].Age)
		if contains(existing, pubkey) {
			continue
		}
		existing = append(existing, pubkey)
		sort.Strings(existing)
		cfg.CreationRules[i].Age = joinCSV(existing)
		changed = true
	}
	return changed
}

// RemoveRecipient drops pubkey from cfg's age recipient list.
// Returns true if a change happened.
func RemoveRecipient(cfg *SopsConfig, pubkey string) bool {
	changed := false
	for i := range cfg.CreationRules {
		existing := splitCSV(cfg.CreationRules[i].Age)
		filtered := existing[:0]
		for _, r := range existing {
			if r != pubkey {
				filtered = append(filtered, r)
			}
		}
		if len(filtered) != len(existing) {
			cfg.CreationRules[i].Age = joinCSV(filtered)
			changed = true
		}
	}
	return changed
}

// SopsUpdatekeys reruns `sops updatekeys` on the vault file so newly-added
// recipients can decrypt existing ciphertext (and removed recipients lose
// forward access — historical git ciphertext is still readable by them
// with their old key; that's the rotation-required story).
//
// Runs with `--yes` to skip interactive confirmation; the caller is
// already through their own confirmation. We cd into the vault dir so
// sops finds .sops.yaml via its normal config-walk rules — passing an
// absolute path alone isn't enough (config lookup is CWD-anchored).
func SopsUpdatekeys(vaultFile string, out io.Writer) error {
	vaultDir := filepath.Dir(vaultFile)
	base := filepath.Base(vaultFile)
	cmd := exec.Command("sops", "updatekeys", "--yes", base)
	cmd.Dir = vaultDir
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sops updatekeys: %w", err)
	}
	return nil
}

// RotationChecklist enumerates upstream tokens that must be rotated after
// removing `who`. Since a removed member with their historical age key can
// still decrypt any pre-removal ciphertext they cloned, every upstream token
// stored in the vault is compromised until rotated.
type RotationChecklist struct {
	Member string
	Items  []RotationItem
}

type RotationItem struct {
	Integration string
	Token       string   // name of the upstream token within integration.tokens
	ScopeNote   string   // for context in the human-facing output
	Grants      []string // grants that use this integration.token pair
}

// BuildChecklist walks the vault and produces one item per
// (integration, upstream-token) pair, decorated with the grants that use it.
func BuildChecklist(root *yaml.Node, member string) *RotationChecklist {
	top := rootMapping(root)
	integrations := mappingChild(top, "integrations")
	grants := mappingChild(top, "grants")
	if integrations == nil {
		return &RotationChecklist{Member: member}
	}
	// Build grants-by-(integ,token) index
	grantsByTuple := map[string][]string{}
	if grants != nil {
		for i := 0; i < len(grants.Content); i += 2 {
			gname := grants.Content[i].Value
			g := grants.Content[i+1]
			ig := scalarOr(g, "integration", "")
			tk := scalarOr(g, "token", "")
			key := ig + "\x00" + tk
			grantsByTuple[key] = append(grantsByTuple[key], gname)
		}
	}
	var out RotationChecklist
	out.Member = member
	for i := 0; i < len(integrations.Content); i += 2 {
		iname := integrations.Content[i].Value
		integ := integrations.Content[i+1]
		tokens := mappingChild(integ, "tokens")
		if tokens == nil {
			continue
		}
		for j := 0; j < len(tokens.Content); j += 2 {
			tname := tokens.Content[j].Value
			tok := tokens.Content[j+1]
			out.Items = append(out.Items, RotationItem{
				Integration: iname,
				Token:       tname,
				ScopeNote:   scalarOr(tok, "scope_note", ""),
				Grants:      grantsByTuple[iname+"\x00"+tname],
			})
		}
	}
	return &out
}

// PrintChecklist emits a human-readable rotation checklist to out.
func (c *RotationChecklist) Print(out io.Writer) {
	fmt.Fprintf(out, "\n⚠  Removing member %q — rotate the following upstream tokens NOW:\n\n", c.Member)
	fmt.Fprintln(out, "  Any cached git ciphertext they cloned before removal is still decryptable")
	fmt.Fprintln(out, "  with their old age key. Every token below must be rotated at the upstream")
	fmt.Fprintln(out, "  service, then updated in the vault via `sops <vault.yaml>` or `dop token issue`.")
	fmt.Fprintln(out)
	for _, it := range c.Items {
		fmt.Fprintf(out, "  - %s.tokens.%s  (%s)\n", it.Integration, it.Token, it.ScopeNote)
		if len(it.Grants) > 0 {
			fmt.Fprintf(out, "      used by grants: %v\n", it.Grants)
		}
	}
	fmt.Fprintln(out)
	fmt.Fprintln(out, "After rotating: `dop pull` on every teammate machine.")
}

// --- yaml.Node helpers (mirrored from tokenio for package boundaries) ---

func rootMapping(root *yaml.Node) *yaml.Node {
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		return root.Content[0]
	}
	return root
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

func scalarOr(m *yaml.Node, key, def string) string {
	if v := mappingChild(m, key); v != nil && v.Kind == yaml.ScalarNode {
		return v.Value
	}
	return def
}

// EnsureTeamMember mutates the vault tree to add/update a team_members entry.
// Overwrites an existing entry with the same name.
func EnsureTeamMember(root *yaml.Node, name, pubkey, note, addedBy string) {
	top := rootMapping(root)
	tm := mappingChild(top, "team_members")
	if tm == nil {
		tm = &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		top.Content = append(top.Content,
			&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "team_members"},
			tm)
	}
	// Remove any existing entry
	for i := 0; i < len(tm.Content); i += 2 {
		if tm.Content[i].Value == name {
			tm.Content = append(tm.Content[:i], tm.Content[i+2:]...)
			break
		}
	}
	entry := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	appendKV(entry, "pubkey_age", pubkey)
	appendKV(entry, "added_at", time.Now().UTC().Format("2006-01-02"))
	if addedBy != "" {
		appendKV(entry, "added_by", addedBy)
	}
	if note != "" {
		appendKV(entry, "note", note)
	}
	tm.Content = append(tm.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: name},
		entry)
}

// RemoveTeamMember returns the pubkey of the removed member (empty if not
// found) so callers can update .sops.yaml recipients too.
func RemoveTeamMember(root *yaml.Node, name string) string {
	top := rootMapping(root)
	tm := mappingChild(top, "team_members")
	if tm == nil {
		return ""
	}
	for i := 0; i < len(tm.Content); i += 2 {
		if tm.Content[i].Value == name {
			pubkey := scalarOr(tm.Content[i+1], "pubkey_age", "")
			tm.Content = append(tm.Content[:i], tm.Content[i+2:]...)
			return pubkey
		}
	}
	return ""
}

func appendKV(m *yaml.Node, key, val string) {
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: val})
}

// --- small string utilities ---

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, p := range splitByComma(s) {
		p = trim(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func joinCSV(xs []string) string {
	// Deliberately no spaces after commas — matches what sops emits.
	s := ""
	for i, x := range xs {
		if i > 0 {
			s += ","
		}
		s += x
	}
	return s
}

func splitByComma(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ',' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	out = append(out, s[start:])
	return out
}

func trim(s string) string {
	i, j := 0, len(s)
	for i < j && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n') {
		i++
	}
	for j > i && (s[j-1] == ' ' || s[j-1] == '\t' || s[j-1] == '\n') {
		j--
	}
	return s[i:j]
}

func contains(xs []string, y string) bool {
	for _, x := range xs {
		if x == y {
			return true
		}
	}
	return false
}
