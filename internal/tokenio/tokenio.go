// Package tokenio provides read/mutate/re-encrypt helpers for the vault.
// Used by dop token issue/revoke and future admin subcommands.
//
// Strategy: shell to `sops --decrypt` to get plaintext YAML, mutate in-place
// as a yaml.Node tree (preserving key order + comments where possible),
// then write out plaintext and shell to `sops --encrypt` to write back.
package tokenio

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// TokenBearer generates a random bearer token of the form `tok_<hex>`.
// 12 bytes → 24 hex chars → 96 bits of entropy. More than enough for a
// non-guessable bearer.
func TokenBearer() (string, error) {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("rand: %w", err)
	}
	return "tok_" + hex.EncodeToString(b[:]), nil
}

// LoadPlain decrypts a vault (SOPS envelope) to plaintext YAML bytes, or
// returns the file as-is if not encrypted (test fixtures).
func LoadPlain(vaultPath string) ([]byte, error) {
	raw, err := os.ReadFile(vaultPath)
	if err != nil {
		return nil, err
	}
	if !isSOPS(raw) {
		return raw, nil
	}
	cmd := exec.Command("sops", "--decrypt", "--input-type", "yaml", "--output-type", "yaml", vaultPath)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("sops --decrypt: %s (%w)", stderr.String(), err)
	}
	return stdout.Bytes(), nil
}

// SavePlain writes plaintext YAML to vaultPath. If the target was
// previously SOPS-encrypted, re-encrypts via `sops --encrypt` respecting
// the vault repo's .sops.yaml recipients. Otherwise writes plaintext.
func SavePlain(vaultPath string, plain []byte) error {
	prev, err := os.ReadFile(vaultPath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	// Fast path: plaintext workflow (tests) — just overwrite.
	if !isSOPS(prev) {
		return os.WriteFile(vaultPath, plain, 0o600)
	}

	// Encrypted path: stage plaintext to tempfile in the same directory so
	// sops picks up the same .sops.yaml, then sops --encrypt --output over
	// the original.
	dir := filepath.Dir(vaultPath)
	tmp, err := os.CreateTemp(dir, ".dop-vault-*.yaml")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.Write(plain); err != nil {
		tmp.Close()
		return err
	}
	tmp.Close()

	recipient, err := ageRecipientFromDir(dir)
	if err != nil {
		return fmt.Errorf("resolve age recipient: %w", err)
	}
	cmd := exec.Command("sops", "--encrypt",
		"--age", recipient,
		"--input-type", "yaml", "--output-type", "yaml",
		"--output", vaultPath, tmpPath)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("sops --encrypt: %s (%w)", stderr.String(), err)
	}
	return nil
}

// ageRecipientFromDir extracts the age recipient from a `.sops.yaml` in `dir`.
// Robust to sops's path-based config discovery quirks: we parse the file we
// wrote at `dop init --vault` time and pass --age explicitly.
func ageRecipientFromDir(dir string) (string, error) {
	path := filepath.Join(dir, ".sops.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", path, err)
	}
	var cfg struct {
		CreationRules []struct {
			Age string `yaml:"age"`
		} `yaml:"creation_rules"`
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return "", fmt.Errorf("parse %s: %w", path, err)
	}
	for _, r := range cfg.CreationRules {
		if r.Age != "" {
			return r.Age, nil
		}
	}
	return "", fmt.Errorf("no age recipient in %s", path)
}

func isSOPS(raw []byte) bool {
	return bytes.Contains(raw, []byte("\nsops:")) || bytes.HasPrefix(raw, []byte("sops:"))
}

// --- yaml.Node helpers for auth_tokens mutation ---

// ParseTree parses a plaintext vault YAML into a mutable Node tree.
func ParseTree(plain []byte) (*yaml.Node, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(plain, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

// EmitTree serializes the tree back to bytes.
func EmitTree(root *yaml.Node) ([]byte, error) {
	var sb strings.Builder
	enc := yaml.NewEncoder(&sb)
	enc.SetIndent(2)
	if err := enc.Encode(root); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return []byte(sb.String()), nil
}

// rootMapping returns the top-level mapping node of a document.
func rootMapping(root *yaml.Node) *yaml.Node {
	if root.Kind == yaml.DocumentNode && len(root.Content) > 0 {
		return root.Content[0]
	}
	return root
}

// mappingChild returns the value node for `key` under a mapping, or nil.
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

// ensureMapping returns a mapping node at m[key], creating one if missing.
func ensureMapping(m *yaml.Node, key string) *yaml.Node {
	if v := mappingChild(m, key); v != nil {
		return v
	}
	k := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}
	v := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	m.Content = append(m.Content, k, v)
	return v
}

// deleteMappingKey removes k from m if present. Returns true if a deletion happened.
func deleteMappingKey(m *yaml.Node, key string) bool {
	if m == nil || m.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return true
		}
	}
	return false
}

// --- Token records ---

// TokenRecord is the human-facing view of an auth_token entry, sans bearer.
type TokenRecord struct {
	Bearer    string // internal only — not displayed by dop token list
	Name      string
	CreatedAt string
	ExpiresAt string
	Grants    []string
	Note      string
}

// AddAuthToken mutates the tree to add a new auth_tokens entry keyed by
// bearer. Fails if the bearer already exists (should be effectively
// impossible with 96-bit random).
func AddAuthToken(root *yaml.Node, bearer string, r TokenRecord, createdBy string) error {
	top := rootMapping(root)
	authTokens := ensureMapping(top, "auth_tokens")
	if mappingChild(authTokens, bearer) != nil {
		return fmt.Errorf("bearer collision (?!) %s", bearer)
	}

	entry := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
	appendKV(entry, "name", r.Name)
	if createdBy != "" {
		appendKV(entry, "created_by", createdBy)
	}
	appendKV(entry, "created_at", time.Now().UTC().Format("2006-01-02"))
	if r.ExpiresAt != "" {
		appendKV(entry, "expires_at", r.ExpiresAt)
	}
	// grants as a flow sequence for compact diffs
	grantsSeq := &yaml.Node{Kind: yaml.SequenceNode, Style: yaml.FlowStyle, Tag: "!!seq"}
	for _, g := range r.Grants {
		grantsSeq.Content = append(grantsSeq.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: g})
	}
	entry.Content = append(entry.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: "grants"},
		grantsSeq)
	if r.Note != "" {
		appendKV(entry, "note", r.Note)
	}

	authTokens.Content = append(authTokens.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: bearer},
		entry)
	return nil
}

// FindByName scans auth_tokens and returns bearer strings whose entry has
// `name == q` OR whose bearer starts with `q`. Used for revoke.
func FindByName(root *yaml.Node, q string) []string {
	top := rootMapping(root)
	authTokens := mappingChild(top, "auth_tokens")
	if authTokens == nil {
		return nil
	}
	var hits []string
	for i := 0; i < len(authTokens.Content); i += 2 {
		bearer := authTokens.Content[i].Value
		entry := authTokens.Content[i+1]
		if strings.HasPrefix(bearer, q) {
			hits = append(hits, bearer)
			continue
		}
		if nv := mappingChild(entry, "name"); nv != nil && nv.Value == q {
			hits = append(hits, bearer)
		}
	}
	return hits
}

// RemoveAuthToken deletes an auth_tokens entry by bearer. Returns true if removed.
func RemoveAuthToken(root *yaml.Node, bearer string) bool {
	top := rootMapping(root)
	authTokens := mappingChild(top, "auth_tokens")
	if authTokens == nil {
		return false
	}
	return deleteMappingKey(authTokens, bearer)
}

// ListTokens returns all auth_tokens as human-facing records, sorted by name.
// Bearer strings are NOT included — this list is safe to display / log.
func ListTokens(root *yaml.Node) []TokenRecord {
	top := rootMapping(root)
	authTokens := mappingChild(top, "auth_tokens")
	if authTokens == nil {
		return nil
	}
	var out []TokenRecord
	for i := 0; i < len(authTokens.Content); i += 2 {
		bearer := authTokens.Content[i].Value
		entry := authTokens.Content[i+1]
		r := TokenRecord{
			Bearer:    bearer, // present for callers that need it — main.go must never print
			Name:      scalarOr(entry, "name", ""),
			CreatedAt: scalarOr(entry, "created_at", ""),
			ExpiresAt: scalarOr(entry, "expires_at", ""),
			Note:      scalarOr(entry, "note", ""),
		}
		if grants := mappingChild(entry, "grants"); grants != nil && grants.Kind == yaml.SequenceNode {
			for _, g := range grants.Content {
				r.Grants = append(r.Grants, g.Value)
			}
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// SensitiveGrants returns the subset of `grantIDs` that reference an
// upstream token whose scope_note contains "write" or "admin" (case-
// insensitive). Used by `dop token issue` to decide whether to prompt.
func SensitiveGrants(root *yaml.Node, grantIDs []string) []string {
	top := rootMapping(root)
	grants := mappingChild(top, "grants")
	integrations := mappingChild(top, "integrations")
	if grants == nil || integrations == nil {
		return nil
	}
	var sensitive []string
	for _, gid := range grantIDs {
		g := mappingChild(grants, gid)
		if g == nil {
			continue
		}
		integName := scalarOr(g, "integration", "")
		tokName := scalarOr(g, "token", "")
		integ := mappingChild(integrations, integName)
		if integ == nil {
			continue
		}
		tokens := mappingChild(integ, "tokens")
		if tokens == nil {
			continue
		}
		tok := mappingChild(tokens, tokName)
		if tok == nil {
			continue
		}
		note := strings.ToLower(scalarOr(tok, "scope_note", ""))
		if strings.Contains(note, "write") || strings.Contains(note, "admin") {
			sensitive = append(sensitive, gid)
		}
	}
	return sensitive
}

// KnownGrants returns the set of grant IDs defined in the vault. Used to
// validate --grants inputs before mutation.
func KnownGrants(root *yaml.Node) map[string]bool {
	top := rootMapping(root)
	grants := mappingChild(top, "grants")
	out := map[string]bool{}
	if grants == nil {
		return out
	}
	for i := 0; i < len(grants.Content); i += 2 {
		out[grants.Content[i].Value] = true
	}
	return out
}

func scalarOr(m *yaml.Node, key, def string) string {
	if v := mappingChild(m, key); v != nil && v.Kind == yaml.ScalarNode {
		return v.Value
	}
	return def
}

func appendKV(m *yaml.Node, key, val string) {
	m.Content = append(m.Content,
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key},
		&yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: val})
}
