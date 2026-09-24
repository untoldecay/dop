// Package vault loads the DOP vault from disk.
//
// P0: plaintext YAML only. P1 wraps this behind a SOPS-aware loader that
// decrypts to the same in-memory shape.
package vault

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

const SupportedSchemaVersion = 1

type Vault struct {
	SchemaVersion int                    `yaml:"schema_version"`
	Integrations  map[string]Integration `yaml:"integrations"`
	Grants        map[string]Grant       `yaml:"grants"`
	AuthTokens    map[string]AuthToken   `yaml:"auth_tokens"`
}

type Integration struct {
	Description string             `yaml:"description"`
	Metadata    map[string]string  `yaml:"metadata"`
	Tokens      map[string]Token   `yaml:"tokens"`
}

type Token struct {
	Value       string `yaml:"value"`
	ScopeNote   string `yaml:"scope_note"`
	UpstreamRef string `yaml:"upstream_ref,omitempty"`
}

type Grant struct {
	Integration string `yaml:"integration"`
	Token       string `yaml:"token"`
	EnvPrefix   string `yaml:"env_prefix"`
}

type AuthToken struct {
	Name      string   `yaml:"name"`
	CreatedBy string   `yaml:"created_by,omitempty"`
	CreatedAt string   `yaml:"created_at,omitempty"`
	ExpiresAt string   `yaml:"expires_at,omitempty"`
	Grants    []string `yaml:"grants"`
	Note      string   `yaml:"note,omitempty"`
}

func Load(path string) (*Vault, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read vault %q: %w", path, err)
	}
	var v Vault
	if err := yaml.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("parse vault %q: %w", path, err)
	}
	if v.SchemaVersion != SupportedSchemaVersion {
		return nil, fmt.Errorf(
			"vault schema_version=%d, this dop binary supports %d — upgrade one side",
			v.SchemaVersion, SupportedSchemaVersion,
		)
	}
	return &v, nil
}
