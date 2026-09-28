// Package vault holds v1 vault schema types + admin-plane vault loading.
//
// v1 schema:
//
//	schema_version: v1
//	admins:
//	  <admin-name>:
//	    age_recipient: age1...
//	    ed25519_pubkey: <hex>
//	    added_at: 2026-09-28
//	    note: "cam-laptop"
//	integrations:
//	  <name>:
//	    description: "..."
//	    metadata: {...}
//	    tokens:
//	      <upstream-token-name>:
//	        value: "..."
//	        scope_note: "read-only"
//	grants:
//	  <grant-id>:
//	    integration: <integration-name>
//	    token: <upstream-token-name>
//	    env_prefix: "NOTION"
//	capabilities:
//	  <capability-id>:            # hex of the 32-byte raw id
//	    subject: "research-agent"
//	    grants: [notion.read]
//	    created_at: 2026-09-28T14:22:00Z
//	    expires_at: 2026-10-01T14:22:00Z
//	    generation: 3
//	    lookup_id: "<40-hex>"    # bundle filename
//	    bundle_hash: "<hex>"     # sha256 of bundle file
//	    issued_by: "<hex>"       # admin ed25519 pubkey
//	    status: active | revoked
//	    signature: "<hex>"       # ed25519 over the record
//	generations:
//	  <subject>: N               # monotonic per-subject counter
//	vault_context: "<40-hex>"    # per-vault random, used in HMAC for lookup_id
package vault

import (
	"errors"
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// SchemaVersion is the current schema label. v1 vaults MUST carry this;
// loading refuses anything else (including numeric v0 schemas from
// pre-v1.0 DOP builds).
const SchemaVersion = "v1"

// Vault is the plaintext view of vault.yaml.
type Vault struct {
	SchemaVersion string                 `yaml:"schema_version"`
	Admins        map[string]Admin       `yaml:"admins,omitempty"`
	Integrations  map[string]Integration `yaml:"integrations,omitempty"`
	Grants        map[string]Grant       `yaml:"grants,omitempty"`
	Capabilities  map[string]Capability  `yaml:"capabilities,omitempty"`
	Generations   map[string]uint64      `yaml:"generations,omitempty"`
	VaultContext  string                 `yaml:"vault_context,omitempty"`
}

// Admin is one authorized vault administrator.
type Admin struct {
	AgeRecipient  string    `yaml:"age_recipient"`
	Ed25519Pubkey string    `yaml:"ed25519_pubkey"`
	AddedAt       time.Time `yaml:"added_at,omitempty"`
	Note          string    `yaml:"note,omitempty"`
}

// Integration models one upstream service and its tokens.
type Integration struct {
	Description string            `yaml:"description,omitempty"`
	Metadata    map[string]string `yaml:"metadata,omitempty"`
	Tokens      map[string]Token  `yaml:"tokens,omitempty"`
}

type Token struct {
	Value     string `yaml:"value"`
	ScopeNote string `yaml:"scope_note,omitempty"`
}

// Grant maps a scope label to (integration, upstream-token, env prefix).
type Grant struct {
	Integration string `yaml:"integration"`
	Token       string `yaml:"token"`
	EnvPrefix   string `yaml:"env_prefix,omitempty"`
}

// Capability is the vault-side metadata record for one issued bearer.
// The YAML type is a plain view; conversion to/from
// `internal/capability.Record` (which carries the signature helpers)
// happens in the issuance layer.
type Capability struct {
	Subject    string    `yaml:"subject"`
	Grants     []string  `yaml:"grants"`
	CreatedAt  time.Time `yaml:"created_at"`
	ExpiresAt  time.Time `yaml:"expires_at"`
	Generation uint64    `yaml:"generation"`
	LookupID   string    `yaml:"lookup_id"`
	BundleHash string    `yaml:"bundle_hash"`
	IssuedBy   string    `yaml:"issued_by"`
	Status     string    `yaml:"status"`
	Signature  string    `yaml:"signature"`
}

// ParsePlain unmarshals plaintext YAML into a Vault, enforcing v1 schema.
func ParsePlain(b []byte) (*Vault, error) {
	var v Vault
	if err := yaml.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("parse vault yaml: %w", err)
	}
	if v.SchemaVersion == "" {
		// Empty file — treat as fresh vault, set version.
		v.SchemaVersion = SchemaVersion
		return &v, nil
	}
	if v.SchemaVersion != SchemaVersion {
		return nil, fmt.Errorf("unsupported vault schema_version=%q; this dop build handles %q. v0.3 vaults are NOT migrated automatically — start fresh", v.SchemaVersion, SchemaVersion)
	}
	return &v, nil
}

// EmitPlain marshals a Vault back to YAML.
func EmitPlain(v *Vault) ([]byte, error) {
	if v.SchemaVersion == "" {
		v.SchemaVersion = SchemaVersion
	}
	return yaml.Marshal(v)
}

// SubjectGeneration returns the current generation for a subject, 0 if
// unknown.
func (v *Vault) SubjectGeneration(subject string) uint64 {
	if v.Generations == nil {
		return 0
	}
	return v.Generations[subject]
}

// BumpGeneration increments the counter for a subject and returns the
// new value.
func (v *Vault) BumpGeneration(subject string) uint64 {
	if v.Generations == nil {
		v.Generations = map[string]uint64{}
	}
	v.Generations[subject]++
	return v.Generations[subject]
}

// ---

// LoadPlain reads a file, returns the parsed Vault. Missing file returns
// a fresh empty Vault (used during bootstrap).
func LoadPlain(path string) (*Vault, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Vault{SchemaVersion: SchemaVersion}, nil
		}
		return nil, err
	}
	return ParsePlain(b)
}

// ---

// ErrNotAdminInstall is returned when a subcommand that needs the vault
// runs on a machine that has no admin key (an agent install).
var ErrNotAdminInstall = errors.New("not an admin install (no keys/admin.age.enc) — this machine cannot decrypt or mutate the vault")
