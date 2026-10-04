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
	"bytes"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ErrNotAttached is returned when the vault directory or vault.yaml
// doesn't exist yet — the user hasn't run `dop init --vault <URL>` or
// `dop init --cache <URL>` on this machine. Callers should detect this
// sentinel via errors.Is and render a plain-English "attach a vault
// first" message rather than leaking the raw os.ReadFile error.
var ErrNotAttached = errors.New("no vault attached to this machine yet")

// ErrSessionEnded is returned when a TUI view tried to talk to the
// admin daemon but the socket was unreachable — usually because the
// session hit its idle timeout or the daemon was killed. Callers
// should detect this sentinel and prompt the operator to log in again
// instead of leaking the raw "dial unix …: connect: refused" string.
var ErrSessionEnded = errors.New("admin session ended — log in again")

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
//
// v1.13.0-rc12: Protected + Owner. When Protected is true, only the
// admin whose ed25519 pubkey matches Owner can mutate the integration
// (edit metadata, add/remove tokens, attach grants). The daemon
// reverts non-owner mutations at save time and logs
// EventProtectedBypassAttempt. Grants pointing at a protected
// integration inherit the Protected + Owner fields automatically.
type Integration struct {
	Description string            `yaml:"description,omitempty"`
	Metadata    map[string]string `yaml:"metadata,omitempty"`
	Tokens      map[string]Token  `yaml:"tokens,omitempty"`
	Protected   bool              `yaml:"protected,omitempty"`
	Owner       string            `yaml:"owner,omitempty"` // ed25519 pubkey hex
	// v1.13.0-rc13 — Kind describes HOW the credential is used so the
	// agent's env bundle can be self-describing. Empty Kind is treated
	// as IntegrationKindAPI for backward-compat (every pre-rc13
	// integration had a base_url and was API-style).
	Kind string `yaml:"kind,omitempty"` // IntegrationKind* constants below
	// v1.14.0-rc3 — symmetric with Grant.Projects/Tags. Grouping
	// metadata only, no inheritance to grants (per rc3-plan.md Phase 4).
	Projects []string `yaml:"projects,omitempty"`
	Tags     []string `yaml:"tags,omitempty"`
}

// Integration kinds. Drive the shape of the env bundle delivered to
// agents + the per-kind metadata keys the CLI/TUI prompt for.
const (
	// IntegrationKindAPI — HTTP service. Hints: base_url, endpoints_url,
	// auth_header (defaults to "Bearer"). Env export:
	// ${NAME}_BASE_URL, ${NAME}_ENDPOINTS_URL, ${NAME}_AUTH_HEADER.
	IntegrationKindAPI = "api"
	// IntegrationKindCLI — binary invoked with the token in env. Hints:
	// cli_cmd (the binary name on PATH), cli_args_hint (usage snippet).
	// Env export: ${NAME}_CMD, ${NAME}_ARGS_HINT.
	IntegrationKindCLI = "cli"
	// IntegrationKindMCP — Model Context Protocol server. Hints: one of
	// mcp_url (http) or mcp_cmd (stdio launcher). Env export:
	// ${NAME}_MCP_URL / ${NAME}_MCP_CMD.
	IntegrationKindMCP = "mcp"
	// IntegrationKindOther — unspecified. Only TOKEN is exported.
	IntegrationKindOther = "other"
)

// IntegrationKindOf returns the effective kind of an integration,
// substituting the legacy default (IntegrationKindAPI) when Kind is
// empty. Callers should prefer this over reading Kind directly.
func IntegrationKindOf(integ Integration) string {
	if integ.Kind == "" {
		return IntegrationKindAPI
	}
	return integ.Kind
}

// ValidIntegrationKind reports whether s is one of the recognized
// IntegrationKind* values. Case-sensitive on purpose — vault entries
// should carry the canonical lowercase form.
func ValidIntegrationKind(s string) bool {
	switch s {
	case IntegrationKindAPI, IntegrationKindCLI, IntegrationKindMCP, IntegrationKindOther:
		return true
	}
	return false
}

// NormalizeIntegrationName returns the canonical form of an
// operator-typed integration/service name used as the vault map key.
// Pre-v1.13.0-rc4 the raw string went straight into the map, so
// "Notion" added twice overwrote itself (same key, data lost) AND
// "Notion" vs "notion" were two distinct entries. From rc4 onwards:
//   - whitespace trimmed
//   - lowercased (so "Notion" == "notion" at the key level)
//   - non-alphanumeric (except '-' and '.') rewritten to '-'
//   - repeated '-' collapsed, leading/trailing '-' trimmed
//
// Example: "Boiler Pensieve" → "boiler-pensieve"
// Example: "Notion / Fray" → "notion-fray"
// Keeps '-' and '.' legible for display; everything else sanitized.
func NormalizeIntegrationName(s string) string {
	s = strings.TrimSpace(s)
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'A' && c <= 'Z':
			out = append(out, c+32)
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.':
			out = append(out, c)
		default:
			out = append(out, '-')
		}
	}
	// Collapse repeated hyphens.
	dedup := make([]byte, 0, len(out))
	prev := byte(0)
	for _, c := range out {
		if c == '-' && prev == '-' {
			continue
		}
		dedup = append(dedup, c)
		prev = c
	}
	// Trim leading/trailing hyphens.
	for len(dedup) > 0 && dedup[0] == '-' {
		dedup = dedup[1:]
	}
	for len(dedup) > 0 && dedup[len(dedup)-1] == '-' {
		dedup = dedup[:len(dedup)-1]
	}
	return string(dedup)
}

// FindIntegrationKey returns the actual map key under which an
// integration lives (handling pre-rc4 legacy keys that weren't
// normalized), plus whether it exists. When nothing matches, the
// returned key is the normalized form — the caller then uses it as
// the storage key for a new entry.
//
// Lookup order: literal match (handles legacy data) → normalized
// match → case/separator-insensitive scan.
func (v *Vault) FindIntegrationKey(name string) (string, bool) {
	if name == "" {
		return "", false
	}
	if _, ok := v.Integrations[name]; ok {
		return name, true
	}
	norm := NormalizeIntegrationName(name)
	if _, ok := v.Integrations[norm]; ok {
		return norm, true
	}
	for k := range v.Integrations {
		if NormalizeIntegrationName(k) == norm {
			return k, true
		}
	}
	return norm, false
}

type Token struct {
	Value     string `yaml:"value"`
	ScopeNote string `yaml:"scope_note,omitempty"`
}

// Grant maps a scope label to (integration, upstream-token, env prefix).
// v1.8: Projects + Tags are metadata for cosmetic grouping in the TUI
// and CLI filters (`--project P`, `--tags T,T`). They do NOT act as
// permission boundaries — grants are the smallest unit of permission,
// projects are just a view. Grants can belong to multiple projects.
type Grant struct {
	Integration string   `yaml:"integration"`
	Token       string   `yaml:"token"`
	EnvPrefix   string   `yaml:"env_prefix,omitempty"`
	Projects    []string `yaml:"projects,omitempty"`
	Tags        []string `yaml:"tags,omitempty"`
	// v1.13.0-rc12 — inherited from the referenced Integration. The
	// grant-add path copies Integration.Protected/Owner at save time
	// so the daemon doesn't need to do a two-hop lookup on every
	// mutation check.
	Protected bool   `yaml:"protected,omitempty"`
	Owner     string `yaml:"owner,omitempty"`
}

// EffectivePrefix returns the env-var prefix DOP should use when
// materializing this grant. Precedence:
//  1. `env_prefix` if set (explicit override).
//  2. `<INTEGRATION>_<TOKEN>` uppercased, dashes/dots → underscores.
//     Baking the token name into the default eliminates the collision
//     footgun that plagued the pre-v1.8 default of `<INTEGRATION>` alone.
//
// v1.13.0-rc4: explicit env_prefix overrides ALSO run through
// SanitizeEnvKey — pre-rc4 they passed through unsanitized, so an
// operator could set `--env-prefix "BOILER PENSIEVE"` and get an
// invalid env var at runtime (literal space in the key).
func (g Grant) EffectivePrefix() string {
	if g.EnvPrefix != "" {
		return SanitizeEnvKey(g.EnvPrefix)
	}
	return SanitizeEnvKey(g.Integration + "_" + g.Token)
}

// SanitizeEnvKey uppercases s and rewrites any non-alphanumeric char to
// `_`. Ensures the result is a valid POSIX env var name.
func SanitizeEnvKey(s string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			out = append(out, c-32)
		case c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	// Collapse repeated underscores.
	dedup := make([]byte, 0, len(out))
	prev := byte(0)
	for _, c := range out {
		if c == '_' && prev == '_' {
			continue
		}
		dedup = append(dedup, c)
		prev = c
	}
	// Trim leading/trailing underscores.
	for len(dedup) > 0 && dedup[0] == '_' {
		dedup = dedup[1:]
	}
	for len(dedup) > 0 && dedup[len(dedup)-1] == '_' {
		dedup = dedup[:len(dedup)-1]
	}
	return string(dedup)
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
	Binding    *Binding  `yaml:"binding,omitempty"`
	// v1.12 — mirror of capability.Record.EnvWrapped / BearerWrapped
	// so syncSidecars doesn't lose the wrapped envelopes on re-write.
	// yaml/json tags match the record's JSON keys so a stored
	// capability round-trips cleanly through vault → record → sidecar.
	EnvWrapped    *WrappedEnv    `yaml:"env_wrapped,omitempty" json:"env_wrapped,omitempty"`
	BearerWrapped *WrappedBearer `yaml:"bearer_wrapped,omitempty" json:"bearer_wrapped,omitempty"`
	// v1.14.0-rc1 — opt-in portable stash. When `token issue
	// --portable` runs, DOP wraps the bearer value with the
	// issuing admin's age recipient and stores the ciphertext here.
	// `dop use <subject>` later unwraps via the admin daemon to
	// retrieve the bearer in a shell on any of the admin's machines
	// (vault pulls carry the stash). Opt-in because the usual flow
	// is "bearer leaves the admin, lives only with the agent"; this
	// stash is specifically for bearers the admin itself will use.
	PortableWrapped string `yaml:"portable_wrapped,omitempty" json:"portable_wrapped,omitempty"`
	Signature       string `yaml:"signature"`
}

// WrappedEnv / WrappedBearer mirror the identically-named types in
// internal/capability. Duplicated here (rather than imported) so the
// vault package stays free of any capability-package dependency —
// vault is currently a leaf that many other packages depend on.
type WrappedEnv struct {
	AdminEphemPub string    `yaml:"admin_ephem_pub" json:"admin_ephem_pub"`
	Salt          string    `yaml:"salt" json:"salt"`
	Nonce         string    `yaml:"nonce" json:"nonce"`
	Ciphertext    string    `yaml:"ciphertext" json:"ciphertext"`
	SealedAt      time.Time `yaml:"sealed_at" json:"sealed_at"`
	Generation    uint64    `yaml:"generation" json:"generation"`
}

type WrappedBearer struct {
	AdminEphemPub string    `yaml:"admin_ephem_pub" json:"admin_ephem_pub"`
	Salt          string    `yaml:"salt" json:"salt"`
	Nonce         string    `yaml:"nonce" json:"nonce"`
	Ciphertext    string    `yaml:"ciphertext" json:"ciphertext"`
	SealedAt      time.Time `yaml:"sealed_at" json:"sealed_at"`
	NewGeneration uint64    `yaml:"new_generation" json:"new_generation"`
}

// Binding tracks how a bearer proves it belongs to the intended agent.
//
//	Kind    "pin"    — issued with a PIN, PIN-hash lives in the bundle;
//	                   Pubkey filled in after claim.
//	Kind    "pubkey" — admin pre-supplied the agent's pubkey; no PIN.
//	Kind    "none"   — legacy / opt-out; bearer alone is enough.
//
// A PIN-bound capability moves through two states:
//   - Unclaimed:  PinExpiry is set, Pubkey is empty.
//   - Claimed:    Pubkey is set, PinExpiry cleared.
//
// v1.11 — KeyType identifies which signature scheme the agent's key
// uses. Older records omit the field entirely; verifiers default to
// Ed25519 (the only option pre-v1.11) for backward compatibility.
//   "ed25519"  — legacy raw file key (default when field is empty)
//   "p256"     — ECDSA P-256, hardware-backed (macOS Secure Enclave)
//                 or file-backed (Linux/CI with DOP_ALLOW_FILE_KEYS=1)
type Binding struct {
	Kind      string    `yaml:"kind" json:"kind"`
	PinExpiry time.Time `yaml:"pin_expiry,omitempty" json:"pin_expiry,omitempty"`
	Pubkey    string    `yaml:"pubkey,omitempty" json:"pubkey,omitempty"`
	KeyType   string    `yaml:"key_type,omitempty" json:"key_type,omitempty"`
	ClaimedAt time.Time `yaml:"claimed_at,omitempty" json:"claimed_at,omitempty"`
}

const (
	BindingKindPIN    = "pin"
	BindingKindPubkey = "pubkey"
	BindingKindNone   = "none"
)

const (
	// KeyTypeEd25519 is the legacy raw-file agent key (pre-v1.11).
	KeyTypeEd25519 = "ed25519"
	// KeyTypeP256 is v1.11+ ECDSA P-256 with X9.62/DER-encoded
	// signatures. Hardware-backed on macOS (Secure Enclave), file-backed
	// on Linux/CI via explicit DOP_ALLOW_FILE_KEYS=1 opt-in.
	KeyTypeP256 = "p256"
)

// EffectiveKeyType returns the binding's key type, defaulting to
// Ed25519 when the field is absent (older records). Callers use this
// to pick the right signature verifier.
func (b *Binding) EffectiveKeyType() string {
	if b == nil || b.KeyType == "" {
		return KeyTypeEd25519
	}
	return b.KeyType
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
//
// v1.13.0-rc17 — returns ErrEncryptedVault when the file is still
// SOPS-sealed rather than falling through to ParsePlain which would
// emit a confusing "cannot parse ENC[AES256_GCM...] as 2006"
// time-parse error. Caller is expected to short-circuit to a clean
// "run dop admin login" message.
func LoadPlain(path string) (*Vault, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &Vault{SchemaVersion: SchemaVersion}, nil
		}
		return nil, err
	}
	if looksSOPSEncrypted(b) {
		return nil, ErrEncryptedVault
	}
	return ParsePlain(b)
}

// ErrEncryptedVault is returned by LoadPlain when the vault.yaml on
// disk is still SOPS-encrypted. Callers in non-admin contexts should
// catch this and emit a clean actionable message instead of leaking
// the time-parse error from a half-parsed SOPS envelope.
var ErrEncryptedVault = errors.New("vault is encrypted at rest — run `dop admin login` to unlock, or set $DOP_TOKEN to read via a bearer")

// looksSOPSEncrypted reports whether b appears to be a SOPS-encrypted
// YAML envelope. SOPS always writes a `sops:` top-level key and
// decorates every scalar with `ENC[AES256_GCM,...]`. We check for
// both: either marker alone is a strong enough signal, but the
// combination makes false positives nearly impossible.
func looksSOPSEncrypted(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	hasSops := bytes.Contains(b, []byte("\nsops:")) || bytes.HasPrefix(b, []byte("sops:"))
	hasEnc := bytes.Contains(b, []byte("ENC[AES256_GCM"))
	return hasSops || hasEnc
}

// ---

// ErrNotAdminInstall is returned when a subcommand that needs the vault
// runs on a machine that has no admin key (an agent install).
var ErrNotAdminInstall = errors.New("not an admin install (no keys/admin.age.enc) — this machine cannot decrypt or mutate the vault")
