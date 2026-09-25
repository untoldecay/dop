// Package vault loads the DOP vault from disk.
//
// A vault file is either:
//   - plaintext YAML (P0 fixtures, tests) — detected by ABSENCE of a top-level `sops:` key
//   - SOPS-encrypted YAML — detected by PRESENCE of the `sops:` metadata key
//
// SOPS decryption shells out to the `sops` binary. The Go library alternative
// drags in ~40MB of cloud KMS SDKs (AWS/GCP/Azure/Vault/HuaweiCloud) for
// backends DOP does not use. Shell-out keeps the binary at ~5MB and preserves
// full sops-cli interop (users can `sops file.yaml` to edit).
//
// Age key path: SOPS reads $SOPS_AGE_KEY_FILE (set by main.go to
// ~/.config/dop/keys/age.txt by default).
package vault

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"gopkg.in/yaml.v3"
)

const SupportedSchemaVersion = 1

type Vault struct {
	SchemaVersion int                    `yaml:"schema_version"`
	Integrations  map[string]Integration `yaml:"integrations"`
	Grants        map[string]Grant       `yaml:"grants"`
	AuthTokens    map[string]AuthToken   `yaml:"auth_tokens"`
	AgentPubkeys  map[string]AgentPubkey `yaml:"agent_pubkeys,omitempty"`
	TeamMembers   map[string]TeamMember  `yaml:"team_members,omitempty"`
}

// TeamMember records a human vault-holder (age recipient). Adding an entry
// registers them as a SOPS recipient in .sops.yaml; removing an entry
// requires rotating every upstream token they may have decrypted historically.
type TeamMember struct {
	PubkeyAge string `yaml:"pubkey_age"`
	AddedAt   string `yaml:"added_at,omitempty"`
	AddedBy   string `yaml:"added_by,omitempty"`
	Note      string `yaml:"note,omitempty"`
}

// AgentPubkey records a cryptographic-identity agent. Auth proceeds by
// possession of the corresponding age private key file (`dop exec --sign-with
// <keyfile>`). No bearer token is required — the agent's identity is the
// public key, which is safe to commit to the vault.
type AgentPubkey struct {
	PubkeyAge string   `yaml:"pubkey_age"`
	Grants    []string `yaml:"grants"`
	Note      string   `yaml:"note,omitempty"`
}

type Integration struct {
	Description string            `yaml:"description"`
	Metadata    map[string]string `yaml:"metadata"`
	Tokens      map[string]Token  `yaml:"tokens"`
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

// Load reads a vault file. Transparently handles both plaintext and
// SOPS-encrypted YAML — the latter via `sops --decrypt`.
func Load(path string) (*Vault, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read vault %q: %w", path, err)
	}

	yamlBytes := raw
	if isSOPSEncrypted(raw) {
		yamlBytes, err = sopsDecrypt(path)
		if err != nil {
			return nil, fmt.Errorf("decrypt vault %q: %w", path, err)
		}
	}

	var v Vault
	if err := yaml.Unmarshal(yamlBytes, &v); err != nil {
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

// isSOPSEncrypted returns true if raw looks like a SOPS-encrypted YAML file.
// SOPS stores its metadata under a top-level `sops:` mapping — cheap check.
func isSOPSEncrypted(raw []byte) bool {
	return bytes.Contains(raw, []byte("\nsops:")) || bytes.HasPrefix(raw, []byte("sops:"))
}

// sopsDecrypt shells out to `sops --decrypt <path>` and returns the plaintext.
// Missing binary produces a clear install hint instead of a cryptic exec error.
func sopsDecrypt(path string) ([]byte, error) {
	if _, err := exec.LookPath("sops"); err != nil {
		return nil, errors.New("sops binary not found in $PATH — install via `brew install sops` or from https://github.com/getsops/sops/releases")
	}
	cmd := exec.Command("sops", "--decrypt", path)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := stderr.String()
		if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("sops --decrypt failed: %s (check $SOPS_AGE_KEY_FILE)", msg)
	}
	return stdout.Bytes(), nil
}
