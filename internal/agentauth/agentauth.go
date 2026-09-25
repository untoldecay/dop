// Package agentauth verifies a cryptographic agent's identity for
// `dop exec --sign-with`.
//
// Model: the agent has an age (X25519) private key file. The vault lists
// their public key under `agent_pubkeys.<agent-name>.pubkey_age`. Auth is
// "possession of a private key whose derived public key matches the vault
// entry" — cryptographically equivalent to a challenge-response for a
// co-located process (which is what dop is: the private key never leaves
// the user's own machine).
//
// If we ever need remote auth (agent → dop over IPC), a real
// challenge-response layer can slot in — the vault schema doesn't change.
package agentauth

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"

	"github.com/fray/dop/internal/vault"
)

// Verify loads the private key at keyfilePath, derives its public key, and
// compares it against v.AgentPubkeys[agentName].PubkeyAge. On success,
// returns the grants that agent is allowed to unlock.
//
// Returns a distinct error for each failure mode so callers can log them
// separately (unknown agent, key file unreadable, pubkey mismatch).
func Verify(v *vault.Vault, agentName, keyfilePath string) (grants []string, err error) {
	if agentName == "" {
		return nil, fmt.Errorf("--agent-name is required for --sign-with")
	}
	if keyfilePath == "" {
		return nil, fmt.Errorf("--sign-with is required (path to age private key)")
	}
	entry, ok := v.AgentPubkeys[agentName]
	if !ok {
		return nil, fmt.Errorf("no agent_pubkeys entry for %q", agentName)
	}
	if entry.PubkeyAge == "" {
		return nil, fmt.Errorf("agent %q has no pubkey_age", agentName)
	}

	f, err := os.Open(keyfilePath)
	if err != nil {
		return nil, fmt.Errorf("open sign-with keyfile: %w", err)
	}
	defer f.Close()

	id, err := readFirstX25519(f)
	if err != nil {
		return nil, fmt.Errorf("parse keyfile: %w", err)
	}

	derived := id.Recipient().String()
	if derived != entry.PubkeyAge {
		return nil, fmt.Errorf("keyfile pubkey %s does not match vault entry for %q", derived, agentName)
	}
	return append([]string(nil), entry.Grants...), nil
}

// readFirstX25519 walks an age keyfile (comments allowed) and returns the
// first X25519 identity it can parse. Matches the internal/agekeys loader.
func readFirstX25519(r io.Reader) (*age.X25519Identity, error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		id, err := age.ParseX25519Identity(line)
		if err != nil {
			return nil, err
		}
		return id, nil
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("no age identity found")
}
