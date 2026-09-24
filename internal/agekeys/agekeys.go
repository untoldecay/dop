// Package agekeys wraps filippo.io/age for DOP's single-recipient use case.
//
// V1 supports one recipient per user (yourself). Multi-recipient support
// (teammate keys) lives in the SOPS layer via .sops.yaml, not here.
package agekeys

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"filippo.io/age"
)

// Generate creates a new X25519 age identity and returns it. Callers are
// responsible for persisting the private key (WritePrivateKey) — Generate
// deliberately never writes to disk on its own.
func Generate() (*age.X25519Identity, error) {
	id, err := age.GenerateX25519Identity()
	if err != nil {
		return nil, fmt.Errorf("generate age identity: %w", err)
	}
	return id, nil
}

// WritePrivateKey serializes the identity to `path` in the standard age
// format (a `# created:` comment, `# public key:` comment, then the private
// key line). Written with mode 0600 — refuses to overwrite an existing file.
func WritePrivateKey(id *age.X25519Identity, path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create key file %s: %w", path, err)
	}
	defer f.Close()

	if _, err := fmt.Fprintf(f, "# public key: %s\n", id.Recipient()); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}
	if _, err := fmt.Fprintln(f, id.String()); err != nil {
		return fmt.Errorf("write key file: %w", err)
	}
	return nil
}

// LoadPrivateKey reads a key file (age-format) and returns the identity.
// Accepts files with comment lines and multiple identities; returns the first.
func LoadPrivateKey(path string) (*age.X25519Identity, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open key file %s: %w", path, err)
	}
	defer f.Close()

	ids, err := parseIdentities(f)
	if err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("no age identity found in %s", path)
	}
	return ids[0], nil
}

func parseIdentities(r io.Reader) ([]*age.X25519Identity, error) {
	var out []*age.X25519Identity
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		id, err := age.ParseX25519Identity(line)
		if err != nil {
			return nil, fmt.Errorf("parse identity: %w", err)
		}
		out = append(out, id)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("read identities: %w", err)
	}
	return out, nil
}
