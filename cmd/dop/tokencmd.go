// `dop token issue/list/revoke` — capability lifecycle.
//
// All ops require an active admin session — the daemon holds the vault
// decrypt key and the ed25519 signing key. This CLI orchestrates:
//
//   1. Ask daemon to decrypt vault.yaml → plaintext YAML
//   2. Mutate the parsed vault (add capability record / mark revoked)
//   3. Write bundle file to disk
//   4. Ask daemon to sign the record's canonical payload
//   5. Ask daemon to re-encrypt vault.yaml
//   6. Commit + push (best-effort)

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/capability"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

func runToken(args []string) int {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: dop token <issue|list|revoke> ...")
		return 2
	}
	switch args[0] {
	case "issue":
		return runTokenIssue(args[1:])
	case "list":
		return runTokenList(args[1:])
	case "revoke":
		return runTokenRevoke(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "dop token: unknown subcommand %q\n", args[0])
		return 2
	}
}

func runTokenIssue(args []string) int {
	fs := flag.NewFlagSet("token issue", flag.ExitOnError)
	grantsCSV := fs.String("grants", "", "comma-separated grant IDs (required)")
	name := fs.String("name", "", "human-readable subject/label")
	expires := fs.String("expires", "72h", "duration until expiry (default 72h)")
	note := fs.String("note", "", "free-text note (not used in v1.0)")
	_ = fs.Parse(args)
	_ = note

	if strings.TrimSpace(*grantsCSV) == "" {
		fmt.Fprintln(os.Stderr, "dop token issue: --grants is required")
		return 2
	}
	grants := splitCSV(*grantsCSV)
	expDur, err := time.ParseDuration(*expires)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token issue: --expires: %v\n", err)
		return 2
	}
	if expDur <= 0 {
		fmt.Fprintln(os.Stderr, "dop token issue: --expires must be positive")
		return 2
	}

	paths, _ := config.Resolve()
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token issue: %v\n", err)
		return 1
	}

	v, vaultPath, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token issue: %v\n", err)
		return 1
	}

	// Validate grants exist.
	unknown := []string{}
	for _, g := range grants {
		if _, ok := v.Grants[g]; !ok {
			unknown = append(unknown, g)
		}
	}
	if len(unknown) > 0 {
		fmt.Fprintf(os.Stderr, "dop token issue: unknown grants: %v\n", unknown)
		return 1
	}

	// Ensure vault_context exists.
	if v.VaultContext == "" {
		ctx := make([]byte, 20)
		rand.Read(ctx)
		v.VaultContext = hex.EncodeToString(ctx)
	}
	vaultCtx, _ := hex.DecodeString(v.VaultContext)

	// Generate bearer + capability id.
	bearer, err := capability.NewBearer()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token issue: %v\n", err)
		return 1
	}
	capIDRaw, err := capability.NewCapabilityID()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token issue: %v\n", err)
		return 1
	}
	capIDHex := hex.EncodeToString(capIDRaw[:])
	subject := strings.TrimSpace(*name)
	if subject == "" {
		subject = "token-" + capIDHex[:8]
	}

	// Resolve grants → env bundle.
	envBundle := resolveGrantsToEnv(v, grants)
	if len(envBundle) == 0 {
		fmt.Fprintln(os.Stderr, "dop token issue: resolved env bundle is empty (are the grants wired to integrations?)")
		return 1
	}

	// Bump the per-subject generation.
	gen := v.BumpGeneration(subject)
	expiresAt := time.Now().Add(expDur).UTC().Truncate(time.Second)
	lookupID := capability.LookupID(vaultCtx, bearer)

	// Write bundle to disk.
	bundlePath := filepath.Join(paths.Vault, "capabilities", lookupID+".bundle")
	if err := os.MkdirAll(filepath.Dir(bundlePath), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "dop token issue: %v\n", err)
		return 1
	}
	f, err := os.Create(bundlePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token issue: %v\n", err)
		return 1
	}
	bundleBytes, err := capability.Write(f, capability.WriteOpts{
		CapabilityID: capIDRaw,
		Bearer:       bearer,
		Generation:   gen,
		ExpiresAt:    expiresAt,
		Env:          envBundle,
	})
	f.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token issue: write bundle: %v\n", err)
		return 1
	}
	bundleHash := capability.HashBundle(bundleBytes)

	// Build capability record and sign via daemon.
	rec := capability.Record{
		CapabilityID: capIDHex,
		Subject:      subject,
		Grants:       grants,
		CreatedAt:    time.Now().UTC().Truncate(time.Second),
		ExpiresAt:    expiresAt,
		Generation:   gen,
		LookupID:     lookupID,
		BundleHash:   bundleHash,
		Status:       capability.RecordStatusActive,
	}
	if err := signRecordViaDaemon(client, &rec); err != nil {
		fmt.Fprintf(os.Stderr, "dop token issue: sign: %v\n", err)
		return 1
	}
	if v.Capabilities == nil {
		v.Capabilities = map[string]vault.Capability{}
	}
	v.Capabilities[capIDHex] = capability2VaultCapability(rec)

	if err := saveVaultViaDaemon(client, paths, vaultPath, v); err != nil {
		fmt.Fprintf(os.Stderr, "dop token issue: %v\n", err)
		return 1
	}

	fmt.Fprintf(os.Stderr, "dop token issue: issued %s (grants: %v, expires: %s)\n", subject, grants, expiresAt.Format(time.RFC3339))
	fmt.Fprintln(os.Stderr, "  bearer (shown ONCE — copy now):")
	fmt.Println(bearer)
	return 0
}

func runTokenList(args []string) int {
	paths, _ := config.Resolve()
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token list: %v\n", err)
		return 1
	}
	v, _, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token list: %v\n", err)
		return 1
	}
	if len(v.Capabilities) == 0 {
		fmt.Println("(no capabilities)")
		return 0
	}
	names := make([]string, 0, len(v.Capabilities))
	for id := range v.Capabilities {
		names = append(names, id)
	}
	sort.Strings(names)
	for _, id := range names {
		c := v.Capabilities[id]
		fmt.Printf("- %s  subject=%s  grants=%v  gen=%d  status=%s  expires=%s\n",
			id[:12], c.Subject, c.Grants, c.Generation, c.Status,
			c.ExpiresAt.Format(time.RFC3339))
	}
	return 0
}

func runTokenRevoke(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: dop token revoke <name>")
		return 2
	}
	query := args[0]

	paths, _ := config.Resolve()
	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token revoke: %v\n", err)
		return 1
	}
	v, vaultPath, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop token revoke: %v\n", err)
		return 1
	}

	// Match by subject; fail if ambiguous.
	matched := ""
	for id, c := range v.Capabilities {
		if c.Subject == query && c.Status == capability.RecordStatusActive {
			if matched != "" {
				fmt.Fprintf(os.Stderr, "dop token revoke: subject %q matches multiple active capabilities; be more specific\n", query)
				return 1
			}
			matched = id
		}
	}
	if matched == "" {
		fmt.Fprintf(os.Stderr, "dop token revoke: no active capability with subject %q\n", query)
		return 1
	}
	c := v.Capabilities[matched]
	c.Status = capability.RecordStatusRevoked
	// Bump generation on revoke so any cached bundle is superseded.
	c.Generation = v.BumpGeneration(c.Subject)

	// Re-sign the record with the new status.
	rec := vaultCapability2Record(c, matched)
	if err := signRecordViaDaemon(client, &rec); err != nil {
		fmt.Fprintf(os.Stderr, "dop token revoke: %v\n", err)
		return 1
	}
	v.Capabilities[matched] = capability2VaultCapability(rec)

	// Delete the bundle file.
	bundlePath := filepath.Join(paths.Vault, "capabilities", c.LookupID+".bundle")
	if err := os.Remove(bundlePath); err != nil && !os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "dop token revoke: warning: %v\n", err)
	}

	if err := saveVaultViaDaemon(client, paths, vaultPath, v); err != nil {
		fmt.Fprintf(os.Stderr, "dop token revoke: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "dop token revoke: revoked %s (gen bumped to %d)\n", query, c.Generation)
	return 0
}

// --- daemon-mediated helpers ---

func requireAdminSession(paths *config.Paths) (*admin.Client, error) {
	client := admin.NewClient(admin.SockPath(paths))
	if !client.SessionActive() {
		return nil, fmt.Errorf("no active admin session — run `dop admin login` first")
	}
	return client, nil
}

// vaultFilePath returns the vault.yaml path, bootstrapping empty if missing.
func vaultFilePath(paths *config.Paths) string {
	return filepath.Join(paths.Vault, "vault.yaml")
}

// loadVaultViaDaemon asks the daemon to decrypt vault.yaml; parses it.
// If vault.yaml doesn't exist yet, returns a fresh v1 vault.
func loadVaultViaDaemon(client *admin.Client, paths *config.Paths) (*vault.Vault, string, error) {
	vp := vaultFilePath(paths)
	fi, err := os.Stat(vp)
	if err != nil && !os.IsNotExist(err) {
		return nil, vp, err
	}
	if fi == nil || fi.Size() == 0 {
		// Fresh vault — no need to call daemon.
		return &vault.Vault{SchemaVersion: vault.SchemaVersion}, vp, nil
	}
	// If it's not SOPS-encrypted (fresh test seed), read directly.
	raw, err := os.ReadFile(vp)
	if err != nil {
		return nil, vp, err
	}
	if !bytes.Contains(raw, []byte("\nsops:")) && !bytes.HasPrefix(raw, []byte("sops:")) {
		v, err := vault.ParsePlain(raw)
		return v, vp, err
	}
	plain, err := client.DecryptVault(vp)
	if err != nil {
		return nil, vp, err
	}
	v, err := vault.ParsePlain(plain)
	return v, vp, err
}

// saveVaultViaDaemon marshals vault and asks the daemon to encrypt +
// write. Uses the admin's own age recipient from the session status.
func saveVaultViaDaemon(client *admin.Client, paths *config.Paths, vaultPath string, v *vault.Vault) error {
	// Bootstrap admin list on first save.
	st, err := client.Status()
	if err != nil {
		return err
	}
	if len(v.Admins) == 0 {
		v.Admins = map[string]Admin{}
	}
	if _, ok := v.Admins["self"]; !ok {
		hostname, _ := os.Hostname()
		if hostname == "" {
			hostname = "admin"
		}
		v.Admins[hostname] = Admin{
			AgeRecipient:  st.AgeRecipient,
			Ed25519Pubkey: st.AdminPubkey,
			AddedAt:       time.Now().UTC().Truncate(time.Second),
			Note:          "self",
		}
	}

	b, err := vault.EmitPlain(v)
	if err != nil {
		return err
	}
	// Build the age recipient list from vault.Admins.
	recipients := []string{}
	for _, a := range v.Admins {
		recipients = append(recipients, a.AgeRecipient)
	}
	if len(recipients) == 0 {
		recipients = []string{st.AgeRecipient}
	}
	recipient := strings.Join(recipients, ",")

	// Ensure .sops.yaml matches (so anyone who edits with `sops` uses same recipients).
	if err := writeSopsConfig(paths.Vault, recipients); err != nil {
		return err
	}

	return client.EncryptVault(vaultPath, b, recipient)
}

// writeSopsConfig writes a .sops.yaml file in the vault dir with the
// current admin recipient list.
func writeSopsConfig(vaultDir string, recipients []string) error {
	body := fmt.Sprintf("creation_rules:\n  - path_regex: 'vault\\.yaml$'\n    age: %s\n", strings.Join(recipients, ","))
	return os.WriteFile(filepath.Join(vaultDir, ".sops.yaml"), []byte(body), 0o644)
}

// --- Record ↔ vault.Capability conversion ---
// vault.Capability is the YAML view; capability.Record is the signing-enabled type.

func capability2VaultCapability(r capability.Record) vault.Capability {
	return vault.Capability{
		Subject:    r.Subject,
		Grants:     r.Grants,
		CreatedAt:  r.CreatedAt,
		ExpiresAt:  r.ExpiresAt,
		Generation: r.Generation,
		LookupID:   r.LookupID,
		BundleHash: r.BundleHash,
		IssuedBy:   r.IssuedBy,
		Status:     r.Status,
		Signature:  r.Signature,
	}
}

func vaultCapability2Record(c vault.Capability, capIDHex string) capability.Record {
	return capability.Record{
		CapabilityID: capIDHex,
		Subject:      c.Subject,
		Grants:       c.Grants,
		CreatedAt:    c.CreatedAt,
		ExpiresAt:    c.ExpiresAt,
		Generation:   c.Generation,
		LookupID:     c.LookupID,
		BundleHash:   c.BundleHash,
		IssuedBy:     c.IssuedBy,
		Status:       c.Status,
		Signature:    c.Signature,
	}
}

// signRecordViaDaemon asks the daemon to ed25519-sign the record's
// canonical payload. Mutates rec.IssuedBy + rec.Signature.
func signRecordViaDaemon(client *admin.Client, rec *capability.Record) error {
	// Set IssuedBy from the session so it lands in the signed payload.
	st, err := client.Status()
	if err != nil {
		return err
	}
	rec.IssuedBy = st.AdminPubkey
	rec.Signature = ""
	payload, err := rec.SigningPayload()
	if err != nil {
		return err
	}
	sig, err := client.Sign(payload)
	if err != nil {
		return err
	}
	rec.Signature = hexEncode(sig)
	return nil
}

// resolveGrantsToEnv walks the vault and materializes the env bundle
// that a bearer with these grants would receive at exec time.
func resolveGrantsToEnv(v *vault.Vault, grants []string) map[string]string {
	out := map[string]string{}
	for _, gid := range grants {
		g, ok := v.Grants[gid]
		if !ok {
			continue
		}
		integ, ok := v.Integrations[g.Integration]
		if !ok {
			continue
		}
		tok, ok := integ.Tokens[g.Token]
		if !ok {
			continue
		}
		prefix := g.EnvPrefix
		if prefix == "" {
			prefix = strings.ToUpper(g.Integration)
		}
		out[prefix+"_TOKEN"] = tok.Value
		for mk, mv := range integ.Metadata {
			out[prefix+"_"+strings.ToUpper(mk)] = mv
		}
	}
	return out
}

func splitCSV(s string) []string {
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// Admin is a local alias to keep tokencmd.go's import list small.
type Admin = vault.Admin

// io.Discard used elsewhere.
var _ io.Writer = io.Discard
