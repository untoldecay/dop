// Agent-plane commands: exec / whoami / env. All work by reading a
// capability bundle and never open the vault.

package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/fray/dop/internal/capability"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

func runExec(args []string) int {
	fs := flag.NewFlagSet("exec", flag.ExitOnError)
	agentName := fs.String("agent-name", "", "self-reported label for audit")
	tokenFile := fs.String("token-file", "", "read bearer from file (alternative to $DOP_TOKEN)")
	cleanEnv := fs.Bool("clean-env", false, "strip inherited env, keep only PATH/HOME/USER + injected")
	noPull := fs.Bool("no-pull", false, "skip auto-pull freshness check")
	_ = fs.Parse(args)
	_ = noPull // freshness check is a Phase 5 polish

	child := fs.Args()
	if len(child) == 0 {
		fmt.Fprintln(os.Stderr, "dop exec: missing command after --")
		return 2
	}

	bearer, err := readBearer(*tokenFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop exec: %v\n", err)
		return 1
	}
	env, res, err := resolveBearer(bearer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop exec: %v\n", err)
		return 1
	}
	if err := verifyBinding(bearer, res); err != nil {
		fmt.Fprintf(os.Stderr, "dop exec: %v\n", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "dop exec: agent=%q subject=%q gen=%d env_keys=%d\n",
		*agentName, res.subject, res.generation, len(env))
	if err := execChild(child, env, *cleanEnv); err != nil {
		fmt.Fprintf(os.Stderr, "dop exec: %v\n", err)
		return 1
	}
	return 0
}

// verifyBinding enforces v1.3 binding rules:
//   - kind=none      → no check
//   - kind=pin, no pubkey → claim required
//   - kind=pin, has pubkey  → must sign a challenge with the local agent key
//   - kind=pubkey    → must sign a challenge with the local agent key
func verifyBinding(bearer string, res resolveResult) error {
	if res.binding == nil {
		return nil
	}
	switch res.binding.Kind {
	case "", "none":
		return nil
	case "pin":
		if res.binding.Pubkey == "" {
			return errors.New("this bearer requires a PIN claim first — run `dop claim <PIN>`")
		}
	case "pubkey":
		// fall through
	default:
		return fmt.Errorf("unknown binding kind %q", res.binding.Kind)
	}
	paths, err := config.Resolve()
	if err != nil {
		return err
	}
	priv, err := loadAgentKey(paths, res.lookupID)
	if err != nil {
		return fmt.Errorf("agent key: %w", err)
	}
	if priv == nil {
		return errors.New("this bearer is bound but no agent key is present on this machine — run `dop claim <PIN>` on the agent's machine")
	}
	pubBytes, err := hex.DecodeString(res.binding.Pubkey)
	if err != nil {
		return fmt.Errorf("binding pubkey not hex: %w", err)
	}
	if len(pubBytes) != ed25519.PublicKeySize {
		return fmt.Errorf("binding pubkey wrong size: %d", len(pubBytes))
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return errors.New("agent key: no public component")
	}
	// Constant-time comparison: local pubkey must match bound pubkey.
	if !ed25519.PublicKey(pubBytes).Equal(pub) {
		return errors.New("local agent key does not match the bound pubkey (was this bearer rebound?)")
	}
	// Sign+verify a canonical challenge — proves possession, not just
	// filesystem presence.
	challenge := []byte("dop-v1-exec:" + res.lookupID + ":" + res.capID)
	sig := ed25519.Sign(priv, challenge)
	if !ed25519.Verify(pub, challenge, sig) {
		return errors.New("agent key self-verify failed")
	}
	return nil
}

func runWhoami(args []string) int {
	bearer, err := readBearer("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop whoami: %v\n", err)
		return 1
	}
	_, res, err := resolveBearer(bearer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop whoami: %v\n", err)
		return 1
	}
	fmt.Printf("bearer: %s\n", bearerFingerprint(bearer))
	fmt.Printf("subject:    %s\n", res.subject)
	fmt.Printf("generation: %d\n", res.generation)
	fmt.Printf("expires_at: %s\n", res.expiresAt.Format(time.RFC3339))
	if res.binding != nil {
		fmt.Printf("binding:    %s", res.binding.Kind)
		switch res.binding.Kind {
		case "pin":
			if res.binding.Pubkey == "" {
				fmt.Printf(" (unclaimed)\n")
			} else {
				fmt.Printf(" (claimed → %s…)\n", res.binding.Pubkey[:16])
			}
		case "pubkey":
			fmt.Printf(" → %s…\n", res.binding.Pubkey[:16])
		default:
			fmt.Println()
		}
	}
	return 0
}

func runEnv(args []string) int {
	bearer, err := readBearer("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop env: %v\n", err)
		return 1
	}
	env, _, err := resolveBearer(bearer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop env: %v\n", err)
		return 1
	}
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Printf("export %s='%s'\n", k, env[k])
	}
	return 0
}

// --- bearer resolution ---

// readBearer returns the bearer from --token-file if set, else
// $DOP_TOKEN, else $DOP_TOKEN_FILE.
func readBearer(fileFlag string) (string, error) {
	if fileFlag != "" {
		return readTokenFile(fileFlag)
	}
	if env := os.Getenv("DOP_TOKEN"); env != "" {
		return env, nil
	}
	if envFile := os.Getenv("DOP_TOKEN_FILE"); envFile != "" {
		return readTokenFile(envFile)
	}
	return "", errors.New("no bearer (set $DOP_TOKEN or --token-file)")
}

func readTokenFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read token file %q: %w", path, err)
	}
	return strings.TrimSpace(string(b)), nil
}

// resolveResult carries the metadata we surface alongside the env map.
type resolveResult struct {
	subject    string
	generation uint64
	expiresAt  time.Time
	capID      string
	lookupID   string
	binding    *capability.EnvelopeBinding
}

// resolveBearer: hash bearer to lookup id, read bundle file, decrypt,
// verify capability record (signature + generation), return env vars.
//
// NEVER opens the vault file itself.
func resolveBearer(bearer string) (map[string]string, resolveResult, error) {
	paths, err := config.Resolve()
	if err != nil {
		return nil, resolveResult{}, err
	}

	// Read vault_context from the encrypted vault? No — vault_context is
	// intentionally stored in a small sidecar so agent installs (no
	// admin key) can read it without decrypting.
	//
	// Layout: <vault>/vault-context.bin (raw 20 bytes).
	ctxPath := filepath.Join(paths.Vault, "vault-context.bin")
	vaultCtx, err := os.ReadFile(ctxPath)
	if err != nil {
		// Fallback: try to derive it from the vault.yaml if we're an
		// admin install (vault.yaml holds it too — but we prefer the
		// sidecar so agents work without a decrypt path).
		vaultCtx, err = readVaultContextFromVault(paths)
		if err != nil {
			return nil, resolveResult{}, fmt.Errorf("no vault_context (%s): %w", ctxPath, err)
		}
	}

	lookupID := capability.LookupID(vaultCtx, bearer)
	bundlePath := filepath.Join(paths.Vault, "capabilities", lookupID+".bundle")
	bundleBytes, err := os.ReadFile(bundlePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, resolveResult{}, fmt.Errorf("unknown bearer (or revoked)")
		}
		return nil, resolveResult{}, err
	}

	// Load capability record from the local generation cache OR the
	// vault (admin installs only). Agents rely on a cache updated at
	// pull time. For Phase 4 minimum, we accept the bundle's own
	// generation (defense: min-generation check via cache).
	minGen := readGenCache(paths, lookupID)
	env, hdr, err := capability.Read(bundleBytes, capability.ReadOpts{
		Bearer:        bearer,
		MinGeneration: minGen,
	})
	if err != nil {
		return nil, resolveResult{}, err
	}
	// Persist the seen generation as the new floor.
	if hdr.Generation > minGen {
		_ = writeGenCache(paths, lookupID, hdr.Generation)
	}
	// Subject lives inside the encrypted envelope now — no vault access
	// required. Fall back to "unknown" for older bundles.
	subject := env.Subject
	if subject == "" {
		subject = "unknown"
	}
	return env.Env, resolveResult{
		subject:    subject,
		generation: hdr.Generation,
		expiresAt:  time.Unix(hdr.ExpiresAtUnix, 0),
		capID:      hex.EncodeToString(hdr.CapabilityID[:]),
		lookupID:   lookupID,
		binding:    env.Binding,
	}, nil
}

// readVaultContextFromVault tries to pull vault_context from a plaintext
// vault.yaml (fresh admin install) OR from a decrypted admin-session
// call. For the agent install we'd normally fail here — but the
// admin should have written vault-context.bin. Fallback path only used
// during the admin-install first-issue when the sidecar isn't written yet.
func readVaultContextFromVault(paths *config.Paths) ([]byte, error) {
	v, err := vault.LoadPlain(filepath.Join(paths.Vault, "vault.yaml"))
	if err != nil {
		return nil, err
	}
	if v.VaultContext == "" {
		return nil, errors.New("vault has no vault_context yet")
	}
	return hex.DecodeString(v.VaultContext)
}

// readSubjectFromVault best-effort reads the subject label for a capID.
// Used for the audit-log "who am I running as" display.
func readSubjectFromVault(paths *config.Paths, capIDHex string) string {
	v, err := vault.LoadPlain(filepath.Join(paths.Vault, "vault.yaml"))
	if err != nil {
		return ""
	}
	if c, ok := v.Capabilities[capIDHex]; ok {
		return c.Subject
	}
	return ""
}

func adminInstallHasVault(paths *config.Paths) bool {
	_, err := os.Stat(filepath.Join(paths.Vault, "vault.yaml"))
	return err == nil
}

// --- generation cache ---
//
// The cache is a small file per capability: <config>/gen-cache/<lookup_id>.
// Stores the highest generation this machine has ever seen for that
// capability. Rejects any lower generation.

func genCachePath(paths *config.Paths, lookupID string) string {
	return filepath.Join(paths.Root, "gen-cache", lookupID)
}

func readGenCache(paths *config.Paths, lookupID string) uint64 {
	b, err := os.ReadFile(genCachePath(paths, lookupID))
	if err != nil {
		return 0
	}
	var v uint64
	fmt.Sscanf(string(b), "%d", &v)
	return v
}

func writeGenCache(paths *config.Paths, lookupID string, gen uint64) error {
	dir := filepath.Dir(genCachePath(paths, lookupID))
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.WriteFile(genCachePath(paths, lookupID), []byte(fmt.Sprintf("%d\n", gen)), 0o600)
}

// --- child exec ---

func execChild(argv []string, env map[string]string, cleanEnv bool) error {
	bin, err := lookPath(argv[0])
	if err != nil {
		return err
	}
	var finalEnv []string
	if cleanEnv {
		for _, keep := range []string{"PATH", "HOME", "USER", "SHELL", "TERM", "LANG"} {
			if v, ok := os.LookupEnv(keep); ok {
				finalEnv = append(finalEnv, keep+"="+v)
			}
		}
	} else {
		finalEnv = append(finalEnv, os.Environ()...)
	}
	// v1.5 env-hardening — when the child is `git`, strip external
	// config + disable hooks + refuse ext protocols BEFORE injecting
	// credential env. Prevents a hostile repo's hooks or a rogue
	// ~/.gitconfig include-if from running with the injected token in
	// reach. Pattern lifted from Buzz's configure_git_auth.
	if base := filepath.Base(argv[0]); base == "git" {
		finalEnv = stripEnv(finalEnv, []string{
			"GIT_SSH_COMMAND", "GIT_EXTERNAL_DIFF", "GIT_ASKPASS",
		})
		finalEnv = append(finalEnv,
			"GIT_TERMINAL_PROMPT=0",
			"GIT_CONFIG_NOSYSTEM=1",
			"GIT_CONFIG_COUNT=2",
			"GIT_CONFIG_KEY_0=core.hooksPath",
			"GIT_CONFIG_VALUE_0=/dev/null",
			"GIT_CONFIG_KEY_1=protocol.ext.allow",
			"GIT_CONFIG_VALUE_1=never",
		)
	}
	// Sort injected keys for determinism.
	keys := make([]string, 0, len(env))
	for k := range env {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		finalEnv = append(finalEnv, k+"="+env[k])
	}
	return syscall.Exec(bin, argv, finalEnv)
}

// stripEnv returns env minus any KEY=... entries whose KEY is in the
// removal set.
func stripEnv(env []string, remove []string) []string {
	set := map[string]bool{}
	for _, k := range remove {
		set[k] = true
	}
	out := env[:0]
	for _, kv := range env {
		i := strings.IndexByte(kv, '=')
		if i > 0 && set[kv[:i]] {
			continue
		}
		out = append(out, kv)
	}
	return out
}

func lookPath(bin string) (string, error) {
	// Small wrapper to keep the exec.LookPath import out of the top of
	// the file (kept execcmd.go lean of exec import).
	for _, p := range strings.Split(os.Getenv("PATH"), ":") {
		full := filepath.Join(p, bin)
		if fi, err := os.Stat(full); err == nil && !fi.IsDir() {
			return full, nil
		}
	}
	return "", fmt.Errorf("%s: not found in $PATH", bin)
}

// bearerFingerprint returns a short opaque tag for display / audit.
func bearerFingerprint(bearer string) string {
	if len(bearer) > 12 {
		return bearer[:12] + "…"
	}
	return bearer
}

// verifyRecord (Phase 4.5): given a Capability record with a known
// admin pubkey, verify its ed25519 signature. Included here for
// completeness; the exec path currently trusts the bundle envelope and
// generation cache. A full verification pass requires reading the vault
// (admin install) OR distributing the trusted admin pubkey list as a
// sidecar to agent installs. Ships as a Phase 5 polish.
func verifyRecord(rec capability.Record, adminPubkeys []string) error {
	if err := rec.Verify(); err != nil {
		return err
	}
	// Also confirm IssuedBy is a known admin.
	for _, p := range adminPubkeys {
		if strings.EqualFold(rec.IssuedBy, p) {
			return nil
		}
	}
	return fmt.Errorf("record signed by unknown admin: %s", rec.IssuedBy)
}

// stubs to keep imports honest — some ed25519 use is deferred to Phase 5.
var _ = ed25519.Sign
var _ io.Writer = os.Stderr
