// Agent-plane commands: exec / whoami / env. All work by reading a
// capability bundle and never open the vault.

package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fray/dop/internal/agentkey"
	"github.com/fray/dop/internal/audit"
	"github.com/fray/dop/internal/capability"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/envseal"
	"github.com/fray/dop/internal/trust"
	"github.com/fray/dop/internal/vault"
)

func runExec(args []string) int {
	fs := flag.NewFlagSet("exec", flag.ExitOnError)
	agentName := fs.String("agent-name", "", "self-reported label for audit")
	tokenFile := fs.String("token-file", "", "read bearer from file (alternative to $DOP_TOKEN)")
	// v1.11 — flipped default. `--clean-env` used to be opt-in; the
	// child inherited the parent's whole env by default, which leaked
	// unrelated secrets (Nostr keys, editor auth tokens, harness
	// config, previous DOP_TOKENs) to whatever the agent invoked. Now
	// the default is clean; keep-parent-env is opt-in via --inherit-env.
	// The legacy --clean-env flag remains as a silent no-op so old
	// wrappers don't break.
	inheritEnv := fs.Bool("inherit-env", false, "let the child see the parent process's env (LEGACY behaviour — leaks unrelated secrets)")
	_ = fs.Bool("clean-env", true, "deprecated: clean is now the default; use --inherit-env to opt back into parent-env passthrough")
	noPull := fs.Bool("no-pull", false, "skip the silent auto-pull freshness check")
	_ = fs.Parse(args)
	cleanEnv := !*inheritEnv

	child := fs.Args()
	if len(child) == 0 {
		fmt.Fprintln(os.Stderr, "dop exec: missing command after --")
		return 2
	}

	// v1.13.0-rc7 — silent auto-pull before resolving the bearer so
	// an admin-side `dop grant add-grant` / `token reseal` / integration
	// edit propagates to the agent on the very next exec, no manual
	// `dop pull`. Rate-limited via a sidecar so hot exec loops stay
	// cheap. Opt out with --no-pull or DOP_NO_AUTO_PULL=1.
	if !*noPull {
		paths, _ := config.Resolve()
		autoPullIfStale(paths)
	}

	bearer, source, err := readBearerWithSource(*tokenFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop exec: %v\n", err)
		return 1
	}
	env, res, err := resolveBearerAutoRotate(&bearer, source)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop exec: %v\n", err)
		return 1
	}
	if err := verifyBinding(bearer, res); err != nil {
		fmt.Fprintf(os.Stderr, "dop exec: %v\n", err)
		return 1
	}
	paths, _ := config.Resolve()
	audit.Append(paths, audit.Event{
		Kind:     audit.EventExec,
		Subject:  res.subject,
		LookupID: res.lookupID,
		Extra: map[string]string{
			"agent_name":  *agentName,
			"generation":  fmt.Sprintf("%d", res.generation),
			"env_keys":    fmt.Sprintf("%d", len(env)),
			"child":       filepath.Base(child[0]),
		},
	})
	fmt.Fprintf(os.Stderr, "dop exec: agent=%q subject=%q gen=%d env_keys=%d\n",
		*agentName, res.subject, res.generation, len(env))
	if err := execChild(child, env, cleanEnv); err != nil {
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
	// v1.11 — the AUTHORITATIVE source for the bound pubkey + key_type
	// is the admin-signed record sidecar (already verified upstream in
	// resolveBearer via verifySignedRecord). The bundle's own
	// EnvelopeBinding is a bearer-locked convenience view that can lag
	// through a `dop agent migrate` (bundle is bearer-encrypted, admin
	// can't rewrite it without the bearer). Load the record here so
	// migrations don't strand agents.
	recPath := filepath.Join(paths.Vault, "capabilities", res.lookupID+".record")
	recBlob, err := os.ReadFile(recPath)
	if err != nil {
		return fmt.Errorf("read record: %w", err)
	}
	var rec capability.Record
	if err := json.Unmarshal(recBlob, &rec); err != nil {
		return fmt.Errorf("record json: %w", err)
	}
	if rec.Binding == nil || rec.Binding.Pubkey == "" {
		return errors.New("record has no bound pubkey — this bearer requires a PIN claim first")
	}
	pubBytes, err := hex.DecodeString(rec.Binding.Pubkey)
	if err != nil {
		return fmt.Errorf("binding pubkey not hex: %w", err)
	}
	expectedType := vault.KeyTypeEd25519
	if rec.Binding.KeyType != "" {
		expectedType = rec.Binding.KeyType
	}
	store, err := agentkey.OpenByType(paths, res.lookupID, expectedType)
	if err != nil {
		if err == agentkey.ErrNotFound {
			return errors.New("this bearer is bound but no agent key of the required type is present on this machine — run `dop claim <PIN>` on the agent's machine, or `dop agent migrate " + res.lookupID + "` if you have an older key here")
		}
		return fmt.Errorf("agent key: %w", err)
	}
	if store.KeyType() != expectedType {
		return fmt.Errorf(
			"local agent key type (%s) doesn't match the record's bound key type (%s) — "+
				"run 'dop agent migrate %s' on this machine, or revoke+re-issue the bearer.",
			store.KeyType(), expectedType, res.lookupID)
	}
	if !agentkey.PubkeyEqual(pubBytes, store.PublicKey()) {
		return errors.New("local agent key does not match the record's bound pubkey (was this bearer rebound elsewhere?)")
	}
	challenge := []byte("dop-v1-exec:" + res.lookupID + ":" + res.capID)
	sig, err := store.Sign(challenge)
	if err != nil {
		return fmt.Errorf("agent key sign: %w", err)
	}
	if err := agentkey.Verify(expectedType, pubBytes, challenge, sig); err != nil {
		return fmt.Errorf("agent key self-verify failed: %w", err)
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
	// v1.13.0-rc7 — Fizz: pre-rc7, --expires=never surfaced here as
	// "9999-12-31T23:59:59Z" (the sentinel). Route through the same
	// display helper the token list/show commands use.
	fmt.Printf("expires_at: %s\n", tokenExpiryDisplay(res.expiresAt))
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
	// v1.13.0-rc7 — same silent auto-pull as exec. `dop env` is often
	// the first thing an agent script runs (`$(dop env)` style), so
	// seeing fresh grants here matters just as much. --no-pull would
	// require a flag parser; env usually runs with no flags so we
	// gate purely on DOP_NO_AUTO_PULL=1.
	paths, _ := config.Resolve()
	autoPullIfStale(paths)

	bearer, source, err := readBearerWithSource("")
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop env: %v\n", err)
		return 1
	}
	env, res, err := resolveBearerAutoRotate(&bearer, source)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop env: %v\n", err)
		return 1
	}
	// v1.9.7 SECURITY — `dop env` prints plaintext credential values, so
	// it must enforce the same PIN-claim binding as `dop exec`. Prior to
	// this fix, possession of $DOP_TOKEN alone was enough to extract
	// secrets, defeating the "stolen bearer isn't enough" guarantee that
	// binding is supposed to provide. Audit-log denied attempts.
	if err := verifyBinding(bearer, res); err != nil {
		paths, _ := config.Resolve()
		audit.Append(paths, audit.Event{
			Kind:     audit.EventEnvDenied,
			Subject:  res.subject,
			LookupID: res.lookupID,
			Extra:    map[string]string{"reason": err.Error()},
		})
		fmt.Fprintf(os.Stderr, "dop env: %v\n", err)
		return 1
	}
	audit.Append(paths, audit.Event{
		Kind:     audit.EventEnv,
		Subject:  res.subject,
		LookupID: res.lookupID,
		Extra: map[string]string{
			"generation": fmt.Sprintf("%d", res.generation),
			"env_keys":   fmt.Sprintf("%d", len(env)),
		},
	})
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
	b, _, err := readBearerWithSource(fileFlag)
	return b, err
}

// readBearerWithSource is v1.12-added and additionally returns the
// writable path (file backing the bearer) or "" if the bearer came
// from $DOP_TOKEN env — needed so bearer rotation can auto-rewrite
// the token file when the agent has one, and cleanly warn when it
// doesn't.
func readBearerWithSource(fileFlag string) (bearer, sourceFile string, err error) {
	if fileFlag != "" {
		b, err := readTokenFile(fileFlag)
		return b, fileFlag, err
	}
	if env := os.Getenv("DOP_TOKEN"); env != "" {
		return env, "", nil
	}
	if envFile := os.Getenv("DOP_TOKEN_FILE"); envFile != "" {
		b, err := readTokenFile(envFile)
		return b, envFile, err
	}
	return "", "", errors.New("no bearer (set $DOP_TOKEN or --token-file)")
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

	// v1.6.2 — verify signed capability record BEFORE decrypting the
	// bundle. The record's admin signature is the actual root of trust;
	// the bundle envelope alone only proves bearer possession.
	//
	// verifyAndLoadRecord accepts only active records. To detect a
	// rotation, we read the record independently first and check for
	// status=rotated + BearerWrapped BEFORE calling the strict verifier.
	if rotated, err := detectAndRotate(paths, lookupID); err != nil {
		return nil, resolveResult{}, fmt.Errorf("bearer rotation: %w", err)
	} else if rotated != nil {
		// The bearer we were called with is stale. The caller should
		// re-invoke with the new bearer — resolveBearer returns a
		// sentinel error carrying the new bearer + new lookup so the
		// caller can retry transparently.
		return nil, resolveResult{}, &rotationError{
			newBearer:   rotated.newBearer,
			newLookupID: rotated.newLookupID,
		}
	}
	rec, err := verifyAndLoadRecord(paths, lookupID, bundleBytes)
	if err != nil {
		return nil, resolveResult{}, fmt.Errorf("record verify: %w", err)
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
	effectiveEnv := env.Env
	// v1.12 — EnvWrapped takes precedence over the bundle env. Any
	// error is HARD: we do NOT silently fall back to bundle env
	// (which would be a downgrade an attacker could force by
	// corrupting the wrapped envelope).
	if rec.EnvWrapped != nil {
		wrappedEnv, oerr := openEnvWrapped(paths, rec)
		if oerr != nil {
			return nil, resolveResult{}, fmt.Errorf("env_wrapped: %w", oerr)
		}
		effectiveEnv = wrappedEnv
	}
	return effectiveEnv, resolveResult{
		subject:    subject,
		generation: hdr.Generation,
		expiresAt:  time.Unix(hdr.ExpiresAtUnix, 0),
		capID:      hex.EncodeToString(hdr.CapabilityID[:]),
		lookupID:   lookupID,
		binding:    env.Binding,
	}, nil
}

// resolveBearerAutoRotate wraps resolveBearer with v1.12 transparent
// bearer rotation. If resolveBearer returns a rotationError, this
// helper:
//   - Writes the new bearer to bearerSource when it points at a file
//     (--token-file or $DOP_TOKEN_FILE); otherwise emits a warning
//     saying the caller MUST restart with the new bearer.
//   - Updates *bearer in place so callers downstream see the new
//     value (verifyBinding needs it for the challenge).
//   - Re-invokes resolveBearer once with the new bearer.
//
// One-shot: if the new bearer's record ALSO says "rotated", we
// return an error rather than looping (would only happen if admin
// rotated twice back-to-back — unusual and worth surfacing).
func resolveBearerAutoRotate(bearer *string, bearerSource string) (map[string]string, resolveResult, error) {
	env, res, err := resolveBearer(*bearer)
	if err == nil {
		return env, res, nil
	}
	var rot *rotationError
	if !errors.As(err, &rot) {
		return nil, res, err
	}
	// Persist the new bearer for future runs. If we can't write it,
	// tell the user exactly what to do next.
	if bearerSource != "" {
		if werr := os.WriteFile(bearerSource, []byte(rot.newBearer), 0o600); werr != nil {
			return nil, res, fmt.Errorf(
				"bearer rotated by admin — got new bearer, but couldn't write to %q: %w\n"+
					"  Manually set DOP_TOKEN=%s and re-run.",
				bearerSource, werr, rot.newBearer)
		}
		fmt.Fprintf(os.Stderr, "dop: wrote rotated bearer to %s\n", bearerSource)
	} else {
		fmt.Fprintln(os.Stderr,
			"⚠  Bearer was rotated by admin. This process is running with $DOP_TOKEN (env),\n"+
				"   which dop cannot rewrite from here — the parent shell/agent driver\n"+
				"   must catch this. New bearer for this rotation:")
		fmt.Fprintln(os.Stderr, "     "+rot.newBearer)
		fmt.Fprintln(os.Stderr,
			"   Update $DOP_TOKEN (or switch to --token-file for auto-rotation) and re-run.")
		return nil, res, errors.New("bearer rotated — retry with new bearer above")
	}
	*bearer = rot.newBearer
	env, res, err = resolveBearer(rot.newBearer)
	if err != nil {
		// Second rotation attempt is unusual; surface loudly.
		return nil, res, fmt.Errorf("after rotation: %w", err)
	}
	return env, res, nil
}

// rotationError is a sentinel returned by resolveBearer when the
// record it looked up has status=rotated + a BearerWrapped envelope
// pointing to the successor. Callers use errors.As to unwrap it and
// re-invoke resolveBearer with newBearer.
type rotationError struct {
	newBearer   string
	newLookupID string
}

func (e *rotationError) Error() string {
	return "bearer rotated; caller must retry with the new bearer"
}

type rotationInfo struct {
	newBearer   string
	newLookupID string
}

// detectAndRotate inspects the record for the given lookup id. If
// status=rotated + BearerWrapped is set, it verifies the record
// signature, opens the wrapped bearer via the local agent SE (or
// file P-256) key, migrates that key to the new lookup id, rewrites
// the bearer-source file when possible, and returns the new bearer
// + new lookup id.
//
// Returns nil rotationInfo (with nil error) when no rotation is
// pending — normal path, caller proceeds with the record as-is.
func detectAndRotate(paths *config.Paths, lookupID string) (*rotationInfo, error) {
	recPath := filepath.Join(paths.Vault, "capabilities", lookupID+".record")
	blob, err := os.ReadFile(recPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // fall through to normal path (will error there)
		}
		return nil, err
	}
	var rec capability.Record
	if err := json.Unmarshal(blob, &rec); err != nil {
		return nil, nil // let the normal path surface the parse error
	}
	if rec.Status != capability.RecordStatusRotated || rec.BearerWrapped == nil {
		return nil, nil // not rotated
	}

	// Verify the signature before trusting BearerWrapped's contents.
	// Trust checks are the same as the normal record verifier — but we
	// skip the "must be active" gate since a rotated record is what we
	// are here for.
	if err := verifyRotatedRecord(paths, lookupID, &rec); err != nil {
		return nil, fmt.Errorf("rotated record verify: %w", err)
	}

	// Only P-256 bearers can carry BearerWrapped (ed25519 can't ECDH).
	if rec.Binding == nil || rec.Binding.KeyType != vault.KeyTypeP256 {
		return nil, errors.New("rotated record's binding is not p256 — cannot open BearerWrapped")
	}
	store, err := agentkey.OpenByType(paths, lookupID, vault.KeyTypeP256)
	if err != nil {
		return nil, fmt.Errorf("open agent key: %w", err)
	}
	sealed, err := envseal.FromHex(map[string]string{
		"admin_ephem_pub": rec.BearerWrapped.AdminEphemPub,
		"salt":            rec.BearerWrapped.Salt,
		"nonce":           rec.BearerWrapped.Nonce,
		"ciphertext":      rec.BearerWrapped.Ciphertext,
	})
	if err != nil {
		return nil, fmt.Errorf("decode wrapped: %w", err)
	}
	shared, err := store.SharedSecret(sealed.AdminEphemPub)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}
	aad := []byte(fmt.Sprintf("dop-bearerwrap-v1|old_lookup=%s|new_gen=%d", lookupID, rec.BearerWrapped.NewGeneration))
	plaintext, err := envseal.OpenWithShared(shared, sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("open wrapped: %w", err)
	}
	var payload struct {
		Bearer   string `json:"bearer"`
		LookupID string `json:"lookup_id"`
	}
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	if payload.Bearer == "" || payload.LookupID == "" {
		return nil, errors.New("wrapped payload missing bearer or lookup_id")
	}

	// Migrate the agent key to the new lookup id — same physical key,
	// re-tagged. Both file and SE backends implement LookupMigrator.
	migrator, ok := store.(agentkey.LookupMigrator)
	if !ok {
		return nil, errors.New("agent key backend doesn't support lookup migration")
	}
	if err := migrator.MigrateLookupID(payload.LookupID); err != nil {
		return nil, fmt.Errorf("migrate agent key tag: %w", err)
	}

	fmt.Fprintf(os.Stderr,
		"dop: bearer rotated by admin — switched to new bearer %s… (lookup %s…)\n",
		payload.Bearer[:min(12, len(payload.Bearer))], payload.LookupID[:12])

	return &rotationInfo{newBearer: payload.Bearer, newLookupID: payload.LookupID}, nil
}

// verifyRotatedRecord is verifyAndLoadRecord without the "must be
// active" check — used for rotated records whose whole purpose is
// to carry a BearerWrapped envelope.
func verifyRotatedRecord(paths *config.Paths, lookupID string, rec *capability.Record) error {
	if rec.LookupID != lookupID {
		return errors.New("record lookup_id mismatch")
	}
	trusted, err := trust.Load(paths)
	if err != nil {
		return fmt.Errorf("load trust: %w", err)
	}
	if !trusted[strings.ToLower(rec.IssuedBy)] && !trusted[rec.IssuedBy] {
		return fmt.Errorf("record signed by unknown admin: %s", short(rec.IssuedBy))
	}
	return rec.Verify()
}

// openEnvWrapped decrypts record.EnvWrapped using the local agent's
// SE (or file-backed P-256) key. Hard-fails on any error per v1.12
// design decision: no silent downgrade to bundle env.
//
// Anti-rollback check: the generation baked under the AEAD's AAD
// must match record.Generation. A mismatch means someone glued a
// stale sealed envelope onto a fresher record; the admin signature
// covers env_wrapped's fields so any splicing also breaks the record
// signature, but the AAD adds belt-and-suspenders.
func openEnvWrapped(paths *config.Paths, rec *capability.Record) (map[string]string, error) {
	if rec.EnvWrapped == nil {
		return nil, errors.New("no env_wrapped on record")
	}
	if rec.EnvWrapped.Generation != rec.Generation {
		return nil, fmt.Errorf("env_wrapped gen %d ≠ record gen %d (stale envelope)",
			rec.EnvWrapped.Generation, rec.Generation)
	}
	if rec.Binding == nil {
		return nil, errors.New("record has env_wrapped but no binding — malformed")
	}
	expectedType := vault.KeyTypeEd25519
	if rec.Binding.KeyType != "" {
		expectedType = rec.Binding.KeyType
	}
	if expectedType != vault.KeyTypeP256 {
		return nil, fmt.Errorf("env_wrapped requires p256 key, record binding is %s", expectedType)
	}
	store, err := agentkey.OpenByType(paths, rec.LookupID, expectedType)
	if err != nil {
		return nil, fmt.Errorf("open agent key: %w", err)
	}
	// Rebuild envseal.Sealed from the hex fields on the record.
	sealed, err := envseal.FromHex(map[string]string{
		"admin_ephem_pub": rec.EnvWrapped.AdminEphemPub,
		"salt":            rec.EnvWrapped.Salt,
		"nonce":           rec.EnvWrapped.Nonce,
		"ciphertext":      rec.EnvWrapped.Ciphertext,
	})
	if err != nil {
		return nil, fmt.Errorf("decode sealed fields: %w", err)
	}
	// Compute the shared secret via the store (SE or file-backed).
	shared, err := store.SharedSecret(sealed.AdminEphemPub)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}
	// AAD must match what the admin sealed with — reproduce it from
	// the same record fields.
	aad := []byte(fmt.Sprintf("dop-envwrap-v1|lookup=%s|gen=%d", rec.LookupID, rec.Generation))
	plaintext, err := envseal.OpenWithShared(shared, sealed, aad)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	var payload struct {
		Env map[string]string `json:"env"`
	}
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		return nil, fmt.Errorf("decode plaintext: %w", err)
	}
	return payload.Env, nil
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
	n, err := fmt.Sscanf(strings.TrimSpace(string(b)), "%d", &v)
	if err != nil || n != 1 {
		// Corrupt cache file. Warn on stderr (surfaced in audit + doctor)
		// but return 0 so exec can still succeed if the bundle itself
		// checks out — a defense-in-depth cache should never brick the
		// primary path.
		fmt.Fprintf(os.Stderr, "dop exec: warning: gen-cache %s corrupt (%v), ignoring\n",
			genCachePath(paths, lookupID), err)
		return 0
	}
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
	// v1.11 — unconditionally strip DOP_TOKEN / DOP_TOKEN_FILE from
	// the child, regardless of clean/inherit mode. A compromised child
	// process inheriting the bearer can just re-invoke `dop env` and
	// dump every credential — which defeats the whole point of the
	// binding gate. The bearer is only meant to be visible to `dop`
	// itself, never the process being run.
	finalEnv = stripEnv(finalEnv, []string{"DOP_TOKEN", "DOP_TOKEN_FILE"})
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

// verifySignedRecord (v1.6.2) is the actual signature-verification
// path the exec plane now runs. It loads:
//   - `<lookup_id>.record` (JSON, signed capability.Record)
//   - `admins.trust` (JSON, plaintext list of admin ed25519 pubkeys)
// then confirms:
//   - the record's ed25519 signature is valid over its canonical form
//   - the record.IssuedBy pubkey is in the trust list
//   - the record.BundleHash matches sha256 of the on-disk bundle
//   - the record.LookupID matches the computed lookup id
//   - the record.Status is "active"
//
// Missing sidecar OR missing trust file → hard-fail. This is the
// gate that promotes "any bearer + any bundle file" (the pre-v1.6.2
// contract) to "any bearer + a bundle whose record was signed by a
// currently-trusted admin".
func verifySignedRecord(paths *config.Paths, lookupID string, bundleBytes []byte) error {
	_, err := verifyAndLoadRecord(paths, lookupID, bundleBytes)
	return err
}

// verifyAndLoadRecord runs the same signed-record checks as
// verifySignedRecord and returns the parsed, verified record — v1.12
// callers (resolveBearer) need it to inspect EnvWrapped without a
// re-read.
func verifyAndLoadRecord(paths *config.Paths, lookupID string, bundleBytes []byte) (*capability.Record, error) {
	recPath := filepath.Join(paths.Vault, "capabilities", lookupID+".record")
	blob, err := os.ReadFile(recPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("no signed record for this bearer (%s missing)", recPath)
		}
		return nil, err
	}
	var rec capability.Record
	if err := json.Unmarshal(blob, &rec); err != nil {
		return nil, fmt.Errorf("record json: %w", err)
	}

	if rec.Status != capability.RecordStatusActive {
		return nil, fmt.Errorf("record status is %q", rec.Status)
	}
	if rec.LookupID != lookupID {
		return nil, fmt.Errorf("record lookup_id mismatch")
	}
	if want := capability.HashBundle(bundleBytes); rec.BundleHash != want {
		return nil, fmt.Errorf("bundle hash mismatch (record %s ≠ file %s) — bundle tampered or out of sync",
			short(rec.BundleHash), short(want))
	}
	trusted, err := trust.Load(paths)
	if err != nil {
		return nil, fmt.Errorf("load trust: %w", err)
	}
	if len(trusted) == 0 {
		trustPath := trust.Path(paths)
		if _, statErr := os.Stat(trustPath); statErr == nil {
			return nil, fmt.Errorf("admins.trust at %s lists zero admins — nothing to verify against", trustPath)
		}
		return nil, fmt.Errorf("no admins.trust file at %s (agent install must `dop pull` after the admin has bootstrapped it)", trustPath)
	}
	if !trusted[strings.ToLower(rec.IssuedBy)] && !trusted[rec.IssuedBy] {
		return nil, fmt.Errorf("record signed by unknown admin: %s", short(rec.IssuedBy))
	}
	if err := rec.Verify(); err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	return &rec, nil
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}

// stubs to keep imports honest — some ed25519 use is deferred to Phase 5.
var _ = ed25519.Sign
var _ io.Writer = os.Stderr

// v1.13.0-rc7 — autoPullIfStale runs the same silent fetch+merge as
// admin login (autoPullVault), but rate-limited via a sidecar
// timestamp file so hot-loop exec/env calls don't thrash the git
// remote. Default freshness window is 15s; override via
// DOP_AUTOPULL_MAX_AGE_SEC. Opt out entirely via DOP_NO_AUTO_PULL=1.
//
// This is what makes "admin edits a grant → agent sees it on next
// exec" truly transparent on both sides. Pre-rc7 the agent needed to
// manually `dop pull` to see admin's push.
func autoPullIfStale(paths *config.Paths) {
	if os.Getenv("DOP_NO_AUTO_PULL") == "1" {
		return
	}
	if paths == nil {
		return
	}
	if _, err := os.Stat(filepath.Join(paths.Vault, ".git")); err != nil {
		return
	}
	maxAge := 15 * time.Second
	if raw := os.Getenv("DOP_AUTOPULL_MAX_AGE_SEC"); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 {
			maxAge = time.Duration(n) * time.Second
		}
	}
	marker := filepath.Join(paths.Root, "last-pull.ts")
	if fi, err := os.Stat(marker); err == nil {
		if time.Since(fi.ModTime()) < maxAge {
			return
		}
	}
	autoPullVault(paths)
	// Touch the sidecar whether or not the pull succeeded — a failed
	// pull shouldn't trigger another one 10ms later. The ModTime is
	// what gates us, not the file contents.
	_ = os.MkdirAll(paths.Root, 0o700)
	f, err := os.Create(marker)
	if err == nil {
		f.Close()
	}
}
