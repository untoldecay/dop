// `dop claim <PIN>` — v1.3 PIN claim.
//
// Runs on the agent's machine (which for the common case is also the
// admin's machine — Cam's laptop, Claude Code, etc). Requires an active
// admin session because the claim mutates the vault (updates the
// capability record's binding and bumps generation) and only the admin
// can sign + re-encrypt.
//
// Flow:
//  1. Read bearer from $DOP_TOKEN (or --token-file).
//  2. Decrypt local bundle → verify PIN hash + not-expired.
//  3. Generate an ed25519 keypair for the agent.
//  4. Bump generation, update record binding (pubkey + claimed_at, clear
//     pin_expiry), re-write the bundle with the new binding + new gen.
//  5. Ask daemon to sign the updated record + re-encrypt the vault.
//  6. Persist the agent private key under <paths.Root>/agent-keys/.
//  7. Print success and the one-liner the agent should eval.
//
// A remote agent (no admin session on its host) can't call this — the
// admin should issue with `--bind-pubkey <hex>` instead, using the
// agent's pre-published pubkey.

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/mdp/qrterminal/v3"
	"rsc.io/qr"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/agentkey"
	"github.com/fray/dop/internal/approvalserver"
	"github.com/fray/dop/internal/audit"
	"github.com/fray/dop/internal/capability"
	"github.com/fray/dop/internal/cli/printguard"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/pendingclaim"
	"github.com/fray/dop/internal/remoteclaim"
	"github.com/fray/dop/internal/tunnel"
	"github.com/fray/dop/internal/vault"
)

func runClaim(args []string) int {
	fs := flag.NewFlagSet("claim", flag.ExitOnError)
	tokenFile := fs.String("token-file", "", "read bearer from file (alternative to $DOP_TOKEN)")
	shell := fs.Bool("shell", false, "after claim, print `eval $(dop env-shell ...)`-style exports")
	// rc6h — --print-export retired (no-op since rc5 Option A). Accepted
	// silently with a one-line deprecation warning if set.
	legacyPrintExport := fs.Bool("print-export", false, "DEPRECATED (rc6h): no-op, accepted for backward-compat.")
	skipApproval := fs.Bool("skip-approval", false, "finalize immediately without out-of-band approval (unsafe for chat handoff)")
	noTunnel := fs.Bool("no-tunnel", false, "serve the approval page on LAN only (no Cloudflare tunnel)")
	bindAddr := fs.String("bind", "", "interface to bind the approval server (default: 127.0.0.1 with tunnel, 0.0.0.0 with --no-tunnel)")
	remote := fs.Bool("remote", false, "no admin daemon on this host — stage the claim in the vault repo, admin approves + syncs via `dop approve-remote`")
	cancel := fs.Bool("cancel", false, "cancel any in-flight pending claim for $DOP_TOKEN and exit")
	status := fs.Bool("status", false, "print the pending-claim state for $DOP_TOKEN (json) and exit")
	// v1.12 — force a specific agent key type. Default (empty) uses the
	// auto-selection heuristic in agentkey.Create (SE on macOS, else
	// ed25519 file). Explicit "p256" opts into ECDH-capable keys on
	// systems where SE isn't reachable (Linux/CI with
	// DOP_ALLOW_FILE_KEYS=1, or macOS dev builds without codesign).
	keyTypeFlag := fs.String("key-type", "", "\"p256\" | \"ed25519\" | \"\" (auto). p256 required for direct grant edits (v1.12)")
	asJSON := fs.Bool("json", false, "emit JSONL events (pending, result) on stdout instead of human-readable output on stderr")
	flagArgs, posArgs := splitFlagsAndPositionals(fs, args)
	_ = fs.Parse(flagArgs)
	if *legacyPrintExport {
		fmt.Fprintln(os.Stderr, "dop claim: --print-export is deprecated and has no effect (removed in rc6h).")
	}

	// Default bind depends on tunnel mode: 127.0.0.1 is fine when the
	// tunnel is the reachability path; --no-tunnel needs 0.0.0.0 so a
	// phone on the same wifi can actually reach the server.
	if *bindAddr == "" {
		if *noTunnel {
			*bindAddr = "0.0.0.0"
		} else {
			*bindAddr = "127.0.0.1"
		}
	}

	// --cancel and --status don't need a PIN; they operate on whatever
	// pending claim exists for the current bearer.
	//
	// v1.13.0-rc11 — ClaudeMini field report: when something's wedged,
	// "just tell me the state" should work without re-supplying the
	// bearer. If no bearer is supplied, we scan the local pending-claims
	// directory. Unambiguous (one entry) → act on it. Multiple → tell
	// the operator which one needs disambiguation. Zero → "no pending
	// claims on this machine".
	if *cancel || *status {
		if len(posArgs) != 0 {
			fmt.Fprintln(os.Stderr, "usage: dop claim --cancel   OR   dop claim --status")
			return 2
		}
		paths, _ := config.Resolve()
		bearer, _ := readBearer(*tokenFile)
		if bearer == "" {
			if *cancel {
				return runClaimCancelNoBearer(paths, *asJSON)
			}
			return runClaimStatusNoBearer(paths, *asJSON)
		}
		if *cancel {
			return runClaimCancel(paths, bearer, *asJSON)
		}
		return runClaimStatus(paths, bearer, *asJSON)
	}

	if len(posArgs) != 1 {
		fmt.Fprintln(os.Stderr, "usage: dop claim <PIN>")
		return 2
	}
	pinArg := posArgs[0]

	bearer, err := readBearer(*tokenFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop claim: %v\n", err)
		return 1
	}

	paths, _ := config.Resolve()

	// Same silent pull as exec, but unconditional: a bearer issued on
	// the admin machine a moment ago isn't in this clone yet, and a
	// claim is rare enough that exec's 15s freshness window would only
	// get in the way. Covers both the local and the --remote path
	// (DOP_NO_AUTO_PULL=1 opts out).
	autoPullVault(paths)
	touchPullMarker(paths)

	// --remote path: no daemon required, stage the claim in the vault.
	if *remote {
		return runClaimRemote(paths, *tokenFile, pinArg, *keyTypeFlag)
	}

	client, err := requireAdminSession(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop claim: %v — an active admin session is required to record the binding\n", err)
		return 1
	}

	// Decrypt the local bundle to inspect its binding.
	ctxPath := filepath.Join(paths.Vault, "vault-context.bin")
	vaultCtx, err := os.ReadFile(ctxPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop claim: no vault_context (%s): %v\n", ctxPath, err)
		return 1
	}
	lookupID := capability.LookupID(vaultCtx, bearer)
	bundlePath := filepath.Join(paths.Vault, "capabilities", lookupID+".bundle")
	oldBundleBytes, err := os.ReadFile(bundlePath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "dop claim: this token isn't recognized by this machine's vault (pulled just now).")
			fmt.Fprintln(os.Stderr, "  Common cause: the admin machine issued it but hasn't pushed yet (dop push there).")
			fmt.Fprintln(os.Stderr, "  Then re-run this claim.")
			return 1
		}
		fmt.Fprintf(os.Stderr, "dop claim: %v\n", err)
		return 1
	}
	env, hdr, err := capability.Read(oldBundleBytes, capability.ReadOpts{Bearer: bearer})
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop claim: decrypt bundle: %v\n", err)
		return 1
	}
	if env.Binding == nil {
		fmt.Fprintln(os.Stderr, "dop claim: this bearer has no binding (issued with --no-bind); nothing to claim")
		return 1
	}
	switch env.Binding.Kind {
	case vault.BindingKindPIN:
		// ok
	case vault.BindingKindPubkey:
		fmt.Fprintln(os.Stderr, "dop claim: this bearer was pre-bound to an admin-supplied pubkey; PIN claim is not applicable")
		return 1
	default:
		fmt.Fprintf(os.Stderr, "dop claim: unsupported binding kind %q\n", env.Binding.Kind)
		return 1
	}
	if env.Binding.Pubkey != "" {
		fmt.Fprintln(os.Stderr, "dop claim: this bearer is already claimed; revoke + re-issue if you meant to rebind")
		return 1
	}
	if env.Binding.PinExpiry > 0 && time.Now().Unix() > env.Binding.PinExpiry {
		audit.Append(paths, audit.Event{
			Kind:     audit.EventClaimDenied,
			Subject:  env.Subject,
			LookupID: lookupID,
			Extra:    map[string]string{"reason": "pin_expired"},
		})
		fmt.Fprintln(os.Stderr, "dop claim: PIN expired — run `dop token repin` to reissue one")
		return 1
	}
	if !capability.VerifyPIN(bearer, pinArg, env.Binding.PinHash) {
		audit.Append(paths, audit.Event{
			Kind:     audit.EventClaimDenied,
			Subject:  env.Subject,
			LookupID: lookupID,
			Extra:    map[string]string{"reason": "pin_mismatch"},
		})
		fmt.Fprintln(os.Stderr, "dop claim: PIN does not match")
		return 1
	}

	// v1.11 — Generate agent key via the platform-aware backend.
	// On macOS this returns a Secure-Enclave-backed P-256 key; on
	// Linux/CI (with DOP_ALLOW_FILE_KEYS=1) it falls back to a
	// file-backed P-256 key; otherwise ed25519 legacy.
	store, err := agentkey.Create(paths, lookupID, *keyTypeFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop claim: keygen: %v\n", err)
		return 1
	}
	pubHex := hex.EncodeToString(store.PublicKey())
	keyType := store.KeyType()
	claimedAt := time.Now().UTC().Truncate(time.Second)

	// Passphrase-gated approval (v1.6). Skippable for unattended flows.
	if !*skipApproval {
		if err := awaitApproval(paths, lookupID, hex.EncodeToString(hdr.CapabilityID[:]), env.Subject, pubHex, *noTunnel, *bindAddr, *asJSON); err != nil {
			if *asJSON {
				emitJSON(map[string]any{"event": "result", "state": "aborted", "error": err.Error()})
			} else {
				fmt.Fprintf(os.Stderr, "dop claim: %v\n", err)
			}
			return 1
		}
	}

	// Load vault via daemon so we can update the record.
	v, vaultPath, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop claim: %v\n", err)
		return 1
	}
	capIDHex := hex.EncodeToString(hdr.CapabilityID[:])
	crec, ok := v.Capabilities[capIDHex]
	if !ok {
		fmt.Fprintln(os.Stderr, "dop claim: capability record not in vault (may need `dop pull`)")
		return 1
	}
	if crec.Status != capability.RecordStatusActive {
		fmt.Fprintf(os.Stderr, "dop claim: capability is not active (status=%s)\n", crec.Status)
		return 1
	}

	// Bump generation for rebind hardening (rollback-replay guard).
	newGen := v.BumpGeneration(crec.Subject)

	// Rewrite bundle with updated binding + new generation.
	newEnvBinding := &capability.EnvelopeBinding{
		Kind:    vault.BindingKindPIN,
		Pubkey:  pubHex,
		KeyType: keyType,
	}
	newBundlePath := bundlePath + ".tmp"
	f, err := os.Create(newBundlePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop claim: %v\n", err)
		return 1
	}
	newBundleBytes, err := capability.Write(f, capability.WriteOpts{
		CapabilityID: hdr.CapabilityID,
		Bearer:       bearer,
		Generation:   newGen,
		ExpiresAt:    time.Unix(hdr.ExpiresAtUnix, 0).UTC(),
		Subject:      env.Subject,
		Env:          env.Env,
		Binding:      newEnvBinding,
	})
	f.Close()
	if err != nil {
		os.Remove(newBundlePath)
		fmt.Fprintf(os.Stderr, "dop claim: rewrite bundle: %v\n", err)
		return 1
	}
	newBundleHash := capability.HashBundle(newBundleBytes)

	// Update the vault record.
	crec.Generation = newGen
	crec.BundleHash = newBundleHash
	crec.Binding = &vault.Binding{
		Kind:      vault.BindingKindPIN,
		Pubkey:    pubHex,
		KeyType:   keyType,
		ClaimedAt: claimedAt,
	}
	rec := vaultCapability2Record(crec, capIDHex)
	if err := signRecordViaDaemon(client, &rec); err != nil {
		os.Remove(newBundlePath)
		fmt.Fprintf(os.Stderr, "dop claim: sign: %v\n", err)
		return 1
	}
	putCapability(v, capIDHex, rec)

	// v1.6.2 — Reorder to minimize inconsistency on crash. Priority is
	// "exec must keep working". Steps:
	//   1. Persist the agent private key (so we don't lose it later).
	//   2. Rename the bundle atomically (exec reads this; new binding lands).
	//   3. Write the signed record sidecar (exec verifies signature via this).
	//   4. Save the vault (heaviest, admin-view only).
	//
	// Failure between (2) and (3): bundle has pubkey, sidecar out of
	// sync — exec's bundle_hash check fails. Rare and manually
	// recoverable via revoke + reissue.
	// Failure between (3) and (4): everything exec needs is on disk;
	// only the vault's own view lags. Re-running claim will observe
	// bundle+sidecar already updated and skip.
	// v1.11 — key already persisted by agentkey.Create at generation
	// time; nothing to do here except surface where it lives for the
	// success message and the audit log.
	keyPath := store.StorageDescription()
	if err := os.Rename(newBundlePath, bundlePath); err != nil {
		fmt.Fprintf(os.Stderr, "dop claim: swap bundle: %v\n", err)
		return 1
	}
	if err := writeRecordSidecar(paths, rec); err != nil {
		fmt.Fprintf(os.Stderr, "dop claim: write record sidecar: %v\n", err)
		return 1
	}
	if err := saveVaultViaDaemon(client, paths, vaultPath, v); err != nil {
		// v1.6.4 — bundle + sidecar + agent key are all on disk and
		// exec will keep working. Only the vault view (generation
		// counter, claimed_at) is stale. Warn loudly with a subject-
		// specific recovery: the operator should `dop admin login` +
		// `dop token revoke %s` + `dop token issue` to bring vault
		// back into agreement, or leave it be until next issue.
		fmt.Fprintf(os.Stderr, "dop claim: save vault failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "  exec-plane state (bundle, sidecar, agent key) is intact for subject %q.\n", env.Subject)
		fmt.Fprintf(os.Stderr, "  next `dop token issue --name %s` may collide on generation until you `dop token revoke %s` + reissue.\n", env.Subject, env.Subject)
		return 1
	}

	audit.Append(paths, audit.Event{
		Kind:     audit.EventClaim,
		Subject:  env.Subject,
		LookupID: lookupID,
		Actor:    pubHex,
		Extra:    map[string]string{"generation": fmt.Sprintf("%d", newGen)},
	})
	if *asJSON {
		emitJSON(map[string]any{
			"event":      "result",
			"state":      "claimed",
			"subject":    env.Subject,
			"generation": newGen,
			"pubkey":     pubHex,
			"agent_key":  keyPath,
		})
	} else {
		fmt.Fprintf(os.Stderr, "dop claim: bound %s → pubkey %s… (gen %d)\n",
			env.Subject, pubHex[:16], newGen)
		fmt.Fprintf(os.Stderr, "  agent key: %s\n", keyPath)
		fmt.Fprintf(os.Stderr, "  run: dop exec --agent-name %s -- <cmd>\n", env.Subject)
	}
	if *shell {
		// v1.14.0-rc4 — Tier 1/2/3 gate. Claim itself already went
		// through approval (that's its whole point); this gate is only
		// to prevent the POST-CLAIM export-line print from leaking
		// into a non-tty transcript. The claim mutation is intact
		// regardless — only the extra export print is gated.
		pathsClaim, _ := config.Resolve()
		clientClaim := admin.NewClient(admin.SockPath(pathsClaim))
		if err := printguard.Guard(printguard.Request{
			Kind:          printguard.KindClaim,
			Subject:       env.Subject,
			Out:           os.Stdout,
			Paths:         pathsClaim,
			Client:        clientClaim,
			ClaimApproved: !*skipApproval,
			LookupID:      lookupID,
		}); err != nil {
			fmt.Fprintln(os.Stderr, "  (claim succeeded; export line NOT printed. Set DOP_TOKEN from your bearer env, or wait for the approval popup.)")
			return 0
		}
		fmt.Printf("export DOP_TOKEN=%s\n", bearer)
	}
	return 0
}

// emitJSON writes a compact JSON object followed by a newline to
// stdout — one event per line so agents can parse the stream
// incrementally.
func emitJSON(v map[string]any) {
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	os.Stdout.Write(b)
	os.Stdout.Write([]byte("\n"))
}

// runClaimCancel deletes the pending-claim file for $DOP_TOKEN so the
// running `dop claim` (which is polling that file) sees it disappear
// and exits. Idempotent: absent file → success.
func runClaimCancel(paths *config.Paths, bearer string, asJSON bool) int {
	lookupID, err := lookupIDFromBearer(paths, bearer)
	if err != nil {
		if asJSON {
			emitJSON(map[string]any{"event": "cancel", "state": "error", "error": err.Error()})
		} else {
			fmt.Fprintf(os.Stderr, "dop claim --cancel: %v\n", err)
		}
		return 1
	}
	if err := pendingclaim.Delete(paths, lookupID); err != nil {
		if asJSON {
			emitJSON(map[string]any{"event": "cancel", "state": "error", "error": err.Error()})
		} else {
			fmt.Fprintf(os.Stderr, "dop claim --cancel: %v\n", err)
		}
		return 1
	}
	if asJSON {
		emitJSON(map[string]any{"event": "cancel", "state": "cancelled", "lookup_id": lookupID})
	} else {
		fmt.Fprintf(os.Stderr, "dop claim --cancel: pending claim cleared\n")
	}
	return 0
}

// runClaimStatus reports the current pending-claim record for
// $DOP_TOKEN. Reports "absent" if no file exists.
func runClaimStatus(paths *config.Paths, bearer string, asJSON bool) int {
	lookupID, err := lookupIDFromBearer(paths, bearer)
	if err != nil {
		if asJSON {
			emitJSON(map[string]any{"event": "status", "state": "error", "error": err.Error()})
		} else {
			fmt.Fprintf(os.Stderr, "dop claim --status: %v\n", err)
		}
		return 1
	}
	rec, err := pendingclaim.Read(paths, lookupID)
	if err != nil {
		if os.IsNotExist(err) {
			if asJSON {
				emitJSON(map[string]any{"event": "status", "state": "absent", "lookup_id": lookupID})
			} else {
				fmt.Println("(no pending claim)")
			}
			return 0
		}
		if asJSON {
			emitJSON(map[string]any{"event": "status", "state": "error", "error": err.Error()})
		} else {
			fmt.Fprintf(os.Stderr, "dop claim --status: %v\n", err)
		}
		return 1
	}
	state := rec.State
	if rec.State == pendingclaim.StatePending && rec.Expired(time.Now()) {
		state = "expired"
	}
	if asJSON {
		emitJSON(map[string]any{
			"event":         "status",
			"state":         state,
			"sas":           rec.SAS,
			"subject":       rec.Subject,
			"lookup_id":     lookupID,
			"started_at":    rec.StartedAt.Format(time.RFC3339),
			"expires_at":    rec.ExpiresAt.Format(time.RFC3339),
			"failure_count": rec.FailureCount,
		})
	} else {
		ttl := time.Until(rec.ExpiresAt).Truncate(time.Second)
		ttlStr := ttl.String()
		if ttl < 0 {
			ttlStr = "expired"
		}
		fmt.Printf("subject: %s\nstate:   %s\nSAS:     %s\nTTL:     %s\n", rec.Subject, state, rec.SAS, ttlStr)
	}
	return 0
}

// lookupIDFromBearer derives the lookup_id for a bearer using the
// vault-context. Both files must already be present locally (vault has
// been initialized).
func lookupIDFromBearer(paths *config.Paths, bearer string) (string, error) {
	ctxPath := filepath.Join(paths.Vault, "vault-context.bin")
	vaultCtx, err := os.ReadFile(ctxPath)
	if err != nil {
		return "", fmt.Errorf("read vault_context: %w", err)
	}
	return capability.LookupID(vaultCtx, bearer), nil
}

// runClaimRemote is the agent-side of the remote-claim flow. It runs
// on a host that has NO admin daemon (CI runner, remote server) but
// does have the vault git-cloned via `dop init --cache` and a bearer
// via $DOP_TOKEN.
//
// Flow:
//  1. Verify the PIN locally against the on-disk bundle.
//  2. Read the existing signed record sidecar for the current gen.
//  3. Generate an ed25519 keypair.
//  4. Prepare a NEW bundle in memory carrying the pubkey binding.
//  5. Write the new bundle to `pending-remote-claims/<lookup_id>.bundle`
//     alongside a signed metadata file.
//  6. Persist the agent private key at `<Root>/agent-keys/<lookup_id>.key`.
//  7. Git commit + push (best-effort — user can push manually).
//
// The admin then runs `dop approve-remote` on their machine to accept
// the pubkey and finalize the record.
func runClaimRemote(paths *config.Paths, tokenFile, pinArg, keyType string) int {
	bearer, err := readBearer(tokenFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop claim --remote: %v\n", err)
		return 1
	}
	if pinArg == "" {
		fmt.Fprintln(os.Stderr, "dop claim --remote: PIN required")
		return 2
	}

	ctxPath := filepath.Join(paths.Vault, "vault-context.bin")
	vaultCtx, err := os.ReadFile(ctxPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop claim --remote: no vault_context (%s): %v\n", ctxPath, err)
		return 1
	}
	lookupID := capability.LookupID(vaultCtx, bearer)
	bundlePath := filepath.Join(paths.Vault, "capabilities", lookupID+".bundle")
	oldBundleBytes, err := os.ReadFile(bundlePath)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintln(os.Stderr, "dop claim --remote: unknown bearer (bundle not found after pulling the vault — did the admin `dop push` after issuing?)")
			return 1
		}
		fmt.Fprintf(os.Stderr, "dop claim --remote: %v\n", err)
		return 1
	}
	env, hdr, err := capability.Read(oldBundleBytes, capability.ReadOpts{Bearer: bearer})
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop claim --remote: decrypt bundle: %v\n", err)
		return 1
	}
	if env.Binding == nil || env.Binding.Kind != vault.BindingKindPIN {
		fmt.Fprintln(os.Stderr, "dop claim --remote: this bearer is not PIN-bound")
		return 1
	}
	if env.Binding.Pubkey != "" {
		fmt.Fprintln(os.Stderr, "dop claim --remote: this bearer is already claimed")
		return 1
	}
	if env.Binding.PinExpiry > 0 && time.Now().Unix() > env.Binding.PinExpiry {
		fmt.Fprintln(os.Stderr, "dop claim --remote: PIN expired — ask admin to `dop token repin`")
		return 1
	}
	if !capability.VerifyPIN(bearer, pinArg, env.Binding.PinHash) {
		fmt.Fprintln(os.Stderr, "dop claim --remote: PIN does not match")
		return 1
	}

	// Read the existing signed record to know the current generation.
	recPath := filepath.Join(paths.Vault, "capabilities", lookupID+".record")
	recBlob, err := os.ReadFile(recPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop claim --remote: no .record sidecar (%s): %v\n", recPath, err)
		return 1
	}
	var existing capability.Record
	if err := json.Unmarshal(recBlob, &existing); err != nil {
		fmt.Fprintf(os.Stderr, "dop claim --remote: record json: %v\n", err)
		return 1
	}

	// Generate the agent key via the same platform-aware backend as the
	// local claim (SE P-256 on macOS, file P-256 with
	// DOP_ALLOW_FILE_KEYS=1, ed25519 fallback; --key-type forces one).
	// The key is persisted BEFORE staging in the vault: if push fails
	// the admin can still approve once it lands, and the pubkey only
	// ever exists here.
	store, err := agentkey.Create(paths, lookupID, keyType)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop claim --remote: keygen: %v\n", err)
		return 1
	}
	pubHex := hex.EncodeToString(store.PublicKey())
	keyPath := store.StorageDescription()
	newGen := existing.Generation + 1
	newBinding := &capability.EnvelopeBinding{
		Kind:    vault.BindingKindPIN,
		Pubkey:  pubHex,
		KeyType: store.KeyType(),
	}
	var newBundleBuf bytes.Buffer
	newBundleBytes, err := capability.Write(&newBundleBuf, capability.WriteOpts{
		CapabilityID: hdr.CapabilityID,
		Bearer:       bearer,
		Generation:   newGen,
		ExpiresAt:    time.Unix(hdr.ExpiresAtUnix, 0).UTC(),
		Subject:      env.Subject,
		Env:          env.Env,
		Binding:      newBinding,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop claim --remote: build new bundle: %v\n", err)
		return 1
	}

	host, _ := os.Hostname()
	req := remoteclaim.Request{
		LookupID:      lookupID,
		CapabilityID:  hex.EncodeToString(hdr.CapabilityID[:]),
		Subject:       env.Subject,
		Host:          host,
		RequestedAt:   time.Now().UTC().Truncate(time.Second),
		ExpiresAt:     time.Now().Add(remoteclaim.TTL).UTC().Truncate(time.Second),
		NewGeneration: newGen,
		NewBundleHash: capability.HashBundle(newBundleBytes),
	}
	if err := req.Sign(store); err != nil {
		fmt.Fprintf(os.Stderr, "dop claim --remote: sign request: %v\n", err)
		return 1
	}
	if err := remoteclaim.Write(paths, req, newBundleBytes); err != nil {
		fmt.Fprintf(os.Stderr, "dop claim --remote: stage claim: %v\n", err)
		return 1
	}

	// Best-effort git push. If it fails, user gets a clear next-step.
	pushErr := gitCommitPushRemoteClaim(paths, lookupID)

	audit.Append(paths, audit.Event{
		Kind:     audit.EventClaimPending,
		Subject:  env.Subject,
		LookupID: lookupID,
		Extra: map[string]string{
			"remote": "true",
			"host":   host,
			"pubkey": pubHex,
		},
	})

	fmt.Fprintf(os.Stderr, "dop claim --remote: staged %s for approval\n", env.Subject)
	fmt.Fprintf(os.Stderr, "  agent key: %s\n", keyPath)
	fmt.Fprintf(os.Stderr, "  admin runs: dop approve-remote --subject %s\n", env.Subject)
	if pushErr != nil {
		fmt.Fprintf(os.Stderr, "  ! git push failed (%v) — run `dop push` after resolving\n", pushErr)
	} else {
		fmt.Fprintln(os.Stderr, "  pushed to vault repo. Once the admin approves, run:")
		fmt.Fprintf(os.Stderr, "    dop exec --agent-name %s -- <cmd>\n", env.Subject)
		fmt.Fprintln(os.Stderr, "  No DOP_TOKEN needed from then on — this host's agent key is the proof. Drop the bearer from your env.")
	}
	return 0
}

// gitCommitPushRemoteClaim adds the two pending-remote-claim files and
// pushes them. Kept close to the callsite because it's a one-shot dance.
func gitCommitPushRemoteClaim(paths *config.Paths, lookupID string) error {
	dir := paths.Vault
	rel := filepath.Join("pending-remote-claims", lookupID)
	if err := runGit(io.Discard, dir, "add", rel+".bundle", rel+".json"); err != nil {
		return err
	}
	if err := runGit(io.Discard, dir, "commit", "-m",
		fmt.Sprintf("dop: remote claim %s (unapproved)", lookupID[:12])); err != nil {
		return err
	}
	return runGit(io.Discard, dir, "push")
}

// awaitApproval spins up:
//   - a local HTTP server bound to bindAddr:PORT
//   - optionally a cloudflared tunnel pointing at that server
//   - a QR code displayed on the terminal encoding the URL
//
// It emits a `claim_pending` audit event (fires the macOS notification),
// writes the pending-claim file for `dop pending` / `dop approve <SAS>`
// CLI compatibility, then blocks until the human decides on the web
// page OR the CLI approve command lands OR TTL expires.
func awaitApproval(paths *config.Paths, lookupID, capIDHex, subject, pubHex string, noTunnel bool, bindAddr string, asJSON bool) error {
	sas, err := pendingclaim.NewSAS()
	if err != nil {
		return fmt.Errorf("SAS gen: %w", err)
	}
	displayToken, err := approvalserver.NewDisplayToken()
	if err != nil {
		return fmt.Errorf("token gen: %w", err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	rec := pendingclaim.Record{
		SAS:          sas,
		LookupID:     lookupID,
		CapabilityID: capIDHex,
		Subject:      subject,
		Pubkey:       pubHex,
		StartedAt:    now,
		ExpiresAt:    now.Add(pendingclaim.TTL),
		State:        pendingclaim.StatePending,
	}
	if err := pendingclaim.Write(paths, rec); err != nil {
		return err
	}
	defer pendingclaim.Delete(paths, lookupID)

	// Bind an ephemeral port on bindAddr.
	listener, err := net.Listen("tcp", bindAddr+":0")
	if err != nil {
		return fmt.Errorf("bind approval server: %w", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port

	srv := approvalserver.New(paths, rec, displayToken)
	httpSrv := &http.Server{Handler: srv.Handler()}
	go func() { _ = httpSrv.Serve(listener) }()
	defer func() {
		shCtx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_ = httpSrv.Shutdown(shCtx)
	}()

	// Optionally launch a Cloudflare tunnel.
	var (
		publicURL string
		tun       *tunnel.Tunnel
	)
	if !noTunnel && tunnel.Available() {
		// v1.11.1 — sweep any orphaned cloudflared quick-tunnel processes
		// from prior sessions before starting a fresh one. Silent by
		// design: users hit this when the previous `dop claim` was
		// SIGKILL'd or the shell was force-quit, leaving cloudflared
		// alive but detached. Without cleanup, the new tunnel competes
		// with the dead one and the phone gets 530 from Cloudflare.
		_ = tunnel.KillStrays()
		tctx, tcancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer tcancel()
		t, terr := tunnel.Start(tctx, port, 15*time.Second)
		if terr != nil {
			fmt.Fprintf(os.Stderr, "dop claim: tunnel unavailable (%v) — falling back to LAN URL\n", terr)
		} else {
			tun = t
			publicURL = t.URL + "/c/" + displayToken
			defer tun.Stop()
		}
	} else if !tunnel.Available() {
		fmt.Fprintln(os.Stderr, "dop claim: cloudflared not on PATH — serving LAN-only. `brew install cloudflared` for internet approval.")
	}
	localURL := fmt.Sprintf("http://%s:%d/c/%s", displayHost(bindAddr), port, displayToken)
	if publicURL == "" {
		publicURL = localURL
	}
	srv.PublicURL = publicURL

	audit.Append(paths, audit.Event{
		Kind:     audit.EventClaimPending,
		Subject:  subject,
		LookupID: lookupID,
		Extra: map[string]string{
			"sas":        sas,
			"expires_in": pendingclaim.TTL.String(),
			"url":        publicURL,
		},
	})

	// v1.9.3: also write a PNG QR so an AI agent can attach it in chat
	// (Unicode terminal QR is unreliable for anything but a human eye).
	qrPath := filepath.Join(paths.Root, "pending-claims", lookupID+".qr.png")
	_ = writeQRPNG(publicURL, qrPath)

	if asJSON {
		payload := map[string]any{
			"event":       "pending",
			"state":       "pending",
			"subject":     subject,
			"sas":         sas,
			"lookup_id":   lookupID,
			"public_url":  publicURL,
			"lan_url":     localURL,
			"qr_png":      qrPath,
			"expires_at":  rec.ExpiresAt.Format(time.RFC3339),
			"ttl_seconds": int(pendingclaim.TTL / time.Second),
			"cancel_hint": "dop claim --cancel",
			// v1.9.6 — agent-facing playbook. The clipboard message shown
			// to the user is now just the run command; the agent gets its
			// full brief here so nothing has to leak into the user's chat.
			"agent_instructions": []string{
				"attach the qr_png file to this chat with your file-display tool (e.g. SendUserFile) so the user can scan it inline",
				"share public_url as plain text so the user can also open it on their phone",
				"tell the user: scan the QR or open the URL, then enter your DOP approval passphrase",
				"do NOT retry this command — it blocks until approval and then emits a `result` event on stdout",
				"if you need to abort (timeout, wrong PIN, user changed their mind): run `DOP_TOKEN=<same> dop claim --cancel` in another shell",
			},
		}
		emitJSON(payload)
	} else {
		// Structured header — the labelled lines are parseable by an agent
		// skill so the file + URL can be surfaced back into the chat.
		fmt.Fprintf(os.Stderr, "\ndop claim: PENDING — approve within %s\n", pendingclaim.TTL)
		fmt.Fprintf(os.Stderr, "  subject: %s\n", subject)
		fmt.Fprintf(os.Stderr, "  SAS:     %s\n\n", sas)
		fmt.Fprintf(os.Stderr, "QR image: %s\n", qrPath)
		fmt.Fprintf(os.Stderr, "Public URL: %s\n", publicURL)
		if publicURL != localURL {
			fmt.Fprintf(os.Stderr, "LAN URL: %s\n", localURL)
		}
		fmt.Fprintln(os.Stderr)
		fmt.Fprintln(os.Stderr, "  → attach the QR image in this chat AND share the Public URL as text.")
		fmt.Fprintln(os.Stderr, "  → the admin will scan the QR or open the URL on their phone,")
		fmt.Fprintln(os.Stderr, "    enter the DOP approval passphrase, and this claim will unblock.")
		fmt.Fprintln(os.Stderr)
		// v1.13.0-rc14 — polling / state / abort guidance lives HERE,
		// in the runtime output of `dop claim`, not in the pasted
		// handoff text. See contract 13_handoff_text_shape.md: the
		// paste must contain only the command; everything else about
		// how to monitor/abort is streamed by the binary itself when
		// the receiving agent runs it.
		fmt.Fprintln(os.Stderr, "  this command blocks until approval. while it runs you can:")
		fmt.Fprintln(os.Stderr, "    • poll from another shell:  dop claim --status --json")
		fmt.Fprintln(os.Stderr, "        → returns {state: pending | approved | expired | absent}")
		fmt.Fprintln(os.Stderr, "    • cancel the pending claim:  dop claim --cancel")
		fmt.Fprintln(os.Stderr)
		// Unicode terminal QR — harmless for humans, ignored by agents.
		qrterminal.GenerateHalfBlock(publicURL, qrterminal.L, os.Stderr)
	}

	// Clean up on Ctrl-C or terminal close. SIGHUP matters when the
	// user closes the shell hosting `dop claim` — without trapping it
	// the process dies via runtime default, defers don't run, and we
	// strand the pending-claim file + orphaned cloudflared subprocess.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	// v1.9.6 — tunnel health-check + one-shot auto-restart. Quick
	// tunnels die often enough that a user's phone-side approval was
	// hitting HTTP 530 with no way to notice. Every 20s we HEAD the
	// public URL; after two consecutive failures we tear the tunnel
	// down + bring up a fresh one, push the new URL through JSON, and
	// keep going. The LAN URL never changes and remains a reliable
	// fallback the whole time.
	stopHealth := make(chan struct{})
	defer close(stopHealth)
	if tun != nil && !noTunnel {
		go tunnelHealthLoop(&tun, srv, subject, sas, lookupID, qrPath, rec, localURL, asJSON, stopHealth)
	}

	// Wait on: (1) the web server signaling a decision, (2) the pending
	// file's on-disk state (CLI `dop approve <SAS>` flow), (3) TTL, (4)
	// Ctrl-C.
	deadline := time.Now().Add(pendingclaim.TTL)
	tick := time.NewTicker(400 * time.Millisecond)
	defer tick.Stop()

	decisionCh := make(chan approvalserver.Decision, 1)
	go func() {
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		defer cancel()
		decisionCh <- srv.Wait(ctx)
	}()

	for {
		select {
		case <-sigCh:
			return errors.New("interrupted — pending claim cancelled")
		case d := <-decisionCh:
			switch d {
			case approvalserver.DecisionApproved:
				// Grace period so the "Approved" HTML fully flushes back
				// through the tunnel before we tear it down.
				time.Sleep(1500 * time.Millisecond)
				return nil
			case approvalserver.DecisionRejected:
				audit.Append(paths, audit.Event{
					Kind:     audit.EventClaimDenied,
					Subject:  subject,
					LookupID: lookupID,
					Extra:    map[string]string{"reason": "rejected"},
				})
				return errors.New("claim rejected via web")
			default:
				audit.Append(paths, audit.Event{
					Kind:     audit.EventClaimDenied,
					Subject:  subject,
					LookupID: lookupID,
					Extra:    map[string]string{"reason": "approval_timeout"},
				})
				return errors.New("approval window expired")
			}
		case <-tick.C:
			if time.Now().After(deadline) {
				audit.Append(paths, audit.Event{
					Kind:     audit.EventClaimDenied,
					Subject:  subject,
					LookupID: lookupID,
					Extra:    map[string]string{"reason": "approval_timeout"},
				})
				return errors.New("approval window expired")
			}
			// Also check the pending file — dop approve <SAS> --passphrase
			// mutates the on-disk state.
			cur, err := pendingclaim.Read(paths, lookupID)
			if err != nil {
				// v1.9.4: `dop claim --cancel` (or manual rm) removes the
				// file — treat as an explicit cancellation and unwind.
				if os.IsNotExist(err) {
					audit.Append(paths, audit.Event{
						Kind:     audit.EventClaimDenied,
						Subject:  subject,
						LookupID: lookupID,
						Extra:    map[string]string{"reason": "cancelled"},
					})
					return errors.New("cancelled — pending-claim file removed")
				}
				continue
			}
			switch cur.State {
			case pendingclaim.StateApproved:
				time.Sleep(500 * time.Millisecond)
				return nil
			case pendingclaim.StateRejected:
				audit.Append(paths, audit.Event{
					Kind:     audit.EventClaimDenied,
					Subject:  subject,
					LookupID: lookupID,
					Extra:    map[string]string{"reason": "rejected"},
				})
				return errors.New("claim rejected")
			}
		}
	}
}

// tunnelHealthLoop polls the current tunnel URL every 20s and, on two
// consecutive failures, tears down the dead tunnel and starts a fresh
// one. The srv's PublicURL and the caller's tun pointer are both
// updated so subsequent JSON events (and the approval page) reflect
// the new URL. Emits stderr + JSON warnings so agents / humans can
// see what happened.
//
// The LAN URL never changes; if cloudflared is permanently unreachable
// we give up trying to restart after one attempt and leave the LAN
// path as the fallback.
func tunnelHealthLoop(tunPtr **tunnel.Tunnel, srv *approvalserver.Server,
	subject, sas, lookupID, qrPath string, rec pendingclaim.Record,
	localURL string, asJSON bool, stop <-chan struct{}) {

	tick := time.NewTicker(20 * time.Second)
	defer tick.Stop()
	consecutiveFail := 0
	restartAttempted := false
	for {
		select {
		case <-stop:
			return
		case <-tick.C:
		}
		if *tunPtr == nil {
			return
		}
		cur := (*tunPtr).URL
		if !tunnel.CheckAlive(cur, 5*time.Second) {
			consecutiveFail++
			if consecutiveFail < 2 {
				continue
			}
			if restartAttempted {
				fmt.Fprintln(os.Stderr, "\ndop claim: tunnel remains unreachable — use the LAN URL if you're on the same network.")
				return
			}
			restartAttempted = true
			fmt.Fprintf(os.Stderr, "\ndop claim: ⚠  tunnel appears dead — restarting cloudflared…\n")
			(*tunPtr).Stop()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			t, err := tunnel.Start(ctx, srvPort(srv, localURL), 15*time.Second)
			cancel()
			if err != nil {
				fmt.Fprintf(os.Stderr, "dop claim: tunnel restart failed: %v — falling back to LAN URL: %s\n", err, localURL)
				*tunPtr = nil
				return
			}
			*tunPtr = t
			// srv.DisplayToken was baked into the URL path when the
			// approval page was set up — reuse it so the new tunnel URL
			// still routes to /c/<token>.
			newPublic := t.URL + "/c/" + srv.DisplayToken
			srv.PublicURL = newPublic
			fmt.Fprintf(os.Stderr, "dop claim: ✓ tunnel back up — new public URL: %s\n", newPublic)
			if asJSON {
				emitJSON(map[string]any{
					"event":      "tunnel_reset",
					"state":      "pending",
					"subject":    subject,
					"sas":        sas,
					"lookup_id":  lookupID,
					"public_url": newPublic,
					"lan_url":    localURL,
					"qr_png":     qrPath,
					"expires_at": rec.ExpiresAt.Format(time.RFC3339),
					"note":       "the previous public_url is dead — reshare THIS one",
				})
			}
			consecutiveFail = 0
		} else {
			consecutiveFail = 0
		}
	}
}

// srvPort extracts the local listener port from the LAN URL we already
// built for display. The URL looks like http://<host>:<port>/c/<token>.
// Kept trivial — we only need this on the sad path.
func srvPort(_ *approvalserver.Server, localURL string) int {
	// Find "://<host>:<port>/". Trust the input shape.
	i := strings.Index(localURL, "://")
	if i < 0 {
		return 0
	}
	rest := localURL[i+3:]
	colon := strings.IndexByte(rest, ':')
	if colon < 0 {
		return 0
	}
	after := rest[colon+1:]
	slash := strings.IndexByte(after, '/')
	if slash < 0 {
		slash = len(after)
	}
	p := 0
	for _, r := range after[:slash] {
		if r < '0' || r > '9' {
			return 0
		}
		p = p*10 + int(r-'0')
	}
	return p
}

// writeQRPNG renders a QR code encoding text as a PNG at path (mode
// 0644). Uses rsc.io/qr for encoding — already vendored via qrterminal.
// A silent no-op if we can't create the target directory (a warning is
// fine — the terminal render still works).
func writeQRPNG(text, path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	c, err := qr.Encode(text, qr.M)
	if err != nil {
		return err
	}
	// v1.9.9 — cap the total canvas at 500x500 so chat relays that
	// reject large image dimensions (413 "image dimensions too large")
	// accept the file. c.Size is the QR module count (per side). Compute
	// scale dynamically: (modules + 2*quiet) * scale ≤ targetPx. Enforce
	// a minimum scale of 4 so modules stay chunky enough to scan after
	// chat compression, even for longer URLs (higher QR version).
	//
	// NOTE: c.Image() returns an already-scaled image at (Size+8)*c.Scale
	// pixels — we do NOT use c.Image().Bounds() for the module count.
	modules := c.Size
	const targetPx = 500
	const quietModules = 2
	scale := targetPx / (modules + 2*quietModules)
	if scale < 4 {
		scale = 4
	}
	w, h := modules*scale, modules*scale
	quiet := quietModules * scale
	img := image.NewNRGBA(image.Rect(0, 0, w+2*quiet, h+2*quiet))
	white := color.NRGBA{255, 255, 255, 255}
	for y := img.Rect.Min.Y; y < img.Rect.Max.Y; y++ {
		for x := img.Rect.Min.X; x < img.Rect.Max.X; x++ {
			img.Set(x, y, white)
		}
	}
	// c.Black(mx, my) samples in module coordinates (0..modules-1).
	black := color.NRGBA{0, 0, 0, 255}
	for my := 0; my < modules; my++ {
		for mx := 0; mx < modules; mx++ {
			if !c.Black(mx, my) {
				continue
			}
			x0 := quiet + mx*scale
			y0 := quiet + my*scale
			for dy := 0; dy < scale; dy++ {
				for dx := 0; dx < scale; dx++ {
					img.Set(x0+dx, y0+dy, black)
				}
			}
		}
	}
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return png.Encode(f, img)
}

// displayHost turns the bind address into a URL-friendly host. If the
// caller bound to 0.0.0.0 (LAN mode), we discover the first non-loopback
// IPv4 so the printed URL is actually reachable from a phone.
func displayHost(bind string) string {
	if bind != "0.0.0.0" && bind != "" && bind != "::" {
		return bind
	}
	ifaces, err := net.Interfaces()
	if err != nil {
		return "127.0.0.1"
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := i.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			v4 := ipnet.IP.To4()
			if v4 == nil || v4.IsLoopback() || v4.IsLinkLocalUnicast() {
				continue
			}
			return v4.String()
		}
	}
	return "127.0.0.1"
}

// v1.11 — loadAgentKey was removed. Callers now use
// internal/agentkey.Open which supports both the legacy file-backed
// ed25519 keys AND the new SE-backed P-256 keys transparently.

// v1.13.0-rc11 — runClaimStatusNoBearer answers "what's pending on
// this machine?" without requiring the operator to re-supply the
// bearer. Scans the local pending-claims directory via
// pendingclaim.List. Unambiguous → report state. Multiple → list
// subjects + lookup prefixes + ask operator to narrow with
// $DOP_TOKEN. Zero → nothing to report.
func runClaimStatusNoBearer(paths *config.Paths, asJSON bool) int {
	// v1.13.0-rc17 — reap stale pending-claim files before listing so
	// orphans from SIGKILL/power-loss don't pollute the status output.
	// Non-fatal: if the reaper hits an fs error we just continue with
	// whatever we can read.
	if reaped, _ := pendingclaim.Reap(paths); len(reaped) > 0 && !asJSON {
		fmt.Fprintf(os.Stderr, "dop claim --status: reaped %d stale pending claim(s)\n", len(reaped))
	}
	recs, err := pendingclaim.List(paths)
	if err != nil {
		if asJSON {
			emitJSON(map[string]any{"event": "status", "state": "error", "error": err.Error()})
		} else {
			fmt.Fprintf(os.Stderr, "dop claim --status: %v\n", err)
		}
		return 1
	}
	if len(recs) == 0 {
		if asJSON {
			emitJSON(map[string]any{"event": "status", "state": "absent", "note": "no pending claims on this machine"})
		} else {
			fmt.Fprintln(os.Stderr, "dop claim --status: no pending claims on this machine")
		}
		return 0
	}
	if len(recs) == 1 {
		return runClaimStatusEmit(recs[0], asJSON)
	}
	// Multiple — enumerate so the operator can disambiguate.
	if asJSON {
		items := make([]map[string]any, 0, len(recs))
		for _, r := range recs {
			items = append(items, map[string]any{
				"state":      r.State,
				"subject":    r.Subject,
				"lookup_id":  r.LookupID,
				"sas":        r.SAS,
				"expires_at": r.ExpiresAt.Format(time.RFC3339),
			})
		}
		emitJSON(map[string]any{"event": "status", "state": "multiple", "pending": items})
	} else {
		fmt.Fprintf(os.Stderr, "dop claim --status: %d pending claims on this machine — set $DOP_TOKEN to narrow:\n", len(recs))
		for _, r := range recs {
			fmt.Fprintf(os.Stderr, "  subject=%s  lookup=%s  sas=%s  state=%s  expires=%s\n",
				r.Subject, r.LookupID[:12], r.SAS, r.State, r.ExpiresAt.Format(time.RFC3339))
		}
	}
	return 0
}

// runClaimCancelNoBearer cancels the pending claim when exactly one
// exists on this machine. Multiple → refuse (operator must narrow
// with $DOP_TOKEN). Zero → say so.
func runClaimCancelNoBearer(paths *config.Paths, asJSON bool) int {
	recs, err := pendingclaim.List(paths)
	if err != nil {
		if asJSON {
			emitJSON(map[string]any{"event": "cancel", "state": "error", "error": err.Error()})
		} else {
			fmt.Fprintf(os.Stderr, "dop claim --cancel: %v\n", err)
		}
		return 1
	}
	if len(recs) == 0 {
		if asJSON {
			emitJSON(map[string]any{"event": "cancel", "state": "absent", "note": "no pending claims on this machine"})
		} else {
			fmt.Fprintln(os.Stderr, "dop claim --cancel: no pending claims on this machine")
		}
		return 0
	}
	if len(recs) > 1 {
		if asJSON {
			emitJSON(map[string]any{"event": "cancel", "state": "ambiguous", "count": len(recs), "note": "set $DOP_TOKEN to narrow"})
		} else {
			fmt.Fprintf(os.Stderr, "dop claim --cancel: %d pending claims on this machine — set $DOP_TOKEN to pick one.\n", len(recs))
		}
		return 1
	}
	// Exactly one.
	r := recs[0]
	if err := pendingclaim.Delete(paths, r.LookupID); err != nil {
		if asJSON {
			emitJSON(map[string]any{"event": "cancel", "state": "error", "error": err.Error()})
		} else {
			fmt.Fprintf(os.Stderr, "dop claim --cancel: %v\n", err)
		}
		return 1
	}
	if asJSON {
		emitJSON(map[string]any{"event": "cancel", "state": "cancelled", "lookup_id": r.LookupID, "subject": r.Subject})
	} else {
		fmt.Fprintf(os.Stderr, "dop claim --cancel: pending claim cleared (subject=%s lookup=%s)\n", r.Subject, r.LookupID[:12])
	}
	return 0
}

// runClaimStatusEmit renders one pending-claim record in the format
// expected by `dop claim --status`. Shared between the bearer-known
// and no-bearer code paths.
func runClaimStatusEmit(r *pendingclaim.Record, asJSON bool) int {
	ttl := time.Until(r.ExpiresAt).Truncate(time.Second).String()
	if time.Until(r.ExpiresAt) < 0 {
		ttl = "expired"
	}
	if asJSON {
		emitJSON(map[string]any{
			"event":         "status",
			"state":         r.State,
			"sas":           r.SAS,
			"subject":       r.Subject,
			"lookup_id":     r.LookupID,
			"started_at":    r.StartedAt.Format(time.RFC3339),
			"expires_at":    r.ExpiresAt.Format(time.RFC3339),
			"ttl":           ttl,
			"failure_count": r.FailureCount,
		})
	} else {
		fmt.Fprintf(os.Stderr, "dop claim --status: subject=%s state=%s sas=%s ttl=%s\n",
			r.Subject, r.State, r.SAS, ttl)
	}
	return 0
}
