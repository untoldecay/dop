// Wire protocol for the admin session's unix socket.
//
// Length-prefixed JSON. Every message on the socket:
//   [4-byte big-endian length][json bytes]
//
// Requests carry an Op; responses carry OK or Error. Op-specific data
// travels as json.RawMessage in Data.

package admin

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

type Request struct {
	Op   string          `json:"op"`
	Data json.RawMessage `json:"data,omitempty"`
}

type Response struct {
	OK    bool            `json:"ok"`
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

// Op constants — one exported for each supported RPC. Adding new ops
// requires bumping the protocol version if they break existing clients;
// Phase 2 has no backwards-compat concerns because there are no other
// callers yet.
const (
	OpStatus         = "status"
	OpKeepAlive      = "keep_alive"
	OpLogout         = "logout"
	OpSign           = "sign"
	OpDecryptVault   = "decrypt_vault"   // Phase 3
	OpEncryptVault   = "encrypt_vault"   // Phase 3
	OpUnwrapPortable = "unwrap_portable" // v1.14.0-rc1 — `dop use`
	// v1.14.0-rc4 — local approval popup. Daemon runs osascript
	// in-process, verifies the typed passphrase against approval.hash,
	// returns decision synchronously. The passphrase never leaves the
	// daemon process. Callers (print surfaces + claim flow) use this
	// as the LOCAL fast-path; they fall back to the tunnel+phone flow
	// when the daemon isn't reachable or the popup times out.
	OpApprovalPopup = "approval_popup"
	// v1.14.0-rc6 — shell-trust cache for the eval/pipe pattern. rc6i
	// supersedes this with OpTrustContext (richer context + metadata +
	// idle TTL). OpShellTrust retained for one release cycle so an
	// older daemon upgraded alongside a newer CLI (or vice-versa)
	// doesn't fail hard.
	OpShellTrust = "shell_trust"
	// v1.14.0-rc6i — trust-context cache. Replaces the rc6 shell-trust
	// cache. Keyed by `<ContextKind>:<ContextValue>:<Subject>`; the CLI
	// builds the context via internal/sessiontrust (DOP_SESSION_ID →
	// recognized harness adapter → tty → getsid() → ppid). The daemon
	// stores grants with CreatedAt + LastUsedAt metadata; grants expire
	// after idle TTL (default 30m). Logout clears everything.
	OpTrustContext = "trust_context"
)

// StatusResp is the payload of an `OpStatus` response.
type StatusResp struct {
	Unlocked          bool   `json:"unlocked"`
	AdminPubkey       string `json:"admin_pubkey"`
	IdleTTLSeconds    int64  `json:"idle_ttl_seconds"`
	AbsTTLSeconds     int64  `json:"abs_ttl_seconds"`
	AgeRecipient      string `json:"age_recipient"`
	StartedAtUnix     int64  `json:"started_at_unix"`
	LastActivityUnix  int64  `json:"last_activity_unix"`
}

// SignReq is the payload of an `OpSign` request.
type SignReq struct {
	DataHex string `json:"data_hex"`
}

// SignResp is the payload of an `OpSign` response.
type SignResp struct {
	SigHex string `json:"sig_hex"`
}

// DecryptVaultReq — Phase 3.
type DecryptVaultReq struct {
	VaultPath string `json:"vault_path"`
}

// DecryptVaultResp — plaintext bytes as base64 to keep JSON safe.
type DecryptVaultResp struct {
	PlaintextB64 string `json:"plaintext_b64"`
}

// EncryptVaultReq — Phase 3. Writes encrypted output to VaultPath.
type EncryptVaultReq struct {
	VaultPath    string `json:"vault_path"`
	PlaintextB64 string `json:"plaintext_b64"`
	AgeRecipient string `json:"age_recipient"` // recipient(s) for encryption
}

// UnwrapPortableReq — v1.14.0-rc1. Payload of OpUnwrapPortable.
// The daemon decrypts CiphertextB64 with the admin's age identity;
// the plaintext is a bearer value stashed on a capability record
// at `token issue --portable` time.
type UnwrapPortableReq struct {
	CiphertextB64 string `json:"ciphertext_b64"`
}

// UnwrapPortableResp — bearer plaintext as base64 (same convention
// as DecryptVaultResp — JSON doesn't love binary, and bearer is
// opaque enough that base64 is the clean carrier).
type UnwrapPortableResp struct {
	PlaintextB64 string `json:"plaintext_b64"`
}

// ApprovalPopupReq — v1.14.0-rc4. Caller supplies the human-readable
// prompt text that will appear in the OS dialog. The daemon decides
// which platform-specific dialog to render.
//
// `Kind` is a short tag (`claim`, `print_use`, `print_issue`, `print_env`)
// that lets the daemon customize the dialog title AND audit the
// decision with the right event. `Subject` is the specific thing being
// approved (bearer subject, grant id, etc.) — surfaces in both the
// dialog and the audit event.
type ApprovalPopupReq struct {
	Kind       string `json:"kind"`
	Subject    string `json:"subject"`
	PromptText string `json:"prompt_text"`
	// TimeoutMs bounds the dialog's wait. 0 → daemon default (60s).
	TimeoutMs int `json:"timeout_ms,omitempty"`
}

// ShellTrustReq — v1.14.0-rc6. Legacy shape; retained for one release
// cycle so a daemon upgraded ahead of (or behind) its CLI doesn't fail
// hard. New callers use TrustContextReq.
type ShellTrustReq struct {
	PID     int    `json:"pid"`
	Subject string `json:"subject"`
	Mode    string `json:"mode"` // "check" | "mark"
}

// ShellTrustResp — Trusted=true means the (PID, subject) is in the
// cache. Legacy; see TrustContextResp.
type ShellTrustResp struct {
	Trusted bool `json:"trusted"`
}

// TrustContextReq — v1.14.0-rc6i. Replaces ShellTrustReq.
//
// ContextKind + ContextValue identify the operator-approved execution
// context (built by the CLI via internal/sessiontrust.Resolve()).
// Subject is the vault subject the approval was granted for. Mode is
// "check" (returns Trusted + metadata), "mark" (records a grant),
// "list" (returns ALL active grants — ignores Subject), or "revoke"
// (removes one or all grants).
type TrustContextReq struct {
	ContextKind  string `json:"context_kind"`
	ContextValue string `json:"context_value"`
	Subject      string `json:"subject"`
	Mode         string `json:"mode"` // "check" | "mark" | "list" | "revoke"
	// RevokeAll — when Mode=="revoke" and this is true, drop every
	// grant in the cache. Mutually exclusive with ContextKind+Subject
	// (which revoke a single matching entry).
	RevokeAll bool `json:"revoke_all,omitempty"`
}

// TrustGrantInfo — one row returned by the "list" mode.
type TrustGrantInfo struct {
	ContextKind  string `json:"context_kind"`
	ContextValue string `json:"context_value"`
	Subject      string `json:"subject"`
	CreatedUnix  int64  `json:"created_unix"`
	LastUsedUnix int64  `json:"last_used_unix"`
	// Source names the surface that originally granted the trust
	// (e.g. "print_use/local", "print_env/phone") — purely for
	// operator-facing observability via `dop trust list`.
	Source string `json:"source,omitempty"`
}

// TrustContextResp — unified response. Trusted is set for "check".
// Grants is set for "list". Revoked is a count for "revoke".
type TrustContextResp struct {
	Trusted bool             `json:"trusted,omitempty"`
	Grants  []TrustGrantInfo `json:"grants,omitempty"`
	Revoked int              `json:"revoked,omitempty"`
}

// ApprovalPopupResp — the daemon's verdict.
//
// Approved = passphrase typed and verified.
// Denied   = operator clicked Deny.
// Timeout  = dialog didn't close within TimeoutMs.
// Unsupported = running on a platform without a native dialog (Linux,
//               headless container, DOP_NO_POPUP=1). Caller MUST fall
//               back to the tunnel+phone flow.
type ApprovalPopupResp struct {
	Decision string `json:"decision"` // "approved" | "denied" | "timeout" | "unsupported"
	Reason   string `json:"reason,omitempty"`
}

// --- Wire helpers ---

// WriteMessage frames + writes a JSON message to w.
func WriteMessage(w io.Writer, v any) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(body)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	return nil
}

// ReadMessage reads a framed JSON message from r into v.
func ReadMessage(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	// Guard against runaway messages. 10 MB ceiling covers even a
	// decrypted-vault response comfortably.
	if n > 10*1024*1024 {
		return fmt.Errorf("message too large: %d bytes", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}
