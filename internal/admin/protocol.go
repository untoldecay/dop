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
	OpStatus          = "status"
	OpKeepAlive       = "keep_alive"
	OpLogout          = "logout"
	OpSign            = "sign"
	OpDecryptVault    = "decrypt_vault" // Phase 3
	OpEncryptVault    = "encrypt_vault" // Phase 3
	OpUnwrapAdminUse  = "unwrap_admin_use" // v1.14.0-rc1 — `dop use`
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

// UnwrapAdminUseReq — v1.14.0-rc1. Payload of OpUnwrapAdminUse.
// The daemon decrypts CiphertextB64 with the admin's age identity;
// the plaintext is a bearer value stashed on a capability record
// at `token issue --for-admin-use` time.
type UnwrapAdminUseReq struct {
	CiphertextB64 string `json:"ciphertext_b64"`
}

// UnwrapAdminUseResp — bearer plaintext as base64 (same convention
// as DecryptVaultResp — JSON doesn't love binary, and bearer is
// opaque enough that base64 is the clean carrier).
type UnwrapAdminUseResp struct {
	PlaintextB64 string `json:"plaintext_b64"`
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
