// Client-side of the admin session: connects to the daemon's unix socket
// and invokes RPCs.

package admin

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"time"
)

// Client is a single-shot connection to the session daemon. Not
// concurrent-safe. Instantiate a fresh Client per RPC.
type Client struct {
	sockPath string
}

// NewClient returns a Client for the given socket path. Does not
// actually connect until an RPC is invoked.
func NewClient(sockPath string) *Client {
	return &Client{sockPath: sockPath}
}

// SessionActive returns true if the socket exists AND the daemon
// reports an unlocked session. False for "no session", "dead socket"
// or a daemon that answers but is locked.
func (c *Client) SessionActive() bool {
	if _, err := os.Stat(c.sockPath); err != nil {
		return false
	}
	st, err := c.Status()
	return err == nil && st.Unlocked
}

func (c *Client) call(req Request) (Response, error) {
	conn, err := net.DialTimeout("unix", c.sockPath, 2*time.Second)
	if err != nil {
		return Response{}, err
	}
	defer conn.Close()
	if err := WriteMessage(conn, req); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := ReadMessage(conn, &resp); err != nil {
		return Response{}, err
	}
	if !resp.OK {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

// Status queries session state.
func (c *Client) Status() (*StatusResp, error) {
	resp, err := c.call(Request{Op: OpStatus})
	if err != nil {
		return nil, err
	}
	var s StatusResp
	if err := json.Unmarshal(resp.Data, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// KeepAlive bumps the idle timer.
func (c *Client) KeepAlive() error {
	_, err := c.call(Request{Op: OpKeepAlive})
	return err
}

// SetTTL changes the running session's idle and absolute TTLs.
func (c *Client) SetTTL(idle, abs time.Duration) error {
	req, _ := json.Marshal(SetTTLReq{IdleTTLSeconds: int64(idle / time.Second), AbsTTLSeconds: int64(abs / time.Second)})
	_, err := c.call(Request{Op: OpSetTTL, Data: req})
	return err
}

// Logout kills the session.
func (c *Client) Logout() error {
	_, err := c.call(Request{Op: OpLogout})
	if err != nil {
		// If the daemon has already gone away, that's still success.
		return nil
	}
	return nil
}

// Sign signs an arbitrary byte blob with the session's ed25519 key.
func (c *Client) Sign(data []byte) ([]byte, error) {
	req, _ := json.Marshal(SignReq{DataHex: hex.EncodeToString(data)})
	resp, err := c.call(Request{Op: OpSign, Data: req})
	if err != nil {
		return nil, err
	}
	var s SignResp
	if err := json.Unmarshal(resp.Data, &s); err != nil {
		return nil, err
	}
	return hex.DecodeString(s.SigHex)
}

// DecryptVault reads the SOPS-encrypted vault file at path and returns
// its plaintext. Phase 3+ callers use this.
func (c *Client) DecryptVault(vaultPath string) ([]byte, error) {
	req, _ := json.Marshal(DecryptVaultReq{VaultPath: vaultPath})
	resp, err := c.call(Request{Op: OpDecryptVault, Data: req})
	if err != nil {
		return nil, err
	}
	var d DecryptVaultResp
	if err := json.Unmarshal(resp.Data, &d); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(d.PlaintextB64)
}

// EncryptVault writes plaintext to vaultPath after encrypting it with the
// given age recipient.
func (c *Client) EncryptVault(vaultPath string, plaintext []byte, ageRecipient string) error {
	req, _ := json.Marshal(EncryptVaultReq{
		VaultPath:    vaultPath,
		PlaintextB64: base64.StdEncoding.EncodeToString(plaintext),
		AgeRecipient: ageRecipient,
	})
	_, err := c.call(Request{Op: OpEncryptVault, Data: req})
	return err
}

// UnwrapPortable — v1.14.0-rc1. Decrypts an portable-stashed bearer
// value via the daemon's age identity. Used by `dop use <subject>`.
func (c *Client) UnwrapPortable(ciphertextB64 string) ([]byte, error) {
	req, _ := json.Marshal(UnwrapPortableReq{CiphertextB64: ciphertextB64})
	resp, err := c.call(Request{Op: OpUnwrapPortable, Data: req})
	if err != nil {
		return nil, err
	}
	var r UnwrapPortableResp
	if err := json.Unmarshal(resp.Data, &r); err != nil {
		return nil, err
	}
	return base64.StdEncoding.DecodeString(r.PlaintextB64)
}

// ApprovalPopup — v1.14.0-rc4. Asks the daemon to show a native approval
// dialog and verify the typed passphrase. Blocking: waits up to the
// server-side timeout (default 60s) for a human response. Returns the
// decision ("approved", "denied", "timeout", "unsupported") plus an
// optional reason string. Callers get "unsupported" when the daemon
// can't show a native dialog on this platform; standard fallback is
// the tunnel+phone flow.
//
// Kind is a short tag the daemon uses to format the dialog title +
// audit the decision. Subject names the thing being approved.
// PromptText (optional) is the human-readable body; the daemon
// synthesizes a default when empty.
func (c *Client) ApprovalPopup(kind, subject, promptText string, timeout time.Duration) (string, string, error) {
	req, _ := json.Marshal(ApprovalPopupReq{
		Kind:       kind,
		Subject:    subject,
		PromptText: promptText,
		TimeoutMs:  int(timeout.Milliseconds()),
	})
	resp, err := c.call(Request{Op: OpApprovalPopup, Data: req})
	if err != nil {
		return "", "", err
	}
	var r ApprovalPopupResp
	if err := json.Unmarshal(resp.Data, &r); err != nil {
		return "", "", err
	}
	return r.Decision, r.Reason, nil
}

// ShellTrustCheck — v1.14.0-rc6. Asks the daemon whether the current
// shell PID is already trusted for the given subject on the eval/pipe
// print path. Non-fatal: any error returns false (safe default).
func (c *Client) ShellTrustCheck(pid int, subject string) (bool, error) {
	req, _ := json.Marshal(ShellTrustReq{PID: pid, Subject: subject, Mode: "check"})
	resp, err := c.call(Request{Op: OpShellTrust, Data: req})
	if err != nil {
		return false, err
	}
	var r ShellTrustResp
	if err := json.Unmarshal(resp.Data, &r); err != nil {
		return false, err
	}
	return r.Trusted, nil
}

// ShellTrustMark — v1.14.0-rc6. Records (PID, subject) in the daemon's
// in-memory trust cache so subsequent same-shell/same-subject eval
// invocations skip the approval popup.
func (c *Client) ShellTrustMark(pid int, subject string) error {
	req, _ := json.Marshal(ShellTrustReq{PID: pid, Subject: subject, Mode: "mark"})
	_, err := c.call(Request{Op: OpShellTrust, Data: req})
	return err
}

// TrustContextCheck — v1.14.0-rc6i. Replaces ShellTrustCheck.
// kind+value identify the operator-approved execution context (built
// by sessiontrust.Resolve); subject names the vault subject the
// approval applies to. Non-fatal: any error returns false.
func (c *Client) TrustContextCheck(kind, value, subject string) (bool, error) {
	req, _ := json.Marshal(TrustContextReq{
		ContextKind:  kind,
		ContextValue: value,
		Subject:      subject,
		Mode:         "check",
	})
	resp, err := c.call(Request{Op: OpTrustContext, Data: req})
	if err != nil {
		return false, err
	}
	var r TrustContextResp
	if err := json.Unmarshal(resp.Data, &r); err != nil {
		return false, err
	}
	return r.Trusted, nil
}

// TrustContextMark — v1.14.0-rc6i. Replaces ShellTrustMark.
func (c *Client) TrustContextMark(kind, value, subject string) error {
	req, _ := json.Marshal(TrustContextReq{
		ContextKind:  kind,
		ContextValue: value,
		Subject:      subject,
		Mode:         "mark",
	})
	_, err := c.call(Request{Op: OpTrustContext, Data: req})
	return err
}

// TrustContextList returns every active grant in the daemon's cache.
// Operators use this via `dop trust list` to see what approvals are
// in flight + when they'll idle-expire.
func (c *Client) TrustContextList() ([]TrustGrantInfo, error) {
	req, _ := json.Marshal(TrustContextReq{Mode: "list"})
	resp, err := c.call(Request{Op: OpTrustContext, Data: req})
	if err != nil {
		return nil, err
	}
	var r TrustContextResp
	if err := json.Unmarshal(resp.Data, &r); err != nil {
		return nil, err
	}
	return r.Grants, nil
}

// TrustContextRevoke drops a single grant from the cache. Pass empty
// strings + revokeAll=true to drop every grant.
func (c *Client) TrustContextRevoke(kind, value, subject string, revokeAll bool) (int, error) {
	req, _ := json.Marshal(TrustContextReq{
		ContextKind:  kind,
		ContextValue: value,
		Subject:      subject,
		Mode:         "revoke",
		RevokeAll:    revokeAll,
	})
	resp, err := c.call(Request{Op: OpTrustContext, Data: req})
	if err != nil {
		return 0, err
	}
	var r TrustContextResp
	if err := json.Unmarshal(resp.Data, &r); err != nil {
		return 0, err
	}
	return r.Revoked, nil
}

// SockPath returns the socket path this client is talking to.
func (c *Client) SockPath() string { return c.sockPath }

// Format helper used elsewhere.
func fmtBytes(n int) string { return fmt.Sprintf("%d B", n) }
