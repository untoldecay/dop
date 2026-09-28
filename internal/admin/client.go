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

// SessionActive returns true if the socket exists AND a status RPC
// succeeds. False for "no session" or "dead socket".
func (c *Client) SessionActive() bool {
	if _, err := os.Stat(c.sockPath); err != nil {
		return false
	}
	_, err := c.Status()
	return err == nil
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

// SockPath returns the socket path this client is talking to.
func (c *Client) SockPath() string { return c.sockPath }

// Format helper used elsewhere.
func fmtBytes(n int) string { return fmt.Sprintf("%d B", n) }
