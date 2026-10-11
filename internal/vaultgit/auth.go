package vaultgit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/go-git/go-git/v5/plumbing/transport"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"
	gitssh "github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// How dop logs in to the vault repo, first that works wins:
//
//	https:  DOP_REPO_TOKEN → a token dop stored for the host (SaveToken)
//	        → git's own credential helpers, only if git is installed
//	        (`git credential fill`: the macOS keychain, gh, …) → anonymous
//	ssh:    the SSH agent → ~/.ssh/id_ed25519, id_ecdsa, id_rsa
//	        (unencrypted), checked against ~/.ssh/known_hosts
//	file:   nothing needed
//
// A candidate is dropped when the server refuses it, and the next one
// is tried — so a stale stored token falls through to the keychain.

// CredentialsPath is where SaveToken keeps repo tokens (0600 JSON). The
// caller sets it to <dop root>/repo-credentials.json.
var CredentialsPath string

type storedCred struct {
	Username string `json:"username"`
	Token    string `json:"token"`
}

// SaveToken stores a token for host (e.g. "github.com"). Username may
// be empty: GitHub and GitLab accept any name with a token.
func SaveToken(host, username, token string) error {
	if CredentialsPath == "" {
		return errors.New("no credentials path configured")
	}
	all := readStored()
	all[strings.ToLower(host)] = storedCred{Username: username, Token: token}
	b, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(CredentialsPath), 0o700); err != nil {
		return err
	}
	tmp := CredentialsPath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, CredentialsPath)
}

// ForgetToken removes the stored token for host.
func ForgetToken(host string) error {
	all := readStored()
	if _, ok := all[strings.ToLower(host)]; !ok {
		return nil
	}
	delete(all, strings.ToLower(host))
	b, _ := json.MarshalIndent(all, "", "  ")
	return os.WriteFile(CredentialsPath, b, 0o600)
}

// HasToken reports whether a token is stored for host.
func HasToken(host string) bool {
	_, ok := readStored()[strings.ToLower(host)]
	return ok
}

func readStored() map[string]storedCred {
	out := map[string]storedCred{}
	if CredentialsPath == "" {
		return out
	}
	b, err := os.ReadFile(CredentialsPath)
	if err != nil {
		return out
	}
	_ = json.Unmarshal(b, &out)
	return out
}

// Host returns the host of a repo URL ("" for local paths).
func Host(url string) string {
	ep, err := transport.NewEndpoint(url)
	if err != nil || ep.Protocol == "file" {
		return ""
	}
	return ep.Host
}

type candidate struct {
	name string
	auth transport.AuthMethod
}

// helperCache keeps what git's credential helpers returned, per host,
// for the life of the process (one keychain lookup per command).
var (
	helperMu    sync.Mutex
	helperCache = map[string]*githttp.BasicAuth{}
)

func candidates(url string) ([]candidate, error) {
	ep, err := transport.NewEndpoint(url)
	if err != nil {
		return nil, err
	}
	switch ep.Protocol {
	case "file":
		return []candidate{{"none", nil}}, nil
	case "ssh":
		return sshCandidates(ep)
	}
	var cs []candidate
	if t := os.Getenv("DOP_REPO_TOKEN"); t != "" {
		cs = append(cs, candidate{"DOP_REPO_TOKEN", basic("", t)})
	}
	if c, ok := readStored()[strings.ToLower(ep.Host)]; ok && c.Token != "" {
		cs = append(cs, candidate{"stored token", basic(c.Username, c.Token)})
	}
	if a := gitHelperAuth(ep); a != nil {
		cs = append(cs, candidate{"git credential helper", a})
	}
	cs = append(cs, candidate{"anonymous", nil})
	return cs, nil
}

func basic(user, token string) *githttp.BasicAuth {
	if user == "" {
		user = "x-access-token"
	}
	return &githttp.BasicAuth{Username: user, Password: token}
}

// gitHelperAuth asks git's configured credential helpers, when git is
// installed. GIT_TERMINAL_PROMPT=0: never prompt on a terminal.
func gitHelperAuth(ep *transport.Endpoint) *githttp.BasicAuth {
	if os.Getenv("DOP_NO_GIT_CREDENTIAL") == "1" {
		return nil
	}
	key := ep.Protocol + "://" + ep.Host
	helperMu.Lock()
	defer helperMu.Unlock()
	if a, ok := helperCache[key]; ok {
		return a
	}
	helperCache[key] = nil
	bin, err := exec.LookPath("git")
	if err != nil {
		return nil
	}
	host := ep.Host
	if ep.Port != 0 && ep.Port != 443 && ep.Port != 80 {
		host = net.JoinHostPort(ep.Host, fmt.Sprint(ep.Port))
	}
	cmd := exec.Command(bin, "credential", "fill")
	cmd.Stdin = strings.NewReader(fmt.Sprintf("protocol=%s\nhost=%s\n\n", ep.Protocol, host))
	cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_ASKPASS=", "SSH_ASKPASS=")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return nil
	}
	var user, pass string
	sc := bufio.NewScanner(&out)
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), "=")
		switch k {
		case "username":
			user = v
		case "password":
			pass = v
		}
	}
	if pass == "" {
		return nil
	}
	a := basic(user, pass)
	helperCache[key] = a
	return a
}

func sshCandidates(ep *transport.Endpoint) ([]candidate, error) {
	user := ep.User
	if user == "" {
		user = "git"
	}
	hostKeys, err := hostKeyCallback()
	if err != nil {
		return nil, err
	}
	var cs []candidate
	if os.Getenv("SSH_AUTH_SOCK") != "" {
		if a, err := gitssh.NewSSHAgentAuth(user); err == nil {
			a.HostKeyCallback = hostKeys
			cs = append(cs, candidate{"ssh agent", a})
		}
	}
	home, _ := os.UserHomeDir()
	for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
		p := filepath.Join(home, ".ssh", name)
		if _, err := os.Stat(p); err != nil {
			continue
		}
		a, err := gitssh.NewPublicKeysFromFile(user, p, "")
		if err != nil {
			continue // passphrase-protected: only usable through the agent
		}
		a.HostKeyCallback = hostKeys
		cs = append(cs, candidate{"ssh key " + name, a})
	}
	if len(cs) == 0 {
		return nil, errors.New("no SSH key found: start ssh-agent with your key loaded, or use an https:// vault URL with a repo token")
	}
	return cs, nil
}

func hostKeyCallback() (ssh.HostKeyCallback, error) {
	home, _ := os.UserHomeDir()
	files := []string{filepath.Join(home, ".ssh", "known_hosts")}
	if env := os.Getenv("SSH_KNOWN_HOSTS"); env != "" {
		files = filepath.SplitList(env)
	}
	var existing []string
	for _, f := range files {
		if _, err := os.Stat(f); err == nil {
			existing = append(existing, f)
		}
	}
	if len(existing) == 0 {
		return nil, errors.New("no ~/.ssh/known_hosts: connect once with `ssh -T git@<host>` to trust the server, or use an https:// vault URL")
	}
	return knownhosts.New(existing...)
}

// isAuthError reports a refusal that the next candidate might fix.
func isAuthError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, transport.ErrAuthenticationRequired) || errors.Is(err, transport.ErrAuthorizationFailed) {
		return true
	}
	// GitHub answers an unknown/private repo without valid auth with
	// "repository not found"; ssh refusals come back as handshake errors.
	if errors.Is(err, transport.ErrRepositoryNotFound) {
		return true
	}
	s := err.Error()
	return strings.Contains(s, "unable to authenticate") || strings.Contains(s, "no supported methods remain")
}

// withAuth runs op with each login candidate until one isn't refused.
func withAuth(url string, op func(transport.AuthMethod) error) error {
	if url == "" {
		return errors.New("the vault repo has no origin remote")
	}
	cs, err := candidates(url)
	if err != nil {
		return err
	}
	var last error
	for _, c := range cs {
		err := op(c.auth)
		if !isAuthError(err) {
			return err
		}
		last = err
	}
	if host := Host(url); host != "" && !strings.HasPrefix(url, "git@") && !strings.HasPrefix(url, "ssh://") {
		return fmt.Errorf("%w — %s refused every login dop tried. Save a repo token: dop vault login %s", last, host, host)
	}
	return last
}
