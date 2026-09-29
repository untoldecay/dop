// dop-credential-git — git credential helper backed by DOP.
//
// Usage (once, per user):
//
//   git config --global credential.helper 'dop-credential-git'
//
// Then map the hosts you want DOP to answer for:
//
//   dop credential-helper map --host github.com --grant github.readonly
//   dop credential-helper map --host ssh.dev.azure.com --grant azure.devops --username dop
//
// Protocol: git invokes us with argv[1] in {get, store, erase} and
// stdin containing lines like `protocol=https`, `host=github.com`,
// `path=owner/repo.git`, terminated by a blank line. We answer on
// stdout with `username=<name>\npassword=<token>\n\n` for `get`, or
// nothing at all when we don't have a credential (git will then try
// the next helper in its chain).
//
// This binary NEVER touches vault.yaml. It only:
//   1. Reads the bearer from $DOP_TOKEN (or DOP_TOKEN_FILE).
//   2. Reads credential-map.yaml.
//   3. Runs `dop env` in-process (as a library call is cleaner, but the
//      simplest v1 shim shells out) to get the injected env for that
//      bearer.
//   4. Extracts the matched grant's `<PREFIX>_TOKEN` and returns it.
//
// See Buzz's `git-credential-nostr` for the pattern this follows.

package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/fray/dop/internal/capability"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/credmap"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: dop-credential-git <get|store|erase>")
		os.Exit(2)
	}
	op := os.Args[1]
	// store + erase: git tells us to remember / forget a credential.
	// We don't cache anything (bearer holds the truth), so both are
	// silent no-ops. This is a valid credential-helper contract.
	if op == "store" || op == "erase" {
		_, _ = io.Copy(io.Discard, os.Stdin)
		return
	}
	if op != "get" {
		fmt.Fprintf(os.Stderr, "dop-credential-git: unknown op %q\n", op)
		os.Exit(2)
	}
	req := readCredentialRequest(os.Stdin)
	host := req["host"]
	if host == "" {
		// git didn't tell us a host — decline silently so the next
		// helper gets a chance.
		return
	}

	paths, err := config.Resolve()
	if err != nil {
		return
	}
	cmap, err := credmap.Load(paths)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop-credential-git: %v\n", err)
		return
	}
	entry := cmap.Match(host)
	if entry == nil {
		return // no mapping → decline
	}

	bearer := readBearer()
	if bearer == "" {
		fmt.Fprintln(os.Stderr, "dop-credential-git: no DOP_TOKEN set (git will try next helper)")
		return
	}
	env, err := resolveEnvForShim(paths, bearer)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop-credential-git: %v\n", err)
		return
	}
	prefix := entry.EnvPrefix
	if prefix == "" {
		// Auto-derive: the grant name looks like "notion.read" — take
		// the first segment upper-cased. Callers can override via the
		// env_prefix field in credential-map.yaml.
		prefix = strings.SplitN(entry.Grant, ".", 2)[0]
	}
	tokenKey := strings.ToUpper(prefix) + "_TOKEN"
	pw, ok := env[tokenKey]
	if !ok || pw == "" {
		fmt.Fprintf(os.Stderr, "dop-credential-git: bearer has no %s (grant %s not in this bearer's scope?)\n",
			tokenKey, entry.Grant)
		return
	}
	username := entry.Username
	if username == "" {
		username = "dop"
	}
	// Preserve any fields git sent, add ours. Never echo secrets to stderr.
	fmt.Fprintf(os.Stdout, "protocol=%s\nhost=%s\nusername=%s\npassword=%s\n\n",
		req["protocol"], req["host"], username, pw)
}

// readCredentialRequest parses the git-credential protocol: KEY=VALUE
// lines, terminated by a blank line.
func readCredentialRequest(r io.Reader) map[string]string {
	out := map[string]string{}
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}
		if i := strings.IndexByte(line, '='); i > 0 {
			out[line[:i]] = line[i+1:]
		}
	}
	return out
}

// readBearer copies the exec-plane logic: DOP_TOKEN → DOP_TOKEN_FILE.
func readBearer() string {
	if b := os.Getenv("DOP_TOKEN"); b != "" {
		return b
	}
	if p := os.Getenv("DOP_TOKEN_FILE"); p != "" {
		if b, err := os.ReadFile(p); err == nil {
			return strings.TrimSpace(string(b))
		}
	}
	return ""
}

// resolveEnvForShim decrypts the bundle for this bearer and returns
// its env map, WITHOUT the signature-verify machinery (the shim only
// needs to expose credentials the bearer already possesses). The full
// signature-verify chain lives in `dop exec` proper.
//
// NOTE: this is a deliberate MVP shortcut for v1.7. A hardened shim
// would perform the same verifySignedRecord dance as `dop exec` —
// otherwise a compromised sidecar or bundle could feed the shim a
// forged token. Contract for v1.7 shim: the shim inherits the same
// trust the user has already placed in their bearer's on-disk state.
// See contract 09 for the exec-time story we intentionally mirror.
func resolveEnvForShim(paths *config.Paths, bearer string) (map[string]string, error) {
	ctxPath := filepath.Join(paths.Vault, "vault-context.bin")
	vaultCtx, err := os.ReadFile(ctxPath)
	if err != nil {
		return nil, fmt.Errorf("no vault_context: %w", err)
	}
	lookupID := capability.LookupID(vaultCtx, bearer)
	bundleBytes, err := os.ReadFile(filepath.Join(paths.Vault, "capabilities", lookupID+".bundle"))
	if err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	env, _, err := capability.Read(bundleBytes, capability.ReadOpts{Bearer: bearer})
	if err != nil {
		return nil, err
	}
	return env.Env, nil
}
