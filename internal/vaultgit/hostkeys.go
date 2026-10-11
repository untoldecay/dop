package vaultgit

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Published SSH host keys of the big git hosts, used only when the
// user's known_hosts has no entry for the host — a fresh VPS has no
// ~/.ssh/known_hosts, and the built-in git can't ask "continue
// connecting (yes/no)?" like ssh does (dop-w20). A known_hosts entry
// that disagrees still wins (refused): that mismatch is the warning.
//
// Sources (2026-10-11): GitHub — api.github.com/meta ssh_keys (fetched
// over HTTPS); GitLab — ssh-keyscan gitlab.com, checked against the
// SHA256 fingerprints in GitLab's docs (eUXGGm1…, ROQFvPT…, HbW3g8z…).
var builtinHostKeys = map[string][]string{
	"github.com": {
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
		"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEmKSENjQEezOmxkZMy7opKgwFB9nkt5YRrYMjNuG5N87uRgg6CLrbo5wAdT/y6v0mKV0U2w0WZ2YB/++Tpockg=",
		"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCj7ndNxQowgcQnjshcLrqPEiiphnt+VTTvDP6mHBL9j1aNUkY4Ue1gvwnGLVlOhGeYrnZaMgRK6+PKCUXaDbC7qtbW8gIkhL7aGCsOr/C56SJMy/BCZfxd1nWzAOxSDPgVsmerOBYfNqltV9/hWCqBywINIR+5dIg6JTJ72pcEpEjcYgXkE2YEFXV1JHnsKgbLWNlhScqb2UmyRkQyytRLtL+38TGxkxCflmO+5Z8CSSNY7GidjMIZ7Q4zMjA2n1nGrlTDkzwDCsw+wqFPGQA179cnfGWOWRVruj16z6XyvxvjJwbz0wQZ75XK5tKSb7FNyeIEs4TT4jk+S4dhPeAUC5y+bDYirYgM4GC7uEnztnZyaVWQ7B381AK4Qdrwt51ZqExKbQpTUNn+EjqoTwvqNj4kqx5QUCI0ThS/YkOxJCXmPUWZbhjpCg56i+2aB6CmK2JGhn57K5mj0MNdBXA4/WnwH6XoPWJzK5Nyu2zB3nAZp+S5hpQs+p1vN1/wsjk=",
	},
	"gitlab.com": {
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAfuCHKVTjquxvt6CM6tdG4SLp1Btn/nOeHHE5UOzRdf",
		"ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFSMqzJeV9rUzU4kWitGjeR4PWSa29SPqJ1fVkhtj3Hw9xjLVXVYrU9QlYWrOLXBpQ6KWjbjTDTdDkoohFzgbEY=",
		"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsj2bNKTBSpIYDEGk9KxsGh3mySTRgMtXL583qmBpzeQ+jqCMRgBqB98u3z++J1sKlXHWfM9dyhSevkMwSbhoR8XIq/U0tCNyokEi/ueaBMCvbcTHhO7FcwzY92WK4Yt0aGROY5qX2UKSeOvuP4D6TPqKF1onrSzH9bx9XUf2lEdWT/ia1NEKjunUqu1xOB/StKDHMoX4/OKyIzuS0q/T1zOATthvasJFoPrAjkohTyaDUz2LN5JoH839hViyEG82yB+MjcFV5MU3N1l1QL3cVUCh93xSaua1N85qivl+siMkPGbO5xR/En4iEY6K2XPASUEMaieWVNTRCtJ4S8H+9",
	},
}

// knownHostsFiles lists the user's known_hosts files that exist.
func knownHostsFiles() []string {
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
	return existing
}

func hostKeyCallback() (ssh.HostKeyCallback, error) {
	var known ssh.HostKeyCallback
	if files := knownHostsFiles(); len(files) > 0 {
		cb, err := knownhosts.New(files...)
		if err != nil {
			return nil, fmt.Errorf("reading known_hosts: %w", err)
		}
		known = cb
	}
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if known != nil {
			err := known(hostname, remote, key)
			if err == nil {
				return nil
			}
			var ke *knownhosts.KeyError
			if !errors.As(err, &ke) || len(ke.Want) > 0 {
				// A known_hosts entry for this host disagrees: refuse,
				// whatever the built-in list says.
				return fmt.Errorf("%s's SSH host key doesn't match your ~/.ssh/known_hosts — refusing (possible impersonation, or the host changed keys): %w", hostOnly(hostname), err)
			}
		}
		return builtinHostKey(hostname, key)
	}, nil
}

func builtinHostKey(hostname string, key ssh.PublicKey) error {
	host := hostOnly(hostname)
	lines, ok := builtinHostKeys[host]
	if !ok {
		return fmt.Errorf("unknown SSH host %s: trust it once with `ssh -T git@%s` (check the fingerprint with your git host), or use an https:// vault URL with a repo token", host, host)
	}
	for _, l := range lines {
		pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(l))
		if err == nil && bytes.Equal(pk.Marshal(), key.Marshal()) {
			return nil
		}
	}
	return fmt.Errorf("%s's SSH host key (%s) is not one %s publishes — refusing (possible impersonation)", host, ssh.FingerprintSHA256(key), host)
}

func hostOnly(hostname string) string {
	if h, _, err := net.SplitHostPort(hostname); err == nil {
		hostname = h
	}
	return strings.ToLower(strings.Trim(hostname, "[]"))
}
