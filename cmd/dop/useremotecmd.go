// `dop use <subject> --remote` — v1.21 (dop-1dd). Server side of the
// lease flow: no admin key here, so ask the admin machine for a
// short-lived bearer and wait for it in the vault repo.

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/agentkey"
	"github.com/fray/dop/internal/audit"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/remoteuse"
	"github.com/fray/dop/internal/trust"
)

const remoteUsePoll = 5 * time.Second

func runUseRemote(paths *config.Paths, subject, agentName, tokenFile string) int {
	bearer, leaseSubject, expiresAt, err := acquireLease(paths, subject, agentName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dop use --remote: %v\n", err)
		return 1
	}
	return emitLease(bearer, leaseSubject, tokenFile, expiresAt)
}

// acquireLease is the lease flow without any printing of the bearer:
// the cached lease when one is alive, else a request staged in the vault
// repo and the wait for the admin's answer. `dop use --remote` prints
// what it returns; `dop exec --use` hands it straight to the child.
func acquireLease(paths *config.Paths, subject, agentName string) (bearer, leaseSubject string, expiresAt time.Time, err error) {
	fail := func(err error) (string, string, time.Time, error) { return "", "", time.Time{}, err }
	if _, err := os.Stat(paths.Vault); err != nil {
		return fail(fmt.Errorf("no vault here — on a server, attach it first: pick Server in `dop`, or `dop init --cache <repo>`"))
	}
	// A lease already granted for this subject and still alive is reused:
	// every shell call of an agent is a fresh shell, and the operator
	// approved the lease, not one process (mirrors the local trust cache).
	if c, ok := readLeaseCache(paths, subject); ok {
		fmt.Fprintf(os.Stderr, "dop use: reusing the lease of %s granted earlier (as %s, expires %s). It asks again when it ends.\n",
			subject, c.LeaseSubject, c.ExpiresAt.Local().Format("15:04"))
		return c.Token, c.LeaseSubject, c.ExpiresAt, nil
	}
	ident, err := age.GenerateX25519Identity()
	if err != nil {
		return fail(err)
	}
	id, err := remoteuse.NewID()
	if err != nil {
		return fail(err)
	}
	nonce, err := remoteuse.NewID()
	if err != nil {
		return fail(err)
	}
	host, _ := os.Hostname()
	if agentName == "" {
		agentName = host
	}
	now := time.Now().UTC().Truncate(time.Second)
	req := remoteuse.Request{
		RequestID: id, Subject: subject, Host: host, AgentName: agentName,
		Recipient: ident.Recipient().String(), RequestedAt: now, ExpiresAt: now.Add(remoteuse.TTL), Nonce: nonce,
	}
	// Sign with a claimed agent key on this host when there is one, so
	// the admin sees who asks; a bare Server install asks unsigned.
	if store := localAgentSigner(paths); store != nil {
		if err := req.Sign(store); err != nil {
			return fail(fmt.Errorf("sign request: %w", err))
		}
	}
	// Start from the team's current tip: a request staged on a stale copy
	// is refused at push. If this copy has diverged (an earlier request
	// that never made it), a cache install has nothing of its own to
	// keep, so it drops its local commits and follows the team.
	stage := func() error {
		if err := remoteuse.WriteRequest(paths, req); err != nil {
			return fmt.Errorf("stage request: %w", err)
		}
		return gitCommitPushRel(paths, fmt.Sprintf("dop: lease request %s for %s", id[:8], subject), remoteuse.RelPaths(id)[0])
	}
	_ = autoPullAndMerge(paths)
	if err := stage(); err != nil {
		_ = autoPullAndMerge(paths)
		if err = stage(); err != nil {
			if pullKeepTeam(paths) != 0 {
				_ = remoteuse.Delete(paths, id)
				return fail(fmt.Errorf("push request: %w — the server needs push access to the vault repo", err))
			}
			if err = stage(); err != nil {
				_ = remoteuse.Delete(paths, id)
				return fail(fmt.Errorf("push request: %w — the server needs push access to the vault repo", err))
			}
		}
	}
	audit.Append(paths, audit.Event{Kind: audit.EventUseRemoteRequest, Subject: subject,
		Extra: map[string]string{"request": id[:8], "host": host, "agent_name": agentName}})
	fmt.Fprintf(os.Stderr, "dop use --remote: asked the admin for a lease of %s (request %s).\n", subject, id[:8])
	fmt.Fprintf(os.Stderr, "  Waiting up to %s — the admin picks the duration in dop (pending claims) or runs:\n", remoteuse.TTL)
	fmt.Fprintf(os.Stderr, "    dop approve-remote --use %s --lease 10m\n", id[:8])

	deadline := time.Now().Add(remoteuse.TTL)
	for {
		if time.Now().After(deadline) {
			_ = remoteuse.Delete(paths, id)
			_ = gitCommitPushRel(paths, "dop: lease request "+id[:8]+" expired", remoteuse.RelPaths(id)...)
			return fail(fmt.Errorf("no answer in %s — the request expired; ask again when the admin is around", remoteuse.TTL))
		}
		time.Sleep(remoteUsePoll)
		// Unconditional: this loop IS the sync (DOP_NO_AUTO_PULL and the
		// freshness window are for exec's hot path, not for waiting).
		if err := autoPullAndMerge(paths); err != nil && !strings.Contains(err.Error(), "up to date") {
			fmt.Fprintf(os.Stderr, "  (sync: %v)\n", err)
		}
		lease, err := remoteuse.ReadLease(paths, id)
		if err != nil {
			if _, rerr := remoteuse.ReadRequest(paths, id); os.IsNotExist(rerr) {
				return fail(fmt.Errorf("the admin rejected the request"))
			}
			continue
		}
		trusted, err := trust.Load(paths)
		if err != nil {
			return fail(fmt.Errorf("load admins.trust: %w", err))
		}
		if err := lease.Verify(trusted); err != nil {
			return fail(err)
		}
		if lease.RequestID != id {
			return fail(fmt.Errorf("lease answers another request"))
		}
		bearerBytes, err := admin.UnwrapWithIdentity(lease.Ciphertext, ident)
		if err != nil {
			return fail(fmt.Errorf("open lease: %w", err))
		}
		bearer := strings.TrimSpace(string(bearerBytes))
		// Consume: both files go, the bearer lives only in this shell.
		_ = remoteuse.Delete(paths, id)
		_ = gitCommitPushRel(paths, "dop: lease "+id[:8]+" consumed", remoteuse.RelPaths(id)...)
		audit.Append(paths, audit.Event{Kind: audit.EventUseRemoteLease, Subject: subject,
			Extra: map[string]string{"request": id[:8], "lease_subject": lease.LeaseSubject, "expires_at": lease.ExpiresAt.Format(time.RFC3339), "approver": short(lease.Approver)}})
		fmt.Fprintf(os.Stderr, "dop use --remote: lease granted as %s, expires %s (%s). When it expires, ask again.\n",
			lease.LeaseSubject, lease.ExpiresAt.Local().Format("15:04"), time.Until(lease.ExpiresAt).Round(time.Minute))
		writeLeaseCache(paths, subject, leaseCache{Token: bearer, LeaseSubject: lease.LeaseSubject, ExpiresAt: lease.ExpiresAt})
		return bearer, lease.LeaseSubject, lease.ExpiresAt, nil
	}
}

// emitLease hands the bearer to the caller: a token file, or the export
// line. The operator approved this exact print on their machine; no
// local guard (there is no admin daemon here to ask).
func emitLease(bearer, leaseSubject, tokenFile string, expiresAt time.Time) int {
	if tokenFile != "" {
		if err := writeTokenFile(tokenFile, bearer, leaseSubject, expiresAt); err != nil {
			fmt.Fprintf(os.Stderr, "dop use --remote: write token file: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "  wrote %s — export DOP_TOKEN_FILE=%s\n", tokenFile, tokenFile)
		return 0
	}
	fmt.Printf("export DOP_TOKEN=%s\n", bearer)
	return 0
}

// leaseCache is the granted lease kept on the server for its lifetime
// (mode 0600 under the dop root), so an agent's next shell call reuses
// it instead of asking the operator again.
type leaseCache struct {
	Token        string    `json:"token"`
	LeaseSubject string    `json:"lease_subject"`
	ExpiresAt    time.Time `json:"expires_at"`
}

func leaseCachePath(paths *config.Paths, subject string) string {
	safe := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '_'
	}, subject)
	return filepath.Join(paths.Root, "leases", safe+".json")
}

func readLeaseCache(paths *config.Paths, subject string) (leaseCache, bool) {
	var c leaseCache
	blob, err := os.ReadFile(leaseCachePath(paths, subject))
	if err != nil || json.Unmarshal(blob, &c) != nil || c.Token == "" {
		return c, false
	}
	// Not worth reusing when the agent's command would outlive it.
	if time.Until(c.ExpiresAt) < 2*time.Minute {
		_ = os.Remove(leaseCachePath(paths, subject))
		return c, false
	}
	return c, true
}

func writeLeaseCache(paths *config.Paths, subject string, c leaseCache) {
	p := leaseCachePath(paths, subject)
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	blob, _ := json.Marshal(c)
	_ = os.WriteFile(p, blob, 0o600)
}

// localAgentSigner returns a usable claimed agent key on this host, or nil.
func localAgentSigner(paths *config.Paths) agentkey.Store {
	entries, err := collectAgentKeys(paths)
	if err != nil {
		return nil
	}
	for _, e := range entries {
		if e.Orphan || e.PendingDelete {
			continue
		}
		if s, err := agentkey.Open(paths, e.LookupID); err == nil {
			return s
		}
	}
	return nil
}

// gitCommitPushRel stages the vault tree (the in-process git takes
// `add -A .`, not pathspecs; rel is documentation of what changed),
// commits and pushes. Quiet on success; "nothing to commit" is fine.
func gitCommitPushRel(paths *config.Paths, msg string, rel ...string) error {
	_ = rel
	if err := runGit(io.Discard, paths.Vault, "add", "-A", "."); err != nil {
		return err
	}
	if err := runGitAllowExit(io.Discard, paths.Vault, []int{0, 1}, "commit", "-m", msg); err != nil {
		return err
	}
	return runGit(io.Discard, paths.Vault, "push")
}
