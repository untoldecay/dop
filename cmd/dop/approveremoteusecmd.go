// `dop approve-remote --use` — admin side of `dop use --remote` (v1.21).
// Picks the lease length (the operator, never the agent), mints a fresh
// unbound bearer with the portable bearer's grants and that expiry,
// seals it to the request's one-shot recipient, signs the answer.

package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fray/dop/internal/admin"
	"github.com/fray/dop/internal/approval"
	"github.com/fray/dop/internal/approvalcard"
	"github.com/fray/dop/internal/audit"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/remoteuse"
)

const defaultLeaseCap = time.Hour

func runApproveRemoteUse(paths *config.Paths, ref string, lease time.Duration, reject, pfromStdin bool) int {
	fail := func(err error) int { fmt.Fprintf(os.Stderr, "dop approve-remote --use: %v\n", err); return 1 }
	reqs, err := remoteuse.ListRequests(paths)
	if err != nil {
		return fail(err)
	}
	var match *remoteuse.Request
	for _, r := range reqs {
		if strings.HasPrefix(r.RequestID, ref) || strings.EqualFold(r.Subject, ref) {
			if match != nil {
				return fail(fmt.Errorf("%q matches several requests — use the id (dop approve-remote --list)", ref))
			}
			match = r
		}
	}
	if match == nil {
		return fail(fmt.Errorf("no pending lease request %q", ref))
	}
	if reject {
		_ = remoteuse.Delete(paths, match.RequestID)
		if err := gitCommitPushRel(paths, "dop: reject lease request "+match.RequestID[:8], remoteuse.RelPaths(match.RequestID)...); err != nil {
			fmt.Fprintf(os.Stderr, "dop approve-remote --use: git push failed (%v) — run `dop push`\n", err)
		}
		audit.Append(paths, audit.Event{Kind: audit.EventUseRemoteRejected, Subject: match.Subject,
			Extra: map[string]string{"request": match.RequestID[:8], "host": match.Host}})
		fmt.Fprintf(os.Stderr, "dop approve-remote: rejected lease request %s (%s on %s)\n", match.RequestID[:8], match.Subject, match.Host)
		return 0
	}
	if time.Now().After(match.ExpiresAt) {
		return fail(fmt.Errorf("request %s expired at %s — the server gave up; ask it again", match.RequestID[:8], match.ExpiresAt.Format(time.RFC3339)))
	}
	if _, err := remoteuse.ReadLease(paths, match.RequestID); err == nil {
		return fail(fmt.Errorf("request %s is already answered", match.RequestID[:8]))
	}
	signed, err := match.Verify()
	if err != nil {
		return fail(err)
	}

	client, err := requireAdminSession(paths)
	if err != nil {
		return fail(err)
	}
	if !approval.Configured(paths) {
		return fail(fmt.Errorf("no approval passphrase set — run `dop admin set-approval`"))
	}
	v, vaultPath, err := loadVaultViaDaemon(client, paths)
	if err != nil {
		return fail(err)
	}
	_, crec, err := findActiveCapBySubject(v, match.Subject)
	if err != nil {
		return fail(err)
	}
	if crec.PortableWrapped == "" {
		return fail(fmt.Errorf("%q is not a portable bearer — only portable bearers can be leased", match.Subject))
	}
	// Protected grants: the approver must own them, as for local use.
	if err := checkCapabilityProtection(client, crec); err != nil {
		return fail(err)
	}
	cap := defaultLeaseCap
	if crec.LeaseCapSeconds > 0 {
		cap = time.Duration(crec.LeaseCapSeconds) * time.Second
	}
	if lease <= 0 {
		return fail(fmt.Errorf("--lease must be positive"))
	}
	if lease > cap {
		fmt.Fprintf(os.Stderr, "dop approve-remote: %s asked, cap for %s is %s — leasing %s\n", lease, match.Subject, cap, cap)
		lease = cap
	}

	who := match.AgentName
	if signed {
		who += " (signed by its agent key)"
	} else {
		who += " (unsigned request)"
	}
	card := approvalcard.Card{Kind: approvalcard.KindLease, Subject: match.Subject, Who: who, Where: match.Host,
		Touches: strings.Join(crec.Grants, ", "), Expires: match.ExpiresAt}
	fmt.Fprintln(os.Stderr, card.Body())
	fmt.Fprintf(os.Stderr, "lease: %s\n%s\n", lease, card.Footer())
	pass, err := readPassphrase(approvalcard.Passphrase+": ", pfromStdin)
	if err != nil {
		return fail(err)
	}
	ok, err := approval.Verify(paths, pass)
	if err != nil {
		return fail(err)
	}
	if !ok {
		audit.Append(paths, audit.Event{Kind: audit.EventUseRemoteRejected, Subject: match.Subject,
			Extra: map[string]string{"request": match.RequestID[:8], "reason": "bad_passphrase"}})
		return fail(fmt.Errorf("incorrect passphrase"))
	}

	// Mint the lease: unbound, same grants, short expiry, not portable.
	expiresAt := time.Now().Add(lease).UTC().Truncate(time.Second)
	leaseSubject := fmt.Sprintf("%s@%s", match.Subject, match.Host)
	var protectedGrants []string
	for _, gid := range crec.Grants {
		if g, ok := v.Grants[gid]; ok && g.Protected {
			protectedGrants = append(protectedGrants, gid)
		}
	}
	bearer, _, rc := mintBearer("dop approve-remote", client, paths, v, vaultPath, leaseSubject, crec.Grants, expiresAt, true, "", 0, false, 0, protectedGrants)
	if rc != 0 {
		return rc
	}
	ciphertext, err := admin.WrapToRecipient([]byte(bearer), match.Recipient)
	if err != nil {
		return fail(fmt.Errorf("seal lease: %w", err))
	}
	st, err := client.Status()
	if err != nil {
		return fail(err)
	}
	l := remoteuse.Lease{RequestID: match.RequestID, Subject: match.Subject, LeaseSubject: leaseSubject,
		ExpiresAt: expiresAt, Ciphertext: ciphertext, ApprovedAt: time.Now().UTC().Truncate(time.Second), Approver: st.AdminPubkey}
	payload, err := l.SigningPayload()
	if err != nil {
		return fail(err)
	}
	sig, err := client.Sign(payload)
	if err != nil {
		return fail(fmt.Errorf("sign lease: %w", err))
	}
	l.Signature = hex.EncodeToString(sig)
	if err := remoteuse.WriteLease(paths, l); err != nil {
		return fail(err)
	}
	// The minted bearer's bundle + sidecar and the lease travel together.
	if err := gitCommitPushApproveRemote(paths, match.RequestID); err != nil {
		fmt.Fprintf(os.Stderr, "dop approve-remote: git push failed (%v) — run `dop push` manually\n", err)
	}
	audit.Append(paths, audit.Event{Kind: audit.EventUseRemoteApproved, Subject: match.Subject,
		Extra: map[string]string{"request": match.RequestID[:8], "host": match.Host, "agent_name": match.AgentName,
			"lease_subject": leaseSubject, "lease": lease.String(), "expires_at": expiresAt.Format(time.RFC3339)}})
	fmt.Fprintf(os.Stderr, "dop approve-remote: leased %s to %s on %s for %s (as %s, expires %s)\n",
		match.Subject, match.AgentName, match.Host, lease, leaseSubject, expiresAt.Local().Format("15:04"))
	return 0
}
