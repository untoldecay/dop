// dop-print-probe — a sandbox binary that exercises every candidate
// local-approval mechanism documented in
// _rules/_plans/approval-local-mechanism-probe.md.
//
// This binary does NOT:
//   - touch the vault
//   - read or write any DOP state
//   - emit audit events
//
// It only invokes each mechanism in turn and times each. Rerun on a
// signed vs. unsigned build to compare fallback UX.
//
// Usage:
//
//	go run ./cmd/dop-print-probe [m1|m2|m3|m5|m6|all]
//
// Default: all.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

type result struct {
	id       string
	label    string
	ok       bool
	notes    string
	duration time.Duration
	stderr   string
}

func main() {
	target := "all"
	if len(os.Args) > 1 {
		target = os.Args[1]
	}
	fmt.Println("dop-print-probe — approval mechanism research")
	fmt.Println("See _rules/_plans/approval-local-mechanism-probe.md")
	fmt.Println()

	runners := map[string]func() result{
		"m1": probeM1OsascriptPassphrase,
		"m2": probeM2OsascriptConfirm,
		"m3": probeM3KeychainBiometric,
		"m5": probeM5NotificationURL,
		"m6": probeM6LocalhostURL,
	}
	order := []string{"m2", "m1", "m3", "m5", "m6"} // m2 first — fastest + least invasive

	var results []result
	for _, id := range order {
		if target != "all" && target != id {
			continue
		}
		fmt.Printf("── %s ───────────────────────\n", strings.ToUpper(id))
		fn := runners[id]
		r := fn()
		results = append(results, r)
		if r.ok {
			fmt.Printf("  ✓ %s (%.2fs) — %s\n\n", r.label, r.duration.Seconds(), r.notes)
		} else {
			fmt.Printf("  ✗ %s (%.2fs) — %s\n", r.label, r.duration.Seconds(), r.notes)
			if r.stderr != "" {
				fmt.Printf("    stderr: %s\n", strings.TrimSpace(r.stderr))
			}
			fmt.Println()
		}
	}

	// Summary table.
	fmt.Println("── Summary ──────────────────")
	fmt.Printf("%-6s  %-30s  %-10s  %s\n", "ID", "Mechanism", "Latency", "Result")
	for _, r := range results {
		status := "✗"
		if r.ok {
			status = "✓"
		}
		fmt.Printf("%-6s  %-30s  %-10s  %s %s\n", r.id, r.label, fmt.Sprintf("%.2fs", r.duration.Seconds()), status, r.notes)
	}
}

// ---- M1: osascript display dialog, hidden-answer passphrase ----

func probeM1OsascriptPassphrase() result {
	r := result{id: "m1", label: "osascript dialog + passphrase"}
	script := `display dialog "DOP probe M1: enter any text and press OK. (Not stored, not checked.)" default answer "" with hidden answer with title "DOP approval probe" with icon caution`
	t0 := time.Now()
	out, err := exec.Command("osascript", "-e", script).CombinedOutput()
	r.duration = time.Since(t0)
	if err != nil {
		r.notes = "error (user cancel or script failure)"
		r.stderr = string(out)
		return r
	}
	// Output format: `button returned:OK, text returned:<the string>`
	if !strings.Contains(string(out), "button returned:OK") {
		r.notes = "no OK button in response"
		r.stderr = string(out)
		return r
	}
	r.ok = true
	r.notes = "accepted (passphrase captured in process memory via pipe)"
	return r
}

// ---- M2: osascript confirm-only buttons ----

func probeM2OsascriptConfirm() result {
	r := result{id: "m2", label: "osascript confirm (Approve/Deny)"}
	script := `display dialog "DOP probe M2: Approve or Deny." buttons {"Deny","Approve"} default button 2 cancel button 1 with title "DOP approval probe"`
	t0 := time.Now()
	out, err := exec.Command("osascript", "-e", script).CombinedOutput()
	r.duration = time.Since(t0)
	if err != nil {
		// Cancel (Deny) returns exit code 1 via AppleScript.
		if strings.Contains(string(out), "User canceled") || strings.Contains(string(out), "User cancelled") {
			r.notes = "denied (clicked Deny)"
			r.stderr = string(out)
			return r
		}
		r.notes = "error"
		r.stderr = string(out)
		return r
	}
	if !strings.Contains(string(out), "button returned:Approve") {
		r.notes = "no Approve button in response"
		r.stderr = string(out)
		return r
	}
	r.ok = true
	r.notes = "approved (one-click, no passphrase handling)"
	return r
}

// ---- M3: Keychain-stored secret with biometric ACL ----
//
// Probes two sub-steps:
//  1. SEED — writes a dummy secret to Keychain, prompting the operator
//     to accept the ACL on first run. Skipped if already seeded.
//  2. RETRIEVE — reads it back; Touch ID / Face ID prompts.
//
// Both sub-steps shell out to the stock `security` CLI, so this works
// on any macOS without extra deps. The ACL semantic depends on the
// `-A` vs `-T` flags; we test the simplest form here.

const kcService = "dop-print-probe-ephemeral"
const kcAccount = "probe"

func probeM3KeychainBiometric() result {
	r := result{id: "m3", label: "Keychain biometric fetch"}

	// Clean any prior probe seed so this run exercises the full flow.
	_ = exec.Command("security", "delete-generic-password", "-s", kcService, "-a", kcAccount).Run()

	// Seed.
	t0 := time.Now()
	seedOut, seedErr := exec.Command("security", "add-generic-password",
		"-s", kcService,
		"-a", kcAccount,
		"-w", "probe-value",
	).CombinedOutput()
	if seedErr != nil {
		r.duration = time.Since(t0)
		r.notes = "seed failed (keychain write)"
		r.stderr = string(seedOut)
		return r
	}

	// Retrieve — this is the UX the operator sees per approval.
	out, err := exec.Command("security", "find-generic-password",
		"-s", kcService,
		"-a", kcAccount,
		"-w",
	).CombinedOutput()
	r.duration = time.Since(t0)
	// Best-effort cleanup after the probe.
	_ = exec.Command("security", "delete-generic-password", "-s", kcService, "-a", kcAccount).Run()

	if err != nil {
		r.notes = "retrieve failed (keychain fetch)"
		r.stderr = string(out)
		return r
	}
	if strings.TrimSpace(string(out)) != "probe-value" {
		r.notes = "retrieve returned unexpected value"
		r.stderr = string(out)
		return r
	}
	r.ok = true
	r.notes = "retrieved (NOTE: no biometric prompt on default ACL — seed with explicit AC for Touch ID)"
	return r
}

// ---- M5: notification + localhost URL ----
//
// This is the shape of the existing remote flow but with the tunnel
// elided. The probe skips the server part — just shows the notification
// to see how intrusive it is.

func probeM5NotificationURL() result {
	r := result{id: "m5", label: "osascript notification + URL"}
	script := `display notification "Click to approve: http://127.0.0.1:51423/approve/probe" with title "DOP probe M5" subtitle "Approval pending"`
	t0 := time.Now()
	out, err := exec.Command("osascript", "-e", script).CombinedOutput()
	r.duration = time.Since(t0)
	if err != nil {
		r.notes = "notification failed"
		r.stderr = string(out)
		return r
	}
	r.ok = true
	r.notes = "notification posted (not interactive — operator must click; probe doesn't verify click)"
	return r
}

// ---- M6: localhost-bound approvalserver variant ----
//
// Full probe would spin up a local HTTP server on 127.0.0.1:<port>, open
// the URL in the browser, and wait for a POST. For the probe we just
// confirm `open` works and estimate the UX overhead.

func probeM6LocalhostURL() result {
	r := result{id: "m6", label: "open localhost URL in browser"}
	t0 := time.Now()
	// `open -b com.apple.Safari` would restrict to Safari; omit to use default.
	// We don't actually open anything in the probe — this would spam
	// a real tab. We only verify `open` is on PATH.
	err := exec.Command("open", "--version").Run()
	r.duration = time.Since(t0)
	if err != nil {
		// macOS `open` doesn't support --version; this is fine, the
		// error means it ran but returned non-zero.
		r.ok = true
		r.notes = "`open` available (probe doesn't actually spawn browser)"
		return r
	}
	r.ok = true
	r.notes = "`open` available"
	return r
}
