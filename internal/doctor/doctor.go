// Package doctor implements `dop doctor` — the health self-check.
//
// Each Check is independent and returns a Result. The runner aggregates
// them so one broken check doesn't hide others. Exit code is non-zero
// only when a FAIL surfaces; WARN is informational.
package doctor

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"filippo.io/age"

	"github.com/fray/dop/internal/agekeys"
	"github.com/fray/dop/internal/config"
	"github.com/fray/dop/internal/vault"
)

// Status is the outcome of a single check.
type Status int

const (
	Pass Status = iota
	Warn
	Fail
)

func (s Status) String() string {
	switch s {
	case Pass:
		return "PASS"
	case Warn:
		return "WARN"
	case Fail:
		return "FAIL"
	}
	return "?"
}

// Result carries one check's outcome + human-readable detail.
type Result struct {
	Name   string
	Status Status
	Detail string
}

// Run executes the standard check battery. Returns the collected results
// (in stable order) and a bool = "any failures?".
//
// httpClient is optional (nil → http.DefaultClient with a 5s timeout).
func Run(v *vault.Vault, paths *config.Paths, vaultPath string, out io.Writer, httpClient *http.Client) ([]Result, bool) {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 5 * time.Second}
	}

	var results []Result
	add := func(r Result) {
		fmt.Fprintf(out, "  %s %s — %s\n", statusGlyph(r.Status), r.Name, r.Detail)
		results = append(results, r)
	}

	fmt.Fprintln(out, "dop doctor:")

	add(checkBinaryOnPath("sops", "brew install sops or https://github.com/getsops/sops/releases"))
	add(checkBinaryOnPath("git", "install git via your package manager"))
	add(checkVaultReachable(vaultPath))
	add(checkSchemaVersion(v))
	add(checkAgeKey(paths))
	add(checkSopsRecipients(paths))
	add(checkAuditLogs(paths))
	add(checkClockSkew(httpClient))
	// Upstream scope validation runs last because it makes network calls.
	// Each integration is a separate line so partial failures are visible.
	for _, r := range checkUpstreamScopes(v, httpClient) {
		add(r)
	}

	anyFail := false
	for _, r := range results {
		if r.Status == Fail {
			anyFail = true
			break
		}
	}
	return results, anyFail
}

func statusGlyph(s Status) string {
	switch s {
	case Pass:
		return "✓"
	case Warn:
		return "!"
	case Fail:
		return "✗"
	}
	return "?"
}

// --- individual checks -------------------------------------------------------

func checkBinaryOnPath(bin, hint string) Result {
	if _, err := exec.LookPath(bin); err != nil {
		return Result{
			Name:   fmt.Sprintf("binary:%s", bin),
			Status: Fail,
			Detail: fmt.Sprintf("%s not on $PATH — %s", bin, hint),
		}
	}
	return Result{Name: fmt.Sprintf("binary:%s", bin), Status: Pass, Detail: "on $PATH"}
}

func checkVaultReachable(vaultPath string) Result {
	if vaultPath == "" {
		return Result{
			Name:   "vault:reachable",
			Status: Warn,
			Detail: "no vault path (run `dop init --vault ...` to attach one)",
		}
	}
	fi, err := os.Stat(vaultPath)
	if err != nil {
		return Result{Name: "vault:reachable", Status: Fail, Detail: err.Error()}
	}
	return Result{Name: "vault:reachable", Status: Pass, Detail: fmt.Sprintf("%s (%d bytes)", vaultPath, fi.Size())}
}

func checkSchemaVersion(v *vault.Vault) Result {
	if v == nil {
		return Result{Name: "vault:schema", Status: Warn, Detail: "vault not loaded (upstream checks skipped)"}
	}
	if v.SchemaVersion == vault.SupportedSchemaVersion {
		return Result{Name: "vault:schema", Status: Pass, Detail: fmt.Sprintf("v%d matches", v.SchemaVersion)}
	}
	return Result{
		Name:   "vault:schema",
		Status: Fail,
		Detail: fmt.Sprintf("vault v%d, dop supports v%d", v.SchemaVersion, vault.SupportedSchemaVersion),
	}
}

func checkAgeKey(paths *config.Paths) Result {
	if paths == nil {
		return Result{Name: "age-key", Status: Warn, Detail: "paths not resolvable"}
	}
	if _, err := os.Stat(paths.KeyFile); err != nil {
		return Result{Name: "age-key", Status: Fail, Detail: fmt.Sprintf("no key at %s (run `dop init`)", paths.KeyFile)}
	}
	id, err := agekeys.LoadPrivateKey(paths.KeyFile)
	if err != nil {
		return Result{Name: "age-key", Status: Fail, Detail: err.Error()}
	}
	return Result{Name: "age-key", Status: Pass, Detail: id.Recipient().String()}
}

func checkSopsRecipients(paths *config.Paths) Result {
	if paths == nil {
		return Result{Name: "sops-recipients", Status: Warn, Detail: "paths not resolvable"}
	}
	sopsCfg := filepath.Join(paths.Vault, ".sops.yaml")
	b, err := os.ReadFile(sopsCfg)
	if err != nil {
		if os.IsNotExist(err) {
			return Result{Name: "sops-recipients", Status: Warn, Detail: "no .sops.yaml (vault not attached yet?)"}
		}
		return Result{Name: "sops-recipients", Status: Fail, Detail: err.Error()}
	}
	// Extract every age1... string and try to parse it as an X25519 recipient.
	// Simple regex-free scan.
	bad := 0
	good := 0
	for i := 0; i < len(b); i++ {
		if i+4 < len(b) && string(b[i:i+4]) == "age1" {
			end := i
			for end < len(b) && isBech32Char(b[end]) {
				end++
			}
			rec := string(b[i:end])
			if _, err := age.ParseX25519Recipient(rec); err == nil {
				good++
			} else {
				bad++
			}
			i = end
		}
	}
	if bad > 0 {
		return Result{Name: "sops-recipients", Status: Fail, Detail: fmt.Sprintf("%d unparseable age recipients in .sops.yaml", bad)}
	}
	if good == 0 {
		return Result{Name: "sops-recipients", Status: Warn, Detail: "no age recipients declared"}
	}
	return Result{Name: "sops-recipients", Status: Pass, Detail: fmt.Sprintf("%d valid recipients", good)}
}

func isBech32Char(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}

func checkAuditLogs(paths *config.Paths) Result {
	if paths == nil {
		return Result{Name: "audit-log", Status: Warn, Detail: "paths not resolvable"}
	}
	entries, err := os.ReadDir(paths.Logs)
	if err != nil {
		if os.IsNotExist(err) {
			return Result{Name: "audit-log", Status: Warn, Detail: "no logs directory yet (fresh install)"}
		}
		return Result{Name: "audit-log", Status: Fail, Detail: err.Error()}
	}
	total := 0
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "access-") || !strings.HasSuffix(e.Name(), ".jsonl") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(paths.Logs, e.Name()))
		if err != nil {
			return Result{Name: "audit-log", Status: Fail, Detail: err.Error()}
		}
		for _, line := range strings.Split(string(b), "\n") {
			if line == "" {
				continue
			}
			if !strings.HasPrefix(line, "{") {
				return Result{Name: "audit-log", Status: Fail, Detail: fmt.Sprintf("malformed line in %s", e.Name())}
			}
			total++
		}
	}
	return Result{Name: "audit-log", Status: Pass, Detail: fmt.Sprintf("%d log lines across %d files", total, len(entries))}
}

func checkClockSkew(client *http.Client) Result {
	// GitHub's `Date` header is a cheap, low-friction upstream clock. Compare.
	req, _ := http.NewRequest("HEAD", "https://api.github.com/", nil)
	resp, err := client.Do(req)
	if err != nil {
		return Result{Name: "clock-skew", Status: Warn, Detail: "offline; skipping"}
	}
	defer resp.Body.Close()
	serverTime, err := http.ParseTime(resp.Header.Get("Date"))
	if err != nil {
		return Result{Name: "clock-skew", Status: Warn, Detail: "no Date header from api.github.com"}
	}
	skew := time.Since(serverTime)
	if skew < 0 {
		skew = -skew
	}
	if skew > 5*time.Minute {
		return Result{Name: "clock-skew", Status: Fail, Detail: fmt.Sprintf("clock differs from github.com by %s", skew)}
	}
	return Result{Name: "clock-skew", Status: Pass, Detail: fmt.Sprintf("within %s of github.com", skew.Round(time.Second))}
}

// --- upstream scope validation ----------------------------------------------

// ScopeValidator probes an upstream service to confirm a token behaves as
// its scope_note claims. Each service needs its own — DOP knows a few
// out-of-the-box; unknown services get a WARN (never a FAIL).
type ScopeValidator interface {
	Name() string                                                  // integration name this validator handles (e.g. "notion")
	Probe(baseURL, token string, client *http.Client) (Status, string) // (result, detail)
}

var registeredValidators = map[string]ScopeValidator{
	"notion": notionValidator{},
}

// Register lets tests inject fakes.
func Register(v ScopeValidator) {
	registeredValidators[v.Name()] = v
}

// UnregisterAll wipes the validator map for tests.
func UnregisterAll() {
	registeredValidators = map[string]ScopeValidator{}
}

// SetValidators atomically replaces the validator set for tests.
func SetValidators(vs map[string]ScopeValidator) {
	registeredValidators = vs
}

func checkUpstreamScopes(v *vault.Vault, client *http.Client) []Result {
	if v == nil {
		return []Result{{Name: "upstream-scopes", Status: Warn, Detail: "vault not loaded"}}
	}
	var results []Result
	// Deterministic ordering.
	names := make([]string, 0, len(v.Integrations))
	for k := range v.Integrations {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, iname := range names {
		integ := v.Integrations[iname]
		val, hasValidator := registeredValidators[iname]
		if !hasValidator {
			results = append(results, Result{
				Name:   fmt.Sprintf("scope:%s", iname),
				Status: Warn,
				Detail: "no validator registered for this integration; skipping (add one in internal/doctor if it matters)",
			})
			continue
		}
		baseURL := integ.Metadata["base_url"]
		if baseURL == "" {
			results = append(results, Result{
				Name:   fmt.Sprintf("scope:%s", iname),
				Status: Warn,
				Detail: "no base_url in integration metadata; validator can't probe",
			})
			continue
		}
		tokNames := make([]string, 0, len(integ.Tokens))
		for k := range integ.Tokens {
			tokNames = append(tokNames, k)
		}
		sort.Strings(tokNames)
		for _, tn := range tokNames {
			tok := integ.Tokens[tn]
			status, detail := val.Probe(baseURL, tok.Value, client)
			results = append(results, Result{
				Name:   fmt.Sprintf("scope:%s.%s", iname, tn),
				Status: status,
				Detail: detail,
			})
		}
	}
	return results
}

// --- notion validator -------------------------------------------------------

type notionValidator struct{}

func (notionValidator) Name() string { return "notion" }

func (notionValidator) Probe(baseURL, token string, client *http.Client) (Status, string) {
	// Notion doesn't expose a "what can this integration do?" endpoint that
	// distinguishes read vs write. `/users/me` at least verifies the token
	// is valid + not revoked. Full read/write verification requires side-
	// effecting probes, which we intentionally avoid.
	url := strings.TrimRight(baseURL, "/") + "/users/me"
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return Fail, err.Error()
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Notion-Version", "2022-06-28")
	resp, err := client.Do(req)
	if err != nil {
		return Warn, fmt.Sprintf("network: %v (skip)", err)
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case 200:
		return Pass, "token valid against Notion /users/me"
	case 401, 403:
		return Fail, fmt.Sprintf("token rejected (%d) — revoked or wrong token?", resp.StatusCode)
	default:
		return Warn, fmt.Sprintf("unexpected %d from Notion", resp.StatusCode)
	}
}
