// Package probe implements the opt-in endpoints-doc discovery done
// at `dop integration add --probe-endpoints` time.
//
// Design: DOP does NOT auto-fetch anything by default. The operator
// opts in via a flag. When they do, we try a short ordered list of
// well-known paths (`/openapi.json`, `/.well-known/openapi.json`,
// etc.) with a 3s per-request timeout. First response that LOOKS like
// an OpenAPI/Swagger document wins. If nothing hits, we stamp the
// audit event and move on — the add still succeeds.
//
// MCP probing hits the `tools/list` method on the stored MCP URL —
// deterministic per the MCP spec. One request, no probe order.
package probe

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Default per-request timeout. Short so a dead host doesn't make
// `integration add` hang; the full probe worst case is len(paths) *
// perRequestTimeout = ~18s with the current list.
const perRequestTimeout = 3 * time.Second

// OpenAPIProbePaths is the ordered list of paths tried for an api-kind
// integration. Order matters: `.well-known` first (standardized home),
// then the most common conventions. First responding + openapi-shaped
// path wins.
var OpenAPIProbePaths = []string{
	"/.well-known/openapi.json",
	"/openapi.json",
	"/openapi.yaml",
	"/v3/api-docs",
	"/swagger.json",
	"/api-docs",
}

// Result is what the probe returns to the caller.
type Result struct {
	// FoundURL is the full URL that returned a valid-looking doc. Empty
	// when no path responded with openapi-shaped content.
	FoundURL string
	// Attempts lists every probe URL that was tried, in order, with its
	// outcome. Useful for audit + operator feedback.
	Attempts []Attempt
	// Duration is wall-clock time spent probing (end-to-end).
	Duration time.Duration
}

// Attempt captures one probe step for logging + audit.
type Attempt struct {
	URL     string
	Status  int    // HTTP status; 0 if the request errored before response
	Match   bool   // true when response LOOKS like OpenAPI
	ErrText string // populated on transport error; empty on HTTP response
}

// OpenAPI probes baseURL against OpenAPIProbePaths and returns the
// first path whose response looks like an OpenAPI / Swagger document.
// baseURL MUST be an absolute URL ("https://api.example.com"); any
// trailing slash is normalized away.
func OpenAPI(ctx context.Context, baseURL string) (*Result, error) {
	baseURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if baseURL == "" {
		return nil, errors.New("probe: baseURL is empty")
	}
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		return nil, fmt.Errorf("probe: baseURL %q has no http/https scheme", baseURL)
	}
	start := time.Now()
	res := &Result{Attempts: make([]Attempt, 0, len(OpenAPIProbePaths))}
	client := &http.Client{Timeout: perRequestTimeout}
	for _, p := range OpenAPIProbePaths {
		url := baseURL + p
		at := Attempt{URL: url}
		reqCtx, cancel := context.WithTimeout(ctx, perRequestTimeout)
		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
		if err != nil {
			at.ErrText = "newrequest: " + err.Error()
			cancel()
			res.Attempts = append(res.Attempts, at)
			continue
		}
		req.Header.Set("Accept", "application/json, application/yaml, text/yaml")
		req.Header.Set("User-Agent", "dop-probe/1")
		resp, err := client.Do(req)
		cancel()
		if err != nil {
			at.ErrText = "do: " + err.Error()
			res.Attempts = append(res.Attempts, at)
			continue
		}
		at.Status = resp.StatusCode
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			// Peek the first 4KB only — enough to see `openapi:` or
			// `swagger:` field without pulling the whole doc into memory.
			head, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			at.Match = looksLikeOpenAPI(head)
		}
		resp.Body.Close()
		res.Attempts = append(res.Attempts, at)
		if at.Match {
			res.FoundURL = url
			break
		}
	}
	res.Duration = time.Since(start)
	return res, nil
}

// looksLikeOpenAPI returns true when the response head contains an
// OpenAPI 3.x `openapi:` field or a Swagger 2.0 `swagger:` field.
// Handles both JSON (`"openapi": "3.0.0"`) and YAML (`openapi: 3.0.0`).
func looksLikeOpenAPI(head []byte) bool {
	if len(head) == 0 {
		return false
	}
	// JSON path — common for /openapi.json
	if head[0] == '{' {
		var m map[string]any
		if err := json.Unmarshal(head, &m); err == nil {
			if _, ok := m["openapi"]; ok {
				return true
			}
			if _, ok := m["swagger"]; ok {
				return true
			}
		}
		// Fall through to substring sniff — the body may be truncated.
	}
	// YAML / truncated-JSON substring sniff.
	needle1 := []byte("openapi")
	needle2 := []byte("swagger")
	lower := bytes.ToLower(head)
	if bytes.Contains(lower, needle1) || bytes.Contains(lower, needle2) {
		return true
	}
	return false
}

// MCPToolsList probes an MCP server by POSTing a JSON-RPC
// `tools/list` request. Returns a Result where FoundURL == mcpURL on
// success, empty otherwise. MCP is deterministic — there's no probe
// order to try.
func MCPToolsList(ctx context.Context, mcpURL string) (*Result, error) {
	mcpURL = strings.TrimSpace(mcpURL)
	if mcpURL == "" {
		return nil, errors.New("probe: mcpURL is empty")
	}
	if !strings.HasPrefix(mcpURL, "http://") && !strings.HasPrefix(mcpURL, "https://") {
		return nil, fmt.Errorf("probe: mcpURL %q has no http/https scheme", mcpURL)
	}
	start := time.Now()
	res := &Result{Attempts: make([]Attempt, 0, 1)}
	client := &http.Client{Timeout: perRequestTimeout}
	body := bytes.NewReader([]byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`))
	at := Attempt{URL: mcpURL}
	reqCtx, cancel := context.WithTimeout(ctx, perRequestTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, mcpURL, body)
	if err != nil {
		at.ErrText = "newrequest: " + err.Error()
		res.Attempts = append(res.Attempts, at)
		res.Duration = time.Since(start)
		return res, nil
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "dop-probe/1")
	resp, err := client.Do(req)
	if err != nil {
		at.ErrText = "do: " + err.Error()
		res.Attempts = append(res.Attempts, at)
		res.Duration = time.Since(start)
		return res, nil
	}
	defer resp.Body.Close()
	at.Status = resp.StatusCode
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		head, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		at.Match = looksLikeMCPToolsList(head)
	}
	res.Attempts = append(res.Attempts, at)
	if at.Match {
		res.FoundURL = mcpURL
	}
	res.Duration = time.Since(start)
	return res, nil
}

// looksLikeMCPToolsList checks for the JSON-RPC `tools/list` response
// shape: `{"jsonrpc":"2.0","id":1,"result":{"tools":[…]}}`.
func looksLikeMCPToolsList(head []byte) bool {
	if len(head) == 0 || head[0] != '{' {
		return false
	}
	var m map[string]any
	if err := json.Unmarshal(head, &m); err != nil {
		// Partial read — fall back to substring sniff for `"tools"`.
		return bytes.Contains(bytes.ToLower(head), []byte(`"tools"`))
	}
	if m["jsonrpc"] != "2.0" {
		return false
	}
	result, ok := m["result"].(map[string]any)
	if !ok {
		return false
	}
	_, hasTools := result["tools"]
	return hasTools
}
