// v1.13.0-rc15 — unit tests for the opt-in endpoints probe.
// Uses httptest for fast, hermetic coverage of the path-order
// behavior + OpenAPI/MCP shape sniffing.

package probe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenAPI_FirstPathWins(t *testing.T) {
	// Serve a valid OpenAPI doc at /openapi.json. The probe should hit
	// `.well-known/openapi.json` first (404), THEN /openapi.json (hit).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"openapi":"3.0.0","info":{"title":"test"}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	res, err := OpenAPI(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if res.FoundURL != srv.URL+"/openapi.json" {
		t.Errorf("want FoundURL=%q, got %q", srv.URL+"/openapi.json", res.FoundURL)
	}
	// Attempt list should include the 404 at .well-known + the 200 at /openapi.json.
	if len(res.Attempts) < 2 {
		t.Errorf("want ≥ 2 attempts, got %d", len(res.Attempts))
	}
	if res.Attempts[0].URL != srv.URL+"/.well-known/openapi.json" {
		t.Errorf("first probe should be .well-known, got %q", res.Attempts[0].URL)
	}
	if res.Attempts[0].Status != 404 {
		t.Errorf("first probe should 404, got %d", res.Attempts[0].Status)
	}
}

func TestOpenAPI_SwaggerFallback(t *testing.T) {
	// Serve a Swagger 2.0 doc at /swagger.json. The probe should walk
	// past the earlier paths and land on it.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/swagger.json" {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"swagger":"2.0","info":{"title":"legacy"}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	res, err := OpenAPI(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if res.FoundURL != srv.URL+"/swagger.json" {
		t.Errorf("want FoundURL=%q, got %q", srv.URL+"/swagger.json", res.FoundURL)
	}
}

func TestOpenAPI_NoMatchEmptyFoundURL(t *testing.T) {
	// Every path 404s. Probe should return a Result with FoundURL=="",
	// not an error.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()
	res, err := OpenAPI(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if res.FoundURL != "" {
		t.Errorf("want FoundURL=\"\" on no-match, got %q", res.FoundURL)
	}
	if len(res.Attempts) != len(OpenAPIProbePaths) {
		t.Errorf("want %d attempts, got %d", len(OpenAPIProbePaths), len(res.Attempts))
	}
}

func TestOpenAPI_NonOpenAPIResponse(t *testing.T) {
	// 200 OK but the body is HTML (admin page). Must NOT match.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body>Welcome</body></html>`))
	}))
	defer srv.Close()
	res, err := OpenAPI(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if res.FoundURL != "" {
		t.Errorf("HTML must not match OpenAPI shape; got FoundURL=%q", res.FoundURL)
	}
}

func TestOpenAPI_YAMLBody(t *testing.T) {
	// YAML OpenAPI doc at /openapi.yaml. The substring sniff should
	// catch `openapi:` even without JSON parsing.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.yaml" {
			w.Header().Set("Content-Type", "application/yaml")
			w.Write([]byte("openapi: 3.0.0\ninfo:\n  title: yamltest\n"))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()
	res, err := OpenAPI(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("OpenAPI: %v", err)
	}
	if res.FoundURL != srv.URL+"/openapi.yaml" {
		t.Errorf("want FoundURL=%q, got %q", srv.URL+"/openapi.yaml", res.FoundURL)
	}
}

func TestOpenAPI_SchemeRequired(t *testing.T) {
	_, err := OpenAPI(context.Background(), "example.com")
	if err == nil || !strings.Contains(err.Error(), "scheme") {
		t.Errorf("want scheme error, got %v", err)
	}
}

func TestMCPToolsList_SuccessShape(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "want POST", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"ping"}]}}`))
	}))
	defer srv.Close()
	res, err := MCPToolsList(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("MCPToolsList: %v", err)
	}
	if res.FoundURL != srv.URL {
		t.Errorf("want FoundURL=%q, got %q", srv.URL, res.FoundURL)
	}
}

func TestMCPToolsList_WrongShape(t *testing.T) {
	// 200 OK but no `tools` under result — not an MCP server.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"nope":true}}`))
	}))
	defer srv.Close()
	res, err := MCPToolsList(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("MCPToolsList: %v", err)
	}
	if res.FoundURL != "" {
		t.Errorf("want empty FoundURL on wrong-shape response; got %q", res.FoundURL)
	}
}
