package doctor

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/fray/dop/internal/vault"
)

// fakeValidator lets us stub scope probes without hitting a network.
type fakeValidator struct {
	name   string
	status Status
	detail string
}

func (f fakeValidator) Name() string { return f.name }
func (f fakeValidator) Probe(baseURL, token string, _ *http.Client) (Status, string) {
	return f.status, f.detail
}

func TestCheckSchemaVersion_Match(t *testing.T) {
	v := &vault.Vault{SchemaVersion: vault.SupportedSchemaVersion}
	r := checkSchemaVersion(v)
	if r.Status != Pass {
		t.Fatalf("expected Pass, got %v: %s", r.Status, r.Detail)
	}
}

func TestCheckSchemaVersion_Mismatch(t *testing.T) {
	v := &vault.Vault{SchemaVersion: 999}
	r := checkSchemaVersion(v)
	if r.Status != Fail {
		t.Fatalf("expected Fail, got %v", r.Status)
	}
}

func TestCheckUpstreamScopes_UnknownIntegrationIsWarn(t *testing.T) {
	SetValidators(map[string]ScopeValidator{})
	v := &vault.Vault{
		Integrations: map[string]vault.Integration{
			"custom-service": {
				Metadata: map[string]string{"base_url": "https://api.example"},
				Tokens: map[string]vault.Token{
					"read": {Value: "x", ScopeNote: "read-only"},
				},
			},
		},
	}
	results := checkUpstreamScopes(v, http.DefaultClient)
	if len(results) != 1 || results[0].Status != Warn {
		t.Fatalf("expected 1 warn for unknown integration, got %+v", results)
	}
	if !strings.Contains(results[0].Detail, "no validator") {
		t.Fatalf("warning detail wrong: %s", results[0].Detail)
	}
}

func TestCheckUpstreamScopes_ValidatorRuns(t *testing.T) {
	SetValidators(map[string]ScopeValidator{
		"notion": fakeValidator{name: "notion", status: Pass, detail: "ok fake"},
	})
	v := &vault.Vault{
		Integrations: map[string]vault.Integration{
			"notion": {
				Metadata: map[string]string{"base_url": "https://api.notion.com/v1"},
				Tokens: map[string]vault.Token{
					"read":  {Value: "ntn_ro"},
					"write": {Value: "ntn_rw"},
				},
			},
		},
	}
	results := checkUpstreamScopes(v, http.DefaultClient)
	if len(results) != 2 {
		t.Fatalf("expected one result per token, got %d", len(results))
	}
	for _, r := range results {
		if r.Status != Pass {
			t.Fatalf("unexpected status: %+v", r)
		}
	}
}

func TestCheckUpstreamScopes_MissingBaseURLIsWarn(t *testing.T) {
	SetValidators(map[string]ScopeValidator{
		"notion": fakeValidator{name: "notion", status: Pass, detail: "shouldn't be called"},
	})
	v := &vault.Vault{
		Integrations: map[string]vault.Integration{
			"notion": {
				Metadata: map[string]string{}, // no base_url
				Tokens:   map[string]vault.Token{"read": {Value: "x"}},
			},
		},
	}
	results := checkUpstreamScopes(v, http.DefaultClient)
	if len(results) != 1 || results[0].Status != Warn {
		t.Fatalf("expected warn on missing base_url, got %+v", results)
	}
}

func TestNotionValidator_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/users/me" {
			w.WriteHeader(404)
			return
		}
		if r.Header.Get("Authorization") == "" {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()

	s, msg := notionValidator{}.Probe(srv.URL, "ntn_test", srv.Client())
	if s != Pass {
		t.Fatalf("expected Pass, got %v (%s)", s, msg)
	}
}

func TestNotionValidator_Rejects401(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(401)
	}))
	defer srv.Close()
	s, msg := notionValidator{}.Probe(srv.URL, "ntn_bad", srv.Client())
	if s != Fail {
		t.Fatalf("expected Fail, got %v (%s)", s, msg)
	}
	if !strings.Contains(msg, "revoked") {
		t.Fatalf("expected revoked hint, got %q", msg)
	}
}
