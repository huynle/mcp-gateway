package authserver_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/huynle/mcp-gateway/internal/authserver"
)

func testConfig() authserver.Config {
	cfg := authserver.DefaultConfig()
	cfg.Issuer = "https://gw.example.com/"
	return cfg
}

// The two discovery documents are what every harness reads first (MCP
// authorization spec; RFC 8414 and RFC 9728). Pin them field by field so a
// change is a deliberate one.
func TestAuthorizationServerMetadataDocument(t *testing.T) {
	cfg := testConfig()
	want := map[string]any{
		"issuer":                                     "https://gw.example.com",
		"authorization_endpoint":                     "https://gw.example.com/oauth/authorize",
		"token_endpoint":                             "https://gw.example.com/oauth/token",
		"registration_endpoint":                      "https://gw.example.com/oauth/register",
		"revocation_endpoint":                        "https://gw.example.com/oauth/revoke",
		"jwks_uri":                                   "https://gw.example.com/oauth/jwks",
		"response_types_supported":                   []any{"code"},
		"response_modes_supported":                   []any{"query"},
		"grant_types_supported":                      []any{"authorization_code", "refresh_token"},
		"code_challenge_methods_supported":           []any{"S256"},
		"token_endpoint_auth_methods_supported":      []any{"none", "client_secret_post", "client_secret_basic"},
		"revocation_endpoint_auth_methods_supported": []any{"none", "client_secret_post", "client_secret_basic"},
		"scopes_supported":                           []any{"mcp", "mcp:read"},
		"service_documentation":                      "https://gw.example.com/harnesses",
	}
	got := roundTrip(t, authserver.AuthorizationServerMetadata(cfg))
	if !reflect.DeepEqual(got, want) {
		t.Errorf("AS metadata =\n%v\nwant\n%v", got, want)
	}
}

func TestProtectedResourceMetadataDocument(t *testing.T) {
	cfg := testConfig()
	want := map[string]any{
		"resource":                 "https://gw.example.com/mcp",
		"authorization_servers":    []any{"https://gw.example.com"},
		"bearer_methods_supported": []any{"header"},
		"scopes_supported":         []any{"mcp", "mcp:read"},
		"resource_name":            "MCP Gateway",
	}
	got := roundTrip(t, authserver.ProtectedResourceMetadata(cfg))
	if !reflect.DeepEqual(got, want) {
		t.Errorf("PRM =\n%v\nwant\n%v", got, want)
	}
	if cfg.Resource() != "https://gw.example.com/mcp" {
		t.Errorf("Resource() = %q", cfg.Resource())
	}
}

// The handlers serve the documents as JSON with no-store and CORS so a
// browser-based harness can read them.
func TestMetadataHandlers(t *testing.T) {
	cfg := testConfig()
	for _, c := range []struct {
		path string
		h    http.Handler
		key  string
	}{
		{"/.well-known/oauth-authorization-server", authserver.MetadataHandler(cfg), "issuer"},
		{"/.well-known/oauth-protected-resource", authserver.ProtectedResourceHandler(cfg), "resource"},
		{"/.well-known/oauth-protected-resource/mcp", authserver.ProtectedResourceHandler(cfg), "resource"},
	} {
		rec := httptest.NewRecorder()
		c.h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, c.path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", c.path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("%s: content-type %q", c.path, ct)
		}
		if rec.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Errorf("%s: missing CORS header", c.path)
		}
		var doc map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &doc); err != nil {
			t.Fatalf("%s: %v", c.path, err)
		}
		if _, ok := doc[c.key]; !ok {
			t.Errorf("%s: missing %q in %v", c.path, c.key, doc)
		}
	}
}

func roundTrip(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	return out
}
