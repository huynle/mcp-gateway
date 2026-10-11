package auth

import (
	"errors"
	"net/http"
	"slices"
	"testing"

	"github.com/huynle/mcp-gateway/internal/federation/client"
	"github.com/huynle/mcp-gateway/internal/netguard"
	"github.com/huynle/mcp-gateway/internal/store"
)

func newDiscoverer(t *testing.T, n *fakeNet) *Discoverer {
	t.Helper()
	d, err := NewDiscoverer(DiscoveryOptions{HTTPClient: n.client()})
	if err != nil {
		t.Fatalf("NewDiscoverer: %v", err)
	}
	return d
}

func TestDetectBrainShaped(t *testing.T) {
	n := newFakeNet(t)
	mcpURL, as := brainServer(t, n, "brain.example", nil)
	res, err := newDiscoverer(t, n).Detect(t.Context(), mcpURL)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.AuthKinds) == 0 || res.AuthKinds[0] != store.MCPAuthOAuth {
		t.Fatalf("AuthKinds = %v, want oauth first", res.AuthKinds)
	}
	if res.ResourceMetadata == nil || !slices.Equal(res.ResourceMetadata.AuthorizationServers, []string{as.issuer}) {
		t.Fatalf("ResourceMetadata = %+v", res.ResourceMetadata)
	}
	if res.AuthServerMetadata == nil || res.AuthServerMetadata.Issuer != as.issuer ||
		res.AuthServerMetadata.TokenEndpoint != as.issuer+"/token" {
		t.Fatalf("AuthServerMetadata = %+v", res.AuthServerMetadata)
	}
	if !res.SupportsDCR || res.SupportsCIMD || !res.SupportsS256 {
		t.Fatalf("DCR/CIMD/S256 = %v/%v/%v, want true/false/true", res.SupportsDCR, res.SupportsCIMD, res.SupportsS256)
	}
	if !slices.Equal(res.Scopes, []string{"mcp", "mcp:read", "mcp:write", "control"}) {
		t.Fatalf("Scopes = %v", res.Scopes)
	}
	// Brain names its origin as the resource; it is a path prefix of the
	// MCP URL on the same origin, so it is the RFC 8707 resource.
	if res.Resource != as.issuer {
		t.Fatalf("Resource = %q, want %q", res.Resource, as.issuer)
	}
}

func TestDetectRootPRMFallbackAndChallengeMetadata(t *testing.T) {
	n := newFakeNet(t)
	as := newTestAS(t)
	mux := http.NewServeMux()
	as.routes(mux)
	var base string
	// Only the root well-known exists (path-aware 404).
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"resource": base + "/mcp", "authorization_servers": []string{base}})
	})
	mux.Handle("/mcp", gate(mcpHandler(), `Bearer realm="x", scope="files:read"`, func(*http.Request) bool { return false }))
	base = n.add("rootprm.example", mux)
	as.issuer = base
	res, err := newDiscoverer(t, n).Detect(t.Context(), base+"/mcp")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.AuthServerMetadata == nil || res.Resource != base+"/mcp" {
		t.Fatalf("result = %+v", res)
	}
	// The challenge's scope wins over scopes_supported.
	if !slices.Equal(res.Scopes, []string{"files:read"}) {
		t.Fatalf("Scopes = %v, want [files:read]", res.Scopes)
	}

	// resource_metadata in the challenge is followed first.
	mux2 := http.NewServeMux()
	as2 := newTestAS(t)
	as2.routes(mux2)
	var base2 string
	mux2.HandleFunc("GET /meta/prm.json", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"resource": base2 + "/mcp", "authorization_servers": []string{base2}})
	})
	mux2.Handle("/mcp", gate(mcpHandler(), `Bearer resource_metadata="http://challenge.example/meta/prm.json"`, func(*http.Request) bool { return false }))
	base2 = n.add("challenge.example", mux2)
	as2.issuer = base2
	res, err = newDiscoverer(t, n).Detect(t.Context(), base2+"/mcp")
	if err != nil {
		t.Fatalf("Detect(challenge): %v", err)
	}
	if res.AuthServerMetadata == nil {
		t.Fatalf("AS metadata not found via challenge: %+v", res)
	}
	if res.ResourceMetadataURL != "http://challenge.example/meta/prm.json" {
		t.Fatalf("ResourceMetadataURL = %q", res.ResourceMetadataURL)
	}
}

func TestDetectAPIKeyOnly(t *testing.T) {
	n := newFakeNet(t)
	mux := http.NewServeMux()
	mux.Handle("/mcp", gate(mcpHandler(), "", func(r *http.Request) bool { return r.Header.Get("X-Api-Key") == "k" }))
	base := n.add("apikey.example", mux)
	res, err := newDiscoverer(t, n).Detect(t.Context(), base+"/mcp")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	want := []string{store.MCPAuthAPIKey, store.MCPAuthBearer, store.MCPAuthHeaders}
	if !slices.Equal(res.AuthKinds, want) {
		t.Fatalf("AuthKinds = %v, want %v", res.AuthKinds, want)
	}
	if res.ResourceMetadata != nil || res.AuthServerMetadata != nil || res.SupportsDCR || res.SupportsCIMD {
		t.Fatalf("unexpected OAuth facts: %+v", res)
	}
}

func TestDetectNoAuth(t *testing.T) {
	n := newFakeNet(t)
	mux := http.NewServeMux()
	mux.Handle("/mcp", mcpHandler())
	base := n.add("open.example", mux)
	res, err := newDiscoverer(t, n).Detect(t.Context(), base+"/mcp")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !slices.Equal(res.AuthKinds, []string{store.MCPAuthNone}) {
		t.Fatalf("AuthKinds = %v, want [none]", res.AuthKinds)
	}
}

func TestDetectOIDCFallbackAndIssuerMismatch(t *testing.T) {
	n := newFakeNet(t)
	mux := http.NewServeMux()
	var base string
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"resource": base + "/mcp", "authorization_servers": []string{base + "/tenant"}})
	})
	mux.HandleFunc("GET /tenant/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{
			"issuer": base + "/tenant", "authorization_endpoint": base + "/tenant/auth", "token_endpoint": base + "/tenant/token",
			"code_challenge_methods_supported": []string{"S256"}, "scopes_supported": []string{"openid", "offline_access"},
		})
	})
	mux.Handle("/mcp", gate(mcpHandler(), `Bearer`, func(*http.Request) bool { return false }))
	base = n.add("oidc.example", mux)
	res, err := newDiscoverer(t, n).Detect(t.Context(), base+"/mcp")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.AuthServerMetadata == nil || res.AuthServerMetadata.TokenEndpoint != base+"/tenant/token" {
		t.Fatalf("AuthServerMetadata = %+v", res.AuthServerMetadata)
	}
	if !res.OfflineAccess {
		t.Fatal("OfflineAccess = false, want true (offline_access advertised)")
	}

	// An AS whose metadata names another issuer is ignored (RFC 8414 3.3).
	mux2 := http.NewServeMux()
	var base2 string
	mux2.HandleFunc("GET /.well-known/oauth-protected-resource", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"resource": base2, "authorization_servers": []string{base2}})
	})
	mux2.HandleFunc("GET /.well-known/oauth-authorization-server", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"issuer": "http://evil.example", "authorization_endpoint": base2 + "/a", "token_endpoint": base2 + "/t",
			"code_challenge_methods_supported": []string{"S256"}})
	})
	mux2.Handle("/mcp", gate(mcpHandler(), `Bearer`, func(*http.Request) bool { return false }))
	base2 = n.add("mixup.example", mux2)
	res, err = newDiscoverer(t, n).Detect(t.Context(), base2+"/mcp")
	if err != nil {
		t.Fatalf("Detect(mixup): %v", err)
	}
	if res.AuthServerMetadata != nil || slices.Contains(res.AuthKinds, store.MCPAuthOAuth) {
		t.Fatalf("mismatched issuer accepted: %+v", res)
	}
}

func TestDetectResourceMismatchRejected(t *testing.T) {
	n := newFakeNet(t)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, 200, map[string]any{"resource": "http://other.example/mcp", "authorization_servers": []string{"http://other.example"}})
	})
	mux.Handle("/mcp", gate(mcpHandler(), `Bearer`, func(*http.Request) bool { return false }))
	base := n.add("wrongres.example", mux)
	res, err := newDiscoverer(t, n).Detect(t.Context(), base+"/mcp")
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if res.ResourceMetadata != nil || res.AuthServerMetadata != nil {
		t.Fatalf("foreign resource metadata accepted: %+v", res)
	}
}

func TestDetectNetguardBlocksPrivateMetadata(t *testing.T) {
	for _, target := range []string{"http://127.0.0.1:1/x", "http://169.254.169.254/latest"} {
		t.Run(target, func(t *testing.T) {
			n := newFakeNet(t)
			mux := http.NewServeMux()
			var base string
			mux.HandleFunc("GET /.well-known/oauth-protected-resource", func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(w, 200, map[string]any{"resource": base, "authorization_servers": []string{target}})
			})
			mux.Handle("/mcp", gate(mcpHandler(), `Bearer resource_metadata="`+target+`"`, func(*http.Request) bool { return false }))
			base = n.add("ssrf.example", mux)
			res, err := newDiscoverer(t, n).Detect(t.Context(), base+"/mcp")
			if err != nil {
				t.Fatalf("Detect: %v", err)
			}
			if res.AuthServerMetadata != nil {
				t.Fatalf("internal AS metadata fetched: %+v", res.AuthServerMetadata)
			}
			if len(res.Blocked) == 0 {
				t.Fatalf("Blocked = %v, want the refused internal destinations reported", res.Blocked)
			}
		})
	}
}

func TestDetectUnreachableIsError(t *testing.T) {
	n := newFakeNet(t)
	_, err := newDiscoverer(t, n).Detect(t.Context(), "http://nowhere.example/mcp")
	var ce *client.Error
	if !errors.As(err, &ce) || ce.Class != client.ClassUnreachable {
		t.Fatalf("Detect = %v, want client unreachable", err)
	}
	_, err = newDiscoverer(t, n).Detect(t.Context(), "http://127.0.0.1:1/mcp")
	var be *netguard.BlockedError
	if !errors.As(err, &be) {
		t.Fatalf("Detect(loopback) = %v, want a netguard refusal", err)
	}
}
