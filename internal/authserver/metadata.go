package authserver

import (
	"encoding/json"
	"net/http"
)

// Routes the authorization server mounts on the public mux. The
// well-known paths are fixed by RFC 8414 and RFC 9728; the rest are this
// gateway's choice and are only ever reached through the metadata.
const (
	MetadataPath          = "/.well-known/oauth-authorization-server"
	ProtectedResourcePath = "/.well-known/oauth-protected-resource"
	AuthorizePath         = "/oauth/authorize"
	ConsentPath           = "/oauth/authorize/consent"
	TokenPath             = "/oauth/token"
	RegisterPath          = "/oauth/register"
	RevokePath            = "/oauth/revoke"
	JWKSPath              = "/oauth/jwks"
	HarnessesPath         = "/harnesses"
	// DefaultResourcePath is where the protected resource (the MCP
	// endpoint) lives under the issuer.
	DefaultResourcePath = "/mcp"
)

// Scopes an access token can carry. ScopeFull is everything the user's
// role allows; ScopeRead narrows that to read tools, like a read-only
// generated token.
const (
	ScopeFull = "mcp"
	ScopeRead = "mcp:read"
)

// ScopesSupported is the advertised scope list.
var ScopesSupported = []string{ScopeFull, ScopeRead}

// ASMetadata is the RFC 8414 document.
type ASMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	RevocationEndpoint                string   `json:"revocation_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	RevocationAuthMethodsSupported    []string `json:"revocation_endpoint_auth_methods_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ServiceDocumentation              string   `json:"service_documentation"`
}

// PRMetadata is the RFC 9728 document.
type PRMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	BearerMethodsSupported []string `json:"bearer_methods_supported"`
	ScopesSupported        []string `json:"scopes_supported"`
	ResourceName           string   `json:"resource_name"`
}

// AuthorizationServerMetadata builds the RFC 8414 document for cfg.
func AuthorizationServerMetadata(cfg Config) ASMetadata {
	return ASMetadata{
		Issuer:                            cfg.issuer(),
		AuthorizationEndpoint:             cfg.URL(AuthorizePath),
		TokenEndpoint:                     cfg.URL(TokenPath),
		RegistrationEndpoint:              cfg.URL(RegisterPath),
		RevocationEndpoint:                cfg.URL(RevokePath),
		JWKSURI:                           cfg.URL(JWKSPath),
		ResponseTypesSupported:            []string{"code"},
		ResponseModesSupported:            []string{"query"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{"none", "client_secret_post", "client_secret_basic"},
		RevocationAuthMethodsSupported:    []string{"none", "client_secret_post", "client_secret_basic"},
		ScopesSupported:                   ScopesSupported,
		ServiceDocumentation:              cfg.URL(HarnessesPath),
	}
}

// ProtectedResourceMetadata builds the RFC 9728 document for cfg: the MCP
// endpoint is the resource and this gateway its only authorization server.
func ProtectedResourceMetadata(cfg Config) PRMetadata {
	return PRMetadata{
		Resource:               cfg.Resource(),
		AuthorizationServers:   []string{cfg.issuer()},
		BearerMethodsSupported: []string{"header"},
		ScopesSupported:        ScopesSupported,
		ResourceName:           "MCP Gateway",
	}
}

// MetadataHandler serves the RFC 8414 document.
func MetadataHandler(cfg Config) http.Handler {
	doc := AuthorizationServerMetadata(cfg)
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { writeDocument(w, doc) })
}

// ProtectedResourceHandler serves the RFC 9728 document. Mount it at
// ProtectedResourcePath and at ProtectedResourcePath + ResourcePath: the
// 2025-11 MCP spec tries the path-aware location first.
func ProtectedResourceHandler(cfg Config) http.Handler {
	doc := ProtectedResourceMetadata(cfg)
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { writeDocument(w, doc) })
}

// writeDocument sends a discovery document: plain JSON, cacheable for a
// short while, readable cross-origin (browser-based harnesses).
func writeDocument(w http.ResponseWriter, doc any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "mcp-protocol-version")
	_ = json.NewEncoder(w).Encode(doc)
}
