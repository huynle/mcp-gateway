package authserver

import (
	"net/http"

	"github.com/huynle/mcp-gateway/internal/observability"
)

// Routes.
//
// Public (Mount, on the gateway's top-level mux, outside the portal's
// session handling):
//
//	GET  /.well-known/oauth-authorization-server        RFC 8414
//	GET  /.well-known/oauth-protected-resource          RFC 9728
//	GET  /.well-known/oauth-protected-resource/mcp      RFC 9728, path-aware (MCP 2025-11)
//	POST /oauth/register                                RFC 7591
//	POST /oauth/token                                   OAuth 2.1 token endpoint
//	POST /oauth/revoke                                  RFC 7009
//	GET  /oauth/jwks                                    JWK Set
//
// Portal (MountPortal, behind the portal's signed-in check and CSRF):
//
//	GET  /oauth/authorize                               OAuth 2.1 authorization endpoint
//	POST /oauth/authorize/consent                       the user's answer
//	GET  /harnesses                                     connected harnesses
//	POST /harnesses/{id}/revoke                         disconnect one

// Mounter is what Mount registers routes on (an *http.ServeMux).
type Mounter interface {
	Handle(pattern string, handler http.Handler)
}

// Mount registers the public OAuth routes. Discovery documents and the
// JWKS are readable cross-origin; registration and token requests answer
// CORS preflights so browser-hosted harnesses (the MCP inspector) work.
//
// Each path is registered without a method and dispatches itself, so a
// wrong method is 405 with Allow (RFC 9110 section 15.5.6) rather than
// whatever the mux's catch-all (the portal) would answer; OPTIONS is the
// CORS preflight.
func (s *Service) Mount(mux Mounter) {
	cfg := s.cfg
	for _, p := range []string{MetadataPath, ProtectedResourcePath, ProtectedResourcePath + cfg.ResourcePath} {
		mux.Handle(p, methods(http.MethodGet, documentHandler(cfg, p)))
	}
	mux.Handle(JWKSPath, methods(http.MethodGet, http.HandlerFunc(s.ServeJWKS)))
	mux.Handle(RegisterPath, methods(http.MethodPost, http.HandlerFunc(s.ServeRegister)))
	mux.Handle(TokenPath, methods(http.MethodPost, http.HandlerFunc(s.ServeToken)))
	mux.Handle(RevokePath, methods(http.MethodPost, http.HandlerFunc(s.ServeRevoke)))
}

// documentHandler picks the discovery document for a well-known path.
func documentHandler(cfg Config, path string) http.Handler {
	if path == MetadataPath {
		return MetadataHandler(cfg)
	}
	return ProtectedResourceHandler(cfg)
}

// methods serves next for the one allowed method (and HEAD for GET),
// answers the CORS preflight on OPTIONS, and 405 + Allow otherwise. Every
// answer carries the CORS headers (browser-hosted harnesses).
func methods(allowed string, next http.Handler) http.Handler {
	allow := allowed + ", OPTIONS"
	if allowed == http.MethodGet {
		allow = "GET, HEAD, OPTIONS"
	}
	return cors(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == allowed, allowed == http.MethodGet && r.Method == http.MethodHead:
			next.ServeHTTP(w, r)
		case r.Method == http.MethodOptions:
			w.Header().Set("Allow", allow)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.Header().Set("Allow", allow)
			writeError(w, http.StatusMethodNotAllowed, "invalid_request", allowed+" only")
		}
	}))
}

// MountPortal registers the pages that need a signed-in user through the
// portal's MountUser (which redirects anonymous requests to sign-in with
// return_to and checks CSRF on POST) and installs who as the session
// resolver.
func (s *Service) MountPortal(mountUser func(pattern string, handler http.Handler), who Identity) {
	s.SetIdentity(who)
	mountUser("GET "+AuthorizePath, http.HandlerFunc(s.ServeAuthorize))
	mountUser("POST "+ConsentPath, http.HandlerFunc(s.ServeConsent))
	mountUser("GET "+HarnessesPath, http.HandlerFunc(s.ServeHarnesses))
	mountUser("POST "+HarnessesPath+"/{id}/revoke", http.HandlerFunc(s.ServeHarnessRevoke))
}

// ServeJWKS is GET /oauth/jwks: the active key and the retired keys still
// inside their grace period.
func (s *Service) ServeJWKS(w http.ResponseWriter, r *http.Request) {
	set, err := s.keys.JWKS(r.Context())
	if err != nil {
		s.log.Error("jwks unavailable", "event", "authserver.jwks_failed", "error", observability.RedactError(err), "request_id", observability.RequestIDFromContext(r.Context()))
		writeError(w, http.StatusServiceUnavailable, "server_error", "keys are temporarily unavailable")
		return
	}
	writeDocument(w, set)
}

// cors allows cross-origin calls to the token-side endpoints.
func cors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, mcp-protocol-version")
		w.Header().Set("Access-Control-Max-Age", "600")
		next.ServeHTTP(w, r)
	})
}
