package main

import (
	"fmt"
	"log/slog"
	"net/http"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/authserver"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/jobs"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// newAuthServer builds the MCP OAuth 2.1 authorization server (decisions
// 3ycafouv, ysorv868) over the store and the envelope-encryption key
// provider, with the issuer = GATEWAY_BASE_URL, the resource =
// GATEWAY_BASE_URL + /mcp, the generated-token sign-in rule
// (GATEWAY_TOKEN_SIGNIN_MAX_AGE) for refresh tokens, and the
// GATEWAY_OAUTH_* settings read from getenv. Signing keys are stored
// encrypted, so without a key provider the server is not built (nil,
// nil): /mcp then accepts generated tokens only and the discovery
// documents are not served.
func newAuthServer(cfg config.Config, st *store.Store, keys crypto.KeyProvider, rec audit.Recorder, metrics *observability.Metrics, getenv func(string) string, log *slog.Logger) (*authserver.Service, error) {
	if keys == nil {
		log.Warn("no key provider: MCP OAuth sign-in is not available; harnesses must use generated tokens")
		return nil, nil
	}
	acfg, err := authserver.ConfigFromEnv(cfg.BaseURL, getenv)
	if err != nil {
		return nil, fmt.Errorf("authserver: %w", err)
	}
	acfg.SignInMaxAge = cfg.TokenSignInMaxAge
	svc, err := authserver.New(acfg, authserver.NewPostgresStore(st), keys, authserver.Options{Audit: rec, Metrics: metrics, Log: log})
	if err != nil {
		return nil, fmt.Errorf("authserver: %w", err)
	}
	log.Info("oauth authorization server ready", "issuer", acfg.Issuer, "resource", acfg.Resource(),
		"access_ttl", acfg.AccessTokenTTL, "refresh_ttl", acfg.RefreshTokenTTL, "client_idle", acfg.ClientIdle,
		"register_per_min", acfg.RegisterPerMin, "key_rotation", acfg.KeyRotation, "key_grace", acfg.KeyGrace)
	return svc, nil
}

// composeAuthenticator is what /mcp authenticates bearers with: generated
// mgw_ tokens through the token service and OAuth access tokens (JWTs)
// through the authorization server, routed by shape. Without an
// authorization server only generated tokens are accepted.
func composeAuthenticator(tokenSvc *tokens.Service, authSvc *authserver.Service) tokens.Authenticator {
	if authSvc == nil {
		return tokenSvc
	}
	return authserver.Composite(tokenSvc, authSvc.Authenticator())
}

// withOAuthRoutes mounts the public OAuth endpoints (discovery, register,
// token, revoke, JWKS) on the top-level mux, outside the portal's session
// handling.
func withOAuthRoutes(authSvc *authserver.Service) muxExtra {
	return func(mux *http.ServeMux) {
		if authSvc != nil {
			authSvc.Mount(mux)
		}
	}
}

// withHarnessPages mounts the authorize, consent and connected-harnesses
// pages behind the portal's signed-in check and registers the disable
// hook that revokes a user's refresh tokens with their sessions.
func withHarnessPages(authSvc *authserver.Service) portalExtra {
	return func(idSvc *identity.Service, mountUser func(string, http.Handler), session func(*http.Request) (string, string), _ *slog.Logger, _ http.Handler) {
		if authSvc == nil {
			return
		}
		authSvc.MountPortal(mountUser, session)
		idSvc.OnDisable(authSvc.DisableHook())
	}
}

// authServerJobs are the background jobs the authorization server needs:
// pruning idle clients and expired codes, and rotating the signing key.
func authServerJobs(authSvc *authserver.Service) []jobs.Job {
	if authSvc == nil {
		return nil
	}
	return []jobs.Job{authSvc.PruneJob(0), authSvc.KeyRotationJob(0)}
}
