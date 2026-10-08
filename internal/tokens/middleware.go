package tokens

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/huynle/mcp-gateway/internal/observability"
)

// DefaultRealm is the WWW-Authenticate realm when MiddlewareOptions.Realm
// is empty.
const DefaultRealm = "mcp-gateway"

type principalKey struct{}

// PrincipalFrom returns the token principal BearerMiddleware attached, or
// nil when the request did not carry a valid token.
func PrincipalFrom(ctx context.Context) *Principal {
	p, _ := ctx.Value(principalKey{}).(*Principal)
	return p
}

// WithPrincipal attaches a principal to ctx (tests and trusted callers).
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// MiddlewareOptions tunes BearerMiddleware. Every field is optional.
type MiddlewareOptions struct {
	// Limiter bounds failed authentications per client; nil disables the
	// limit (tests). Production passes NewFailureLimiter(DefaultFailureBurst,
	// DefaultFailureWindow).
	Limiter *FailureLimiter
	// ClientIP derives the limiter key from the request. The default is the
	// host part of RemoteAddr; a deployment behind a trusted proxy supplies
	// one that reads the proxy's header.
	ClientIP func(*http.Request) string
	// Realm goes into WWW-Authenticate; empty means DefaultRealm. The /mcp
	// task may append the resource metadata URL (RFC 9728) through
	// WWWAuthenticateExtra.
	Realm string
	// WWWAuthenticateExtra is appended verbatim to every WWW-Authenticate
	// challenge, after a comma (for example
	// `resource_metadata="https://gw.example.com/.well-known/oauth-protected-resource"`).
	WWWAuthenticateExtra string
	// Metrics counts rate-limited requests as auth failures with reason
	// "rate_limited"; nil disables that.
	Metrics *observability.Metrics
	// Log defaults to slog.Default().
	Log *slog.Logger
}

// BearerMiddleware authenticates `Authorization: Bearer <token>` with auth
// and attaches the Principal to the request context (PrincipalFrom).
//
//   - no bearer: 401 with a WWW-Authenticate challenge (RFC 6750 section
//     3); not counted as a failure so harnesses discovering the endpoint
//     do not spend the client's budget;
//   - client over its failure budget: 429 with Retry-After, before the
//     authenticator is consulted;
//   - rejected token (*Error): one failure for the client, 401 with
//     error="invalid_token" and the reason's message in both the challenge
//     and a JSON body;
//   - any other error (store unreachable): 503, not counted as a failure.
//
// The bearer value is never written to the response or the log.
func BearerMiddleware(auth Authenticator, opts MiddlewareOptions) func(http.Handler) http.Handler {
	if opts.ClientIP == nil {
		opts.ClientIP = remoteIP
	}
	if opts.Realm == "" {
		opts.Realm = DefaultRealm
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	challenge := `Bearer realm="` + opts.Realm + `"`
	if opts.WWWAuthenticateExtra != "" {
		challenge += ", " + opts.WWWAuthenticateExtra
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			bearer, ok := bearerToken(r.Header.Get("Authorization"))
			if !ok {
				w.Header().Set("WWW-Authenticate", challenge)
				writeJSON(w, http.StatusUnauthorized, "invalid_request", "a bearer token is required")
				return
			}
			ip := opts.ClientIP(r)
			if opts.Limiter != nil {
				if allowed, wait := opts.Limiter.Allow(ip); !allowed {
					if opts.Metrics != nil {
						opts.Metrics.AuthFailure("rate_limited")
					}
					w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
					writeJSON(w, http.StatusTooManyRequests, "rate_limited", "too many failed authentications; retry later")
					return
				}
			}
			p, err := auth.Authenticate(r.Context(), bearer)
			var authErr *Error
			switch {
			case errors.As(err, &authErr):
				if opts.Limiter != nil {
					opts.Limiter.Fail(ip)
				}
				msg := authErr.Message()
				w.Header().Set("WWW-Authenticate", challenge+`, error="invalid_token", error_description="`+msg+`"`)
				writeJSON(w, http.StatusUnauthorized, "invalid_token", msg)
				return
			case err != nil:
				opts.Log.Error("bearer authentication unavailable", "event", "tokens.auth_unavailable",
					"error", observability.RedactError(err), "request_id", observability.RequestIDFromContext(r.Context()))
				writeJSON(w, http.StatusServiceUnavailable, "server_error", "authentication is temporarily unavailable")
				return
			}
			next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
		})
	}
}

// bearerToken extracts the credential from an Authorization header value.
// The scheme is case-insensitive (RFC 7235); an empty credential is "no
// bearer".
func bearerToken(header string) (string, bool) {
	scheme, rest, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	rest = strings.TrimSpace(rest)
	return rest, rest != ""
}

// remoteIP is the default client key: the host part of RemoteAddr.
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": description})
}
