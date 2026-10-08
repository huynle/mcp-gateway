package identity

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"html"
	"net/http"
	"regexp"
	"time"

	"github.com/zitadel/oidc/v3/pkg/client/rp"
	"github.com/zitadel/oidc/v3/pkg/oidc"

	"github.com/huynle/mcp-gateway/internal/store"
)

// ErrorHandler renders a sign-in error page. The portal installs its own
// templated version with SetErrorHandler; the default is plain HTML.
type ErrorHandler func(w http.ResponseWriter, r *http.Request, status int, message string)

var oauthErrorCodeRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

func defaultErrorHandler(w http.ResponseWriter, _ *http.Request, status int, message string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = fmt.Fprintf(w, "<!doctype html><title>Sign-in failed</title><h1>Sign-in failed</h1><p>%s</p><p><a href=\"/\">Back</a></p>\n", html.EscapeString(message))
}

// SetErrorHandler replaces the sign-in error page renderer.
func (s *Service) SetErrorHandler(h ErrorHandler) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.errorHandler = h
}

func (s *Service) renderError(w http.ResponseWriter, r *http.Request, status int, message string) {
	s.mu.RLock()
	h := s.errorHandler
	s.mu.RUnlock()
	if h == nil {
		h = defaultErrorHandler
	}
	h(w, r, status, message)
}

// Handler serves the sign-in routes:
//
//	GET  /auth/{provider}/start?return_to=/path  redirect to the provider
//	GET  /auth/{provider}/callback               code exchange, session
//	POST /auth/signout                           revoke the session
//
// Sign-out is state-changing and must run behind the portal's CSRF check.
func (s *Service) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /auth/{provider}/start", s.start)
	mux.HandleFunc("GET /auth/{provider}/callback", s.callback)
	mux.HandleFunc("POST /auth/signout", s.SignOut)
	mux.HandleFunc("/auth/signout", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Allow", http.MethodPost)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	})
	return mux
}

func (s *Service) start(w http.ResponseWriter, r *http.Request) {
	p, ok := s.byName[r.PathValue("provider")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	relying, err := p.relyingParty(r.Context())
	if err != nil {
		s.log.Error("oidc discovery failed", "event", "identity.discovery_failed", "provider", p.cfg.Name, "error", err)
		s.renderError(w, r, http.StatusBadGateway, "The identity provider is not reachable right now. Try again in a moment.")
		return
	}
	now := s.now()
	ls, err := s.newLoginState(p, SafeReturnTo(r.URL.Query().Get("return_to")), now)
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Could not start sign-in.")
		return
	}
	value, err := ls.encode(loginKey(p.cfg.ClientSecret))
	if err != nil {
		s.renderError(w, r, http.StatusInternalServerError, "Could not start sign-in.")
		return
	}
	http.SetCookie(w, s.loginCookie(value, ls.Expires))
	w.Header().Set("Cache-Control", "no-store")
	authURL := rp.AuthURL(ls.State, relying,
		rp.WithCodeChallenge(ls.codeChallenge()),
		rp.AuthURLOpt(rp.WithURLParam("nonce", ls.Nonce)),
	)
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Service) callback(w http.ResponseWriter, r *http.Request) {
	p, ok := s.byName[r.PathValue("provider")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	now := s.now()
	q := r.URL.Query()

	ck, err := r.Cookie(LoginCookie)
	if err != nil {
		s.renderError(w, r, http.StatusBadRequest, "No sign-in in progress (the sign-in cookie is missing). Start again.")
		return
	}
	s.clearLoginCookie(w)
	ls, err := decodeLoginState(ck.Value, loginKey(p.cfg.ClientSecret), now)
	if err != nil || ls.Provider != p.cfg.Name {
		s.log.Warn("sign-in rejected", "event", "identity.signin_rejected", "provider", p.cfg.Name, "reason", "login_state_invalid")
		s.renderError(w, r, http.StatusBadRequest, "The sign-in attempt is invalid or expired. Start again.")
		return
	}
	if code := q.Get("error"); code != "" {
		if !oauthErrorCodeRE.MatchString(code) {
			code = "error"
		}
		s.log.Warn("sign-in rejected", "event", "identity.signin_rejected", "provider", p.cfg.Name, "reason", "provider_error", "provider_error", code)
		s.renderError(w, r, http.StatusBadRequest, "The identity provider refused the sign-in ("+code+").")
		return
	}
	if subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(ls.State)) != 1 {
		s.log.Warn("sign-in rejected", "event", "identity.signin_rejected", "provider", p.cfg.Name, "reason", "state_mismatch")
		s.renderError(w, r, http.StatusBadRequest, "The sign-in state does not match. Start again.")
		return
	}
	relying, err := p.relyingParty(r.Context())
	if err != nil {
		s.log.Error("oidc discovery failed", "event", "identity.discovery_failed", "provider", p.cfg.Name, "error", err)
		s.renderError(w, r, http.StatusBadGateway, "The identity provider is not reachable right now. Try again in a moment.")
		return
	}
	tokens, err := rp.CodeExchange[*oidc.IDTokenClaims](withNonce(r.Context(), ls.Nonce), q.Get("code"), relying, rp.WithCodeVerifier(ls.Verifier))
	if err != nil {
		s.log.Warn("sign-in rejected", "event", "identity.signin_rejected", "provider", p.cfg.Name, "reason", "code_exchange_failed", "error", err.Error())
		s.renderError(w, r, http.StatusUnauthorized, "The identity provider did not accept the sign-in. Start again.")
		return
	}
	claims := claimsFromIDToken(tokens.IDTokenClaims)

	// Rotate: the browser's previous session, if any, ends now.
	if prev, err := r.Cookie(SessionCookie); err == nil && prev.Value != "" {
		s.revokeByCookie(r.Context(), prev.Value, now)
	}
	res, err := s.SignIn(r.Context(), p.cfg.Name, claims)
	switch {
	case errors.Is(err, ErrNotAllowed):
		s.renderError(w, r, http.StatusForbidden, "This account is not allowed to use the gateway. Sign in with your company account, or ask an administrator.")
		return
	case errors.Is(err, ErrUserDisabled):
		s.renderError(w, r, http.StatusForbidden, "This account has been disabled. Ask an administrator.")
		return
	case err != nil:
		s.log.Error("sign-in failed", "event", "identity.signin_failed", "provider", p.cfg.Name, "error", err)
		s.renderError(w, r, http.StatusInternalServerError, "Sign-in failed. Try again.")
		return
	}
	http.SetCookie(w, res.Cookie)
	http.Redirect(w, r, ls.ReturnTo, http.StatusSeeOther)
}

func claimsFromIDToken(t *oidc.IDTokenClaims) Claims {
	c := Claims{
		Issuer:        t.Issuer,
		Subject:       t.Subject,
		Name:          t.Name,
		Email:         t.Email,
		EmailVerified: bool(t.EmailVerified),
		Extra:         map[string]any{},
	}
	if c.Name == "" {
		c.Name = t.PreferredUsername
	}
	for k, v := range t.Claims {
		c.Extra[k] = v
	}
	return c
}

// SignOut revokes the request's session, clears the cookie and redirects
// to /. It is the handler behind POST /auth/signout.
func (s *Service) SignOut(w http.ResponseWriter, r *http.Request) {
	if ck, err := r.Cookie(SessionCookie); err == nil && ck.Value != "" {
		s.revokeByCookie(r.Context(), ck.Value, s.now())
	}
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: "", Path: "/", HttpOnly: true,
		Secure: s.cfg.CookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Service) revokeByCookie(ctx context.Context, secret string, now time.Time) {
	err := s.store.Bypass(ctx, func(tx Tx) error {
		sess, err := tx.FindSessionByTokenHash(ctx, hashSecret(secret))
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		return tx.RevokeSession(ctx, sess.ID, now)
	})
	if err != nil {
		s.log.Error("revoke session failed", "event", "identity.session_revoke_failed", "error", err)
	}
}

type principalKey struct{}

// PrincipalFrom returns the signed-in user attached by Middleware, or nil
// for an anonymous request.
func PrincipalFrom(ctx context.Context) *Principal {
	p, _ := ctx.Value(principalKey{}).(*Principal)
	return p
}

// WithPrincipal attaches a principal to ctx (tests and trusted callers).
func WithPrincipal(ctx context.Context, p *Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// touchInterval throttles last_seen_at writes.
const touchInterval = time.Minute

// Middleware resolves the session cookie into a Principal for downstream
// handlers. Anything wrong with the session (unknown, revoked, expired,
// idle too long, user disabled) leaves the request anonymous; the handlers
// decide what anonymous means for them.
func (s *Service) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ck, err := r.Cookie(SessionCookie)
		if err != nil || ck.Value == "" {
			next.ServeHTTP(w, r)
			return
		}
		p, err := s.resolveSession(r.Context(), ck.Value)
		if err != nil {
			s.log.Error("session lookup failed", "event", "identity.session_lookup_failed", "error", err)
		}
		if p == nil {
			next.ServeHTTP(w, r)
			return
		}
		next.ServeHTTP(w, r.WithContext(WithPrincipal(r.Context(), p)))
	})
}

// resolveSession validates the session secret and returns its principal,
// or nil when the session is not usable.
func (s *Service) resolveSession(ctx context.Context, secret string) (*Principal, error) {
	now := s.now()
	var p *Principal
	err := s.store.Bypass(ctx, func(tx Tx) error {
		sess, err := tx.FindSessionByTokenHash(ctx, hashSecret(secret))
		if errors.Is(err, store.ErrNotFound) {
			return nil
		}
		if err != nil {
			return err
		}
		if sess.RevokedAt != nil || !now.Before(sess.ExpiresAt) {
			return nil
		}
		lastSeen := sess.CreatedAt
		if sess.LastSeenAt != nil && sess.LastSeenAt.After(lastSeen) {
			lastSeen = *sess.LastSeenAt
		}
		if now.Sub(lastSeen) > s.cfg.IdleTimeout {
			return tx.RevokeSession(ctx, sess.ID, now)
		}
		u, err := tx.GetUser(ctx, sess.UserID)
		if err != nil {
			return err
		}
		if u.Status != store.UserActive {
			return tx.RevokeSession(ctx, sess.ID, now)
		}
		roles, err := roleNames(ctx, tx, u.ID)
		if err != nil {
			return err
		}
		if now.Sub(lastSeen) >= touchInterval {
			if err := tx.TouchSession(ctx, sess.ID, now); err != nil {
				return err
			}
		}
		p = &Principal{UserID: u.ID, DisplayName: u.DisplayName, Roles: roles, SessionID: sess.ID, CSRFToken: csrfToken(secret)}
		return nil
	})
	return p, err
}
