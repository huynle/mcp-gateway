package authserver

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
)

// The authorization endpoint (OAuth 2.1 section 4.1.1) and the consent
// page. Both live behind the portal's signed-in check (MountPortal), so a
// harness that opens the browser lands on company sign-in first and comes
// back here with the same query. Validation follows the standard's two
// tiers: anything wrong with the client or the redirect URI is answered
// on an error page and never redirected (section 4.1.2.1); every later
// problem is reported to the client at its registered redirect URI with
// the state echoed. PKCE is S256 only, the resource indicator (RFC 8707)
// must name this gateway's MCP endpoint, and state is required.

// Identity resolves the caller of a portal page: the session's user ID
// (empty when not signed in) and its CSRF token, which the consent form
// echoes. The portal module supplies it so this package never touches
// sessions.
type Identity func(r *http.Request) (userID, csrfToken string)

// Limits on authorization request parameters.
const (
	MaxStateLen = 512
	// codeBytes is the entropy of an authorization code.
	codeBytes = 32
)

// pkceRE is the PKCE verifier / challenge alphabet and length (RFC 7636
// sections 4.1 and 4.2).
var pkceRE = regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)

// SetIdentity installs the session resolver the authorize, consent and
// harnesses pages use. MountPortal sets it; tests call it directly.
func (s *Service) SetIdentity(who Identity) { s.who = who }

// authorizeRequest is a validated authorization request.
type authorizeRequest struct {
	client        *store.OAuthClient
	redirectURI   string
	state         string
	codeChallenge string
	scope         string
	resource      string
}

// protocolError is a validated-client error reported at the redirect URI.
type protocolError struct {
	code, description string
}

func (e *protocolError) Error() string { return e.code + ": " + e.description }

// clientError is a client / redirect URI problem shown on an error page.
type clientError struct{ message string }

func (e *clientError) Error() string { return e.message }

// ServeAuthorize is GET /oauth/authorize.
func (s *Service) ServeAuthorize(w http.ResponseWriter, r *http.Request) {
	userID, csrfToken := s.identity(r)
	if userID == "" {
		s.redirectToSignIn(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		s.errorPage(w, http.StatusMethodNotAllowed, "GET only.")
		return
	}
	req, err := s.parseAuthorize(r.Context(), r.URL.Query())
	if s.answerAuthorizeError(w, r, req, err) {
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	s.render(w, r, http.StatusOK, "consent.html", consentData{
		Title: "Connect a harness", CSRFToken: csrfToken, ClientName: req.client.ClientName, ClientID: req.client.ClientID,
		RedirectHost: hostOf(req.redirectURI), Resource: req.resource, Scopes: describeScopes(req.scope),
		Hidden: r.URL.Query(),
	})
}

// ServeConsent is POST /oauth/authorize/consent: the user's answer. The
// request is validated again from the posted fields (a tampered hidden
// field cannot obtain a code) and the CSRF token is checked here as well
// as by the portal.
func (s *Service) ServeConsent(w http.ResponseWriter, r *http.Request) {
	userID, csrfToken := s.identity(r)
	if userID == "" {
		s.errorPage(w, http.StatusUnauthorized, "Sign in before answering this request.")
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		s.errorPage(w, http.StatusMethodNotAllowed, "POST only.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	if err := r.ParseForm(); err != nil {
		s.errorPage(w, http.StatusBadRequest, "The form could not be read.")
		return
	}
	if got := r.PostForm.Get("_csrf"); subtle.ConstantTimeCompare([]byte(got), []byte(csrfToken)) != 1 {
		s.errorPage(w, http.StatusForbidden, "The form token is missing or expired. Start again from your harness.")
		return
	}
	req, err := s.parseAuthorize(r.Context(), r.PostForm)
	if s.answerAuthorizeError(w, r, req, err) {
		return
	}
	if r.PostForm.Get("action") != "approve" {
		s.log.Info("consent denied", "event", "authserver.consent_denied", "user_id", userID, "client_id", req.client.ClientID)
		s.record(r.Context(), userID, "", "oauth_consent_denied", req.client, "deny", "denied")
		s.redirectError(w, r, req, &protocolError{"access_denied", "the user denied the request"})
		return
	}
	code, err := s.issueCode(r.Context(), userID, req)
	if err != nil {
		s.log.Error("code not issued", "event", "authserver.code_failed", "error", observability.RedactError(err), "request_id", observability.RequestIDFromContext(r.Context()))
		s.redirectError(w, r, req, &protocolError{"server_error", "the authorization could not be completed; try again"})
		return
	}
	s.touchClient(r.Context(), req.client.ID, s.now())
	s.log.Info("consent granted", "event", "authserver.consent_granted", "user_id", userID, "client_id", req.client.ClientID, "scope", req.scope)
	s.record(r.Context(), userID, "", "oauth_consent_granted", req.client, "allow", "succeeded")
	u, _ := url.Parse(req.redirectURI)
	q := u.Query()
	q.Set("code", code)
	q.Set("state", req.state)
	u.RawQuery = q.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

// issueCode stores a fresh single-use code bound to the request.
func (s *Service) issueCode(ctx context.Context, userID string, req *authorizeRequest) (string, error) {
	code, err := randomToken(codeBytes)
	if err != nil {
		return "", err
	}
	row := &store.OAuthCode{
		CodeHash: hashSecret(code), UserID: userID, ClientID: req.client.ID, RedirectURI: req.redirectURI,
		Resource: req.resource, Scope: req.scope, CodeChallenge: req.codeChallenge, ExpiresAt: s.now().Add(s.cfg.CodeTTL),
	}
	err = s.st.AsUser(ctx, userID, func(tx Tx) error { return tx.CreateCode(ctx, row) })
	if err != nil {
		return "", err
	}
	return code, nil
}

// parseAuthorize validates the request parameters (query or posted form)
// in the order the standard requires.
func (s *Service) parseAuthorize(ctx context.Context, q url.Values) (*authorizeRequest, error) {
	clientID := q.Get("client_id")
	if clientID == "" {
		return nil, &clientError{"The request does not name a client."}
	}
	var client *store.OAuthClient
	err := s.st.Bypass(ctx, func(tx Tx) error {
		var err error
		client, err = tx.FindClientByClientID(ctx, clientID)
		return err
	})
	switch {
	case errors.Is(err, store.ErrNotFound):
		return nil, &clientError{"Unknown client. Register the harness again (its registration may have expired)."}
	case err != nil:
		return nil, err
	}
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" || !redirectURIRegistered(client.RedirectURIs, redirectURI) {
		return nil, &clientError{"The redirect URI is missing or is not one the client registered."}
	}
	req := &authorizeRequest{client: client, redirectURI: redirectURI, state: q.Get("state")}
	meta := clientMeta(client)
	switch rt := q.Get("response_type"); {
	case rt == "":
		return req, &protocolError{"invalid_request", "response_type is required"}
	case rt != ResponseTypeCode || !slices.Contains(meta.ResponseTypes, rt):
		return req, &protocolError{"unsupported_response_type", "only response_type=code is supported"}
	}
	switch {
	case req.state == "":
		return req, &protocolError{"invalid_request", "state is required"}
	case len(req.state) > MaxStateLen:
		return req, &protocolError{"invalid_request", "state is too long"}
	}
	req.codeChallenge = q.Get("code_challenge")
	switch method := q.Get("code_challenge_method"); {
	case req.codeChallenge == "":
		return req, &protocolError{"invalid_request", "code_challenge is required (PKCE S256)"}
	case method != "S256":
		return req, &protocolError{"invalid_request", "code_challenge_method must be S256"}
	case !pkceRE.MatchString(req.codeChallenge):
		return req, &protocolError{"invalid_request", "code_challenge is malformed"}
	}
	scope, ok := ParseScope(q.Get("scope"))
	if !ok {
		return req, &protocolError{"invalid_scope", "scope must be a subset of: " + strings.Join(ScopesSupported, " ")}
	}
	if meta.Scope != "" && !scopeWithin(scope, meta.Scope) {
		return req, &protocolError{"invalid_scope", "scope exceeds what the client registered"}
	}
	req.scope = scope
	resource := q.Get("resource")
	switch {
	case resource == "":
		return req, &protocolError{"invalid_target", "resource is required and must be " + s.cfg.Resource()}
	case !sameResource(resource, s.cfg.Resource()):
		return req, &protocolError{"invalid_target", "resource must be " + s.cfg.Resource()}
	}
	req.resource = s.cfg.Resource()
	return req, nil
}

// answerAuthorizeError renders or redirects an authorization error and
// reports whether one was answered.
func (s *Service) answerAuthorizeError(w http.ResponseWriter, r *http.Request, req *authorizeRequest, err error) bool {
	var ce *clientError
	var pe *protocolError
	switch {
	case err == nil:
		return false
	case errors.As(err, &ce):
		s.log.Warn("authorization request refused", "event", "authserver.authorize_refused", "reason", ce.message, "client_id", r.FormValue("client_id"))
		s.errorPage(w, http.StatusBadRequest, ce.message)
	case errors.As(err, &pe) && req != nil:
		s.log.Warn("authorization request rejected", "event", "authserver.authorize_rejected", "error", pe.code, "description", pe.description, "client_id", req.client.ClientID)
		s.redirectError(w, r, req, pe)
	default:
		s.log.Error("authorization request failed", "event", "authserver.authorize_failed", "error", observability.RedactError(err), "request_id", observability.RequestIDFromContext(r.Context()))
		s.errorPage(w, http.StatusInternalServerError, "The request could not be completed. Try again.")
	}
	return true
}

// redirectError sends the client an error at its registered redirect URI.
func (s *Service) redirectError(w http.ResponseWriter, r *http.Request, req *authorizeRequest, pe *protocolError) {
	u, err := url.Parse(req.redirectURI)
	if err != nil {
		s.errorPage(w, http.StatusBadRequest, "The redirect URI is invalid.")
		return
	}
	q := u.Query()
	q.Set("error", pe.code)
	q.Set("error_description", pe.description)
	if req.state != "" {
		q.Set("state", req.state)
	}
	u.RawQuery = q.Encode()
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, u.String(), http.StatusSeeOther)
}

// redirectToSignIn sends an anonymous browser to the portal's sign-in page
// with this request as the return path (the portal does the same for
// every signed-in page; this covers the handler used on its own).
func (s *Service) redirectToSignIn(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	http.Redirect(w, r, "/signin?return_to="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
}

// identity resolves the caller through the installed Identity.
func (s *Service) identity(r *http.Request) (string, string) {
	if s.who == nil {
		return "", ""
	}
	return s.who(r)
}

// redirectURIRegistered reports whether requested is one of the client's
// registered redirect URIs: an exact string match (OAuth 2.1 section
// 4.1.3, MCP spec "Open Redirection"), or, for an http URI on the
// loopback interface, a match in everything but the port (OAuth 2.1
// section 8.4.2, RFC 8252 section 7.3: native harnesses bind an
// ephemeral port per run). The code is then bound to the URI actually
// used, so the token request must repeat it.
func redirectURIRegistered(registered []string, requested string) bool {
	if slices.Contains(registered, requested) {
		return true
	}
	u, err := url.Parse(requested)
	if err != nil || u.Scheme != "http" || !isLoopbackHost(u.Hostname()) || u.User != nil || u.Opaque != "" || u.Fragment != "" || strings.Contains(requested, "#") {
		return false
	}
	for _, raw := range registered {
		r, err := url.Parse(raw)
		if err != nil || r.Scheme != "http" || !isLoopbackHost(r.Hostname()) {
			continue
		}
		if r.Hostname() == u.Hostname() && r.EscapedPath() == u.EscapedPath() && r.RawQuery == u.RawQuery && r.User == nil {
			return true
		}
	}
	return false
}

// sameResource compares a requested resource indicator with the canonical
// one: scheme and host case-insensitively, the rest exactly (RFC 8707
// section 2; the MCP spec asks servers to accept upper-case scheme and
// host).
func sameResource(requested, canonical string) bool {
	a, err := url.Parse(requested)
	if err != nil {
		return false
	}
	b, err := url.Parse(canonical)
	if err != nil {
		return false
	}
	return strings.EqualFold(a.Scheme, b.Scheme) && strings.EqualFold(a.Host, b.Host) &&
		a.Path == b.Path && a.RawQuery == b.RawQuery && a.Fragment == "" && a.User == nil && a.Opaque == ""
}

// scopeWithin reports whether every value of requested is granted by
// allowed; ScopeFull grants everything (a read-only token can be minted
// from a full refresh token, never the reverse).
func scopeWithin(requested, allowed string) bool {
	allowedSet := strings.Fields(allowed)
	if slices.Contains(allowedSet, ScopeFull) {
		return true
	}
	for _, f := range strings.Fields(requested) {
		if !slices.Contains(allowedSet, f) {
			return false
		}
	}
	return true
}

// describeScopes explains the requested scopes to the user.
func describeScopes(scope string) []string {
	var out []string
	for _, f := range strings.Fields(scope) {
		switch f {
		case ScopeFull:
			out = append(out, "Use the tools your role allows, including writes (mcp)")
		case ScopeRead:
			out = append(out, "Read-only access to the tools your role allows (mcp:read)")
		default:
			out = append(out, f)
		}
	}
	return out
}

// hostOf is the host part of a URL, for display.
func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// record files a user audit event; a failure is logged, never surfaced.
func (s *Service) record(ctx context.Context, userID, familyID, action string, client *store.OAuthClient, decision, outcome string) {
	ev := audit.Event{
		Time:             s.now(),
		UserID:           userID,
		TokenID:          familyID,
		ResourceIdentity: map[string]string{"action": action},
		Decision:         decision,
		Outcome:          outcome,
		RequestID:        observability.RequestIDFromContext(ctx),
	}
	if client != nil {
		ev.ResourceIdentity["client_id"] = client.ClientID
		ev.ResourceIdentity["client_name"] = client.ClientName
	}
	if err := s.audit.Record(ctx, ev); err != nil {
		s.log.Error("audit event not recorded", "event", "authserver.audit_failed", "action", action, "error", observability.RedactError(err))
	}
}

// clientMeta decodes a stored client's metadata with the defaults a
// registration without those fields received.
func clientMeta(c *store.OAuthClient) clientMetadata {
	var m clientMetadata
	_ = json.Unmarshal(c.Metadata, &m)
	if m.TokenEndpointAuthMethod == "" {
		m.TokenEndpointAuthMethod = AuthMethodNone
	}
	if len(m.GrantTypes) == 0 {
		m.GrantTypes = []string{GrantAuthorizationCode, GrantRefreshToken}
	}
	if len(m.ResponseTypes) == 0 {
		m.ResponseTypes = []string{ResponseTypeCode}
	}
	return m
}

// touchClient marks a client used (it completed a sign-in or a token
// exchange) in its own transaction, best-effort: it only affects pruning.
func (s *Service) touchClient(ctx context.Context, id string, at time.Time) {
	err := s.st.Bypass(ctx, func(tx Tx) error { return tx.TouchClient(ctx, id, at) })
	if err != nil {
		s.log.Warn("oauth client last_used_at not updated", "event", "authserver.touch_failed", "error", observability.RedactError(err))
	}
}
