package authserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Dynamic client registration (RFC 7591). Registration is open because
// harnesses register themselves before any user is known (decision
// ysorv868), so it is bounded three ways: redirect URIs are restricted to
// https or loopback http, every address gets RegisterPerMin registrations
// a minute, and at most MaxUnusedClients registrations that never
// completed a sign-in are kept, the rest being pruned after ClientIdle.
// Clients are public (PKCE, no secret) unless they ask for a secret.

// Registration limits.
const (
	MaxRedirectURIs   = 10
	MaxRedirectURILen = 2048
	MaxClientNameLen  = 100
	MaxRegisterBody   = 64 << 10
	// ClientIDPrefix starts every issued client_id.
	ClientIDPrefix = "gwc_"
	// DefaultClientName names a client that did not give one.
	DefaultClientName = "Unnamed harness"
)

// Client authentication methods (RFC 7591 token_endpoint_auth_method).
const (
	AuthMethodNone        = "none"
	AuthMethodSecretPost  = "client_secret_post"
	AuthMethodSecretBasic = "client_secret_basic"
)

// Grant and response types.
const (
	GrantAuthorizationCode = "authorization_code"
	GrantRefreshToken      = "refresh_token"
	ResponseTypeCode       = "code"
)

var (
	authMethodsSupported = []string{AuthMethodNone, AuthMethodSecretPost, AuthMethodSecretBasic}
	grantTypesSupported  = []string{GrantAuthorizationCode, GrantRefreshToken}
)

// RegistrationRequest is the RFC 7591 client metadata this server reads.
type RegistrationRequest struct {
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string `json:"grant_types,omitempty"`
	ResponseTypes           []string `json:"response_types,omitempty"`
	ClientName              string   `json:"client_name,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	Scope                   string   `json:"scope,omitempty"`
	SoftwareID              string   `json:"software_id,omitempty"`
	SoftwareVersion         string   `json:"software_version,omitempty"`
}

// RegistrationResponse is the RFC 7591 answer: the registered metadata
// plus the issued identifier (and secret, once, for confidential clients).
type RegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientSecretExpiresAt   *int64   `json:"client_secret_expires_at,omitempty"`
	ClientName              string   `json:"client_name"`
	RedirectURIs            []string `json:"redirect_uris"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
}

// clientMetadata is what the oauth_clients.metadata column stores.
type clientMetadata struct {
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	Scope                   string   `json:"scope,omitempty"`
	ClientURI               string   `json:"client_uri,omitempty"`
	LogoURI                 string   `json:"logo_uri,omitempty"`
	SoftwareID              string   `json:"software_id,omitempty"`
	SoftwareVersion         string   `json:"software_version,omitempty"`
}

// RegistrationError is a refused registration: Code is the RFC 7591
// error ("invalid_redirect_uri", "invalid_client_metadata").
type RegistrationError struct {
	Code        string
	Description string
}

func (e *RegistrationError) Error() string { return "authserver: " + e.Code + ": " + e.Description }

// ErrRegistrationCapped is returned when the unused-client cap is reached.
var ErrRegistrationCapped = errors.New("authserver: too many unused client registrations")

// Register validates and stores a client registration. It does not rate
// limit; ServeRegister does.
func (s *Service) Register(ctx context.Context, req RegistrationRequest) (*RegistrationResponse, error) {
	meta, resp, err := validateRegistration(req)
	if err != nil {
		return nil, err
	}
	var secret string
	var secretHash []byte
	if meta.TokenEndpointAuthMethod != AuthMethodNone {
		secret, err = randomToken(32)
		if err != nil {
			return nil, fmt.Errorf("authserver: client secret: %w", err)
		}
		secretHash = hashSecret(secret)
	}
	id, err := randomToken(16)
	if err != nil {
		return nil, fmt.Errorf("authserver: client id: %w", err)
	}
	metaDoc, err := json.Marshal(meta)
	if err != nil {
		return nil, err
	}
	row := &store.OAuthClient{ClientID: ClientIDPrefix + id, ClientSecretHash: secretHash, ClientName: resp.ClientName, RedirectURIs: resp.RedirectURIs, Metadata: metaDoc}
	err = s.st.Bypass(ctx, func(tx Tx) error {
		n, err := tx.CountUnusedClients(ctx)
		if err != nil {
			return err
		}
		if n >= int64(s.cfg.MaxUnusedClients) {
			return ErrRegistrationCapped
		}
		return tx.CreateClient(ctx, row)
	})
	if err != nil {
		return nil, err
	}
	resp.ClientID = row.ClientID
	resp.ClientIDIssuedAt = row.CreatedAt.Unix()
	if secret != "" {
		resp.ClientSecret = secret
		never := int64(0)
		resp.ClientSecretExpiresAt = &never
	}
	s.log.Info("oauth client registered", "event", "authserver.client_registered", "client_id", row.ClientID,
		"client_name", row.ClientName, "redirect_uris", len(row.RedirectURIs), "auth_method", meta.TokenEndpointAuthMethod)
	return resp, nil
}

// ServeRegister is POST /oauth/register: JSON in, 201 + JSON out; 400
// with an RFC 7591 error for bad metadata; 429 with Retry-After when the
// address is over its budget or the unused-client cap is reached.
func (s *Service) ServeRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "invalid_request", "POST only")
		return
	}
	ip := s.clientIP(r)
	if allowed, wait := s.limiter.Allow(ip); !allowed {
		w.Header().Set("Retry-After", strconv.Itoa(int(math.Ceil(wait.Seconds()))))
		writeError(w, http.StatusTooManyRequests, "too_many_requests", "too many client registrations from this address; retry later")
		return
	}
	s.limiter.Fail(ip) // every attempt, valid or not, spends the budget
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, MaxRegisterBody))
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, "invalid_client_metadata", "registration document too large")
			return
		}
		writeError(w, http.StatusBadRequest, "invalid_client_metadata", "the body could not be read")
		return
	}
	var req RegistrationRequest
	if err := json.Unmarshal(body, &req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_client_metadata", "the body is not a JSON client metadata document")
		return
	}
	resp, err := s.Register(r.Context(), req)
	var regErr *RegistrationError
	switch {
	case errors.As(err, &regErr):
		writeError(w, http.StatusBadRequest, regErr.Code, regErr.Description)
		return
	case errors.Is(err, ErrRegistrationCapped):
		w.Header().Set("Retry-After", "3600")
		writeError(w, http.StatusTooManyRequests, "too_many_requests", "too many unused client registrations; retry later")
		return
	case err != nil:
		s.log.Error("client registration failed", "event", "authserver.register_failed", "error", observability.RedactError(err),
			"request_id", observability.RequestIDFromContext(r.Context()))
		writeError(w, http.StatusServiceUnavailable, "server_error", "registration is temporarily unavailable")
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

// validateRegistration applies the registration policy and returns what
// will be stored and what will be answered.
func validateRegistration(req RegistrationRequest) (clientMetadata, *RegistrationResponse, error) {
	bad := func(code, format string, args ...any) (clientMetadata, *RegistrationResponse, error) {
		return clientMetadata{}, nil, &RegistrationError{Code: code, Description: fmt.Sprintf(format, args...)}
	}
	switch {
	case len(req.RedirectURIs) == 0:
		return bad("invalid_redirect_uri", "redirect_uris is required")
	case len(req.RedirectURIs) > MaxRedirectURIs:
		return bad("invalid_redirect_uri", "at most %d redirect_uris", MaxRedirectURIs)
	}
	uris := make([]string, 0, len(req.RedirectURIs))
	for _, raw := range req.RedirectURIs {
		if err := ValidateRedirectURI(raw); err != nil {
			return bad("invalid_redirect_uri", "%s: %v", raw, err)
		}
		if !slices.Contains(uris, raw) {
			uris = append(uris, raw)
		}
	}
	method := req.TokenEndpointAuthMethod
	if method == "" {
		method = AuthMethodNone
	}
	if !slices.Contains(authMethodsSupported, method) {
		return bad("invalid_client_metadata", "token_endpoint_auth_method %q is not supported", method)
	}
	grants := req.GrantTypes
	if len(grants) == 0 {
		grants = []string{GrantAuthorizationCode, GrantRefreshToken}
	}
	for _, g := range grants {
		if !slices.Contains(grantTypesSupported, g) {
			return bad("invalid_client_metadata", "grant_type %q is not supported", g)
		}
	}
	if !slices.Contains(grants, GrantAuthorizationCode) {
		return bad("invalid_client_metadata", "grant_types must include authorization_code")
	}
	responses := req.ResponseTypes
	if len(responses) == 0 {
		responses = []string{ResponseTypeCode}
	}
	for _, rt := range responses {
		if rt != ResponseTypeCode {
			return bad("invalid_client_metadata", "response_type %q is not supported", rt)
		}
	}
	// A registered scope restricts what the client may ask for; none
	// means any supported scope. The answer lists what it may use.
	scope, ok := ParseScope(req.Scope)
	if !ok {
		return bad("invalid_client_metadata", "scope %q is not supported", req.Scope)
	}
	if strings.TrimSpace(req.Scope) == "" {
		scope = ""
	}
	answerScope := scope
	if answerScope == "" {
		answerScope = strings.Join(ScopesSupported, " ")
	}
	name := strings.TrimSpace(req.ClientName)
	switch {
	case name == "":
		name = DefaultClientName
	case len(name) > MaxClientNameLen:
		return bad("invalid_client_metadata", "client_name must be at most %d characters", MaxClientNameLen)
	case strings.ContainsAny(name, "\x00\n\r"):
		return bad("invalid_client_metadata", "client_name contains control characters")
	}
	for field, v := range map[string]string{"client_uri": req.ClientURI, "logo_uri": req.LogoURI} {
		if v == "" {
			continue
		}
		u, err := url.Parse(v)
		if err != nil || u.Scheme != "https" || u.Host == "" || len(v) > MaxRedirectURILen {
			return bad("invalid_client_metadata", "%s must be an https URL", field)
		}
	}
	meta := clientMetadata{
		TokenEndpointAuthMethod: method, GrantTypes: slices.Clone(grants), ResponseTypes: slices.Clone(responses), Scope: scope,
		ClientURI: req.ClientURI, LogoURI: req.LogoURI, SoftwareID: trim(req.SoftwareID, 100), SoftwareVersion: trim(req.SoftwareVersion, 100),
	}
	resp := &RegistrationResponse{
		ClientName: name, RedirectURIs: uris, TokenEndpointAuthMethod: method, GrantTypes: meta.GrantTypes,
		ResponseTypes: meta.ResponseTypes, Scope: answerScope, ClientURI: req.ClientURI, LogoURI: req.LogoURI,
	}
	return meta, resp, nil
}

// ValidateRedirectURI accepts an absolute https URL, or an http URL whose
// host is the loopback interface (localhost, 127.0.0.1, [::1]) on any
// port, as the MCP authorization spec requires; never a fragment, never
// another scheme.
func ValidateRedirectURI(raw string) error {
	if raw == "" || len(raw) > MaxRedirectURILen {
		return errors.New("must be a non-empty URL of at most 2048 characters")
	}
	if strings.ContainsAny(raw, " \t\r\n\x00") {
		return errors.New("contains whitespace or control characters")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return errors.New("is not a valid URL")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return errors.New("must not contain a fragment")
	}
	if u.Host == "" || u.Hostname() == "" {
		return errors.New("must be an absolute URL with a host")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		return errors.New("http is only allowed for localhost / 127.0.0.1 / [::1]")
	default:
		return errors.New("scheme must be https (or http on the loopback interface)")
	}
}

// isLoopbackHost reports whether host is the loopback interface by name
// or address.
func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func trim(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}
