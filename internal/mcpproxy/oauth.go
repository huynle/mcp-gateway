package mcpproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
)

// OAuth constants of the gateway's authorization server
// (internal/authserver, docs/harness-setup.md).
const (
	grantDeviceCode   = "urn:ietf:params:oauth:grant-type:device_code"
	grantRefreshToken = "refresh_token"

	protectedResourcePath = "/.well-known/oauth-protected-resource"
	asMetadataPath        = "/.well-known/oauth-authorization-server"

	authRequestTimeout = 30 * time.Second
	maxAuthBody        = 1 << 20
	maxDescription     = 200
)

// endpoints are what discovery found: the MCP endpoint (the protected
// resource) and the authorization server's endpoints.
type endpoints struct {
	resource string
	issuer   string
	register string
	device   string
	token    string
}

// oauthError is an OAuth error answer (RFC 6749 section 5.2).
type oauthError struct {
	Status      int
	Code        string
	Description string
}

func (e *oauthError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("%s (%s)", e.Code, e.Description)
	}
	if e.Code != "" {
		return e.Code
	}
	return fmt.Sprintf("HTTP %d", e.Status)
}

func isOAuthError(err error, code string) bool {
	var oe *oauthError
	return errors.As(err, &oe) && oe.Code == code
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token"`
	Scope        string `json:"scope"`
}

type deviceAuthorization struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int64  `json:"expires_in"`
	Interval                int64  `json:"interval"`
}

// oauthClient talks to the authorization server. It never logs or
// returns bodies: they carry codes and tokens.
type oauthClient struct {
	gateway   string
	userAgent string
	http      *http.Client
}

// discover follows the MCP authorization discovery: the protected
// resource metadata (path-aware location first), then the authorization
// server metadata. Every endpoint must be on the gateway's origin: tokens
// and codes never travel elsewhere.
func (c *oauthClient) discover(ctx context.Context) (*endpoints, error) {
	var prm struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	err := c.getJSON(ctx, c.gateway+protectedResourcePath+"/mcp", &prm)
	if err != nil {
		if err = c.getJSON(ctx, c.gateway+protectedResourcePath, &prm); err != nil {
			return nil, fmt.Errorf("discover the gateway's protected resource metadata: %w", err)
		}
	}
	if prm.Resource == "" || len(prm.AuthorizationServers) == 0 {
		return nil, errors.New("the gateway's protected resource metadata names no resource or authorization server")
	}
	issuer := strings.TrimSuffix(prm.AuthorizationServers[0], "/")
	for _, u := range []string{prm.Resource, issuer} {
		if err := c.sameOrigin(u); err != nil {
			return nil, err
		}
	}
	iu, _ := url.Parse(issuer)
	// RFC 8414 section 3.1: the well-known suffix goes before the path.
	asURL := iu.Scheme + "://" + iu.Host + asMetadataPath + strings.TrimSuffix(iu.Path, "/")
	var asm struct {
		Issuer                      string `json:"issuer"`
		TokenEndpoint               string `json:"token_endpoint"`
		RegistrationEndpoint        string `json:"registration_endpoint"`
		DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	}
	if err := c.getJSON(ctx, asURL, &asm); err != nil {
		return nil, fmt.Errorf("discover the authorization server metadata: %w", err)
	}
	if strings.TrimSuffix(asm.Issuer, "/") != issuer {
		return nil, fmt.Errorf("the authorization server metadata names issuer %q, not %q", clean(asm.Issuer), clean(issuer))
	}
	switch {
	case asm.DeviceAuthorizationEndpoint == "":
		return nil, errors.New("the gateway does not offer the device flow (no device_authorization_endpoint); upgrade the gateway")
	case asm.RegistrationEndpoint == "":
		return nil, errors.New("the gateway does not offer dynamic client registration")
	case asm.TokenEndpoint == "":
		return nil, errors.New("the gateway's metadata has no token_endpoint")
	}
	for _, u := range []string{asm.TokenEndpoint, asm.RegistrationEndpoint, asm.DeviceAuthorizationEndpoint} {
		if err := c.sameOrigin(u); err != nil {
			return nil, err
		}
	}
	return &endpoints{
		resource: prm.Resource, issuer: issuer, register: asm.RegistrationEndpoint,
		device: asm.DeviceAuthorizationEndpoint, token: asm.TokenEndpoint,
	}, nil
}

// sameOrigin refuses a URL that is not on the gateway's scheme and host.
func (c *oauthClient) sameOrigin(raw string) error {
	u, err := url.Parse(raw)
	g, _ := url.Parse(c.gateway)
	if err != nil || u.Scheme != g.Scheme || !strings.EqualFold(u.Host, g.Host) || u.User != nil {
		return fmt.Errorf("the gateway's metadata points to %q, which is not on the gateway's origin %s; refusing to send credentials there", clean(raw), c.gateway)
	}
	return nil
}

// register registers the proxy as a public device-flow client.
func (c *oauthClient) register(ctx context.Context, ep *endpoints, name, version string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"client_name":                name,
		"grant_types":                []string{grantDeviceCode, grantRefreshToken},
		"token_endpoint_auth_method": "none",
		"software_id":                "mcp-gateway-proxy",
		"software_version":           version,
	})
	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := c.do(ctx, ep.register, "application/json", body, &out); err != nil {
		return "", fmt.Errorf("register with the gateway: %w", err)
	}
	if out.ClientID == "" {
		return "", errors.New("register with the gateway: no client_id in the answer")
	}
	return out.ClientID, nil
}

func (c *oauthClient) authorizeDevice(ctx context.Context, ep *endpoints, clientID, scope string) (*deviceAuthorization, error) {
	form := url.Values{"client_id": {clientID}, "scope": {scope}, "resource": {ep.resource}}
	var da deviceAuthorization
	if err := c.do(ctx, ep.device, "application/x-www-form-urlencoded", []byte(form.Encode()), &da); err != nil {
		return nil, err
	}
	if da.DeviceCode == "" || da.UserCode == "" || da.VerificationURI == "" {
		return nil, errors.New("the gateway's device authorization answer is incomplete")
	}
	return &da, nil
}

func (c *oauthClient) token(ctx context.Context, ep *endpoints, form url.Values) (*tokenResponse, error) {
	var tr tokenResponse
	if err := c.do(ctx, ep.token, "application/x-www-form-urlencoded", []byte(form.Encode()), &tr); err != nil {
		return nil, err
	}
	if tr.AccessToken == "" || !strings.EqualFold(tr.TokenType, "bearer") {
		return nil, errors.New("the gateway's token answer has no bearer access token")
	}
	return &tr, nil
}

func (c *oauthClient) getJSON(ctx context.Context, u string, v any) error {
	return c.send(ctx, http.MethodGet, u, "", nil, v)
}

func (c *oauthClient) do(ctx context.Context, u, contentType string, body []byte, v any) error {
	return c.send(ctx, http.MethodPost, u, contentType, body, v)
}

// send makes one request; a non-2xx answer is an *oauthError.
func (c *oauthClient) send(ctx context.Context, method, u, contentType string, body []byte, v any) error {
	ctx, cancel := context.WithTimeout(ctx, authRequestTimeout)
	defer cancel()
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, u, rd)
	if err != nil {
		return err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", c.userAgent)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAuthBody))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		oe := &oauthError{Status: resp.StatusCode}
		var e struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		if json.Unmarshal(data, &e) == nil {
			oe.Code, oe.Description = clean(e.Error), trimRunes(clean(e.Description), maxDescription)
		}
		return oe
	}
	if err := json.Unmarshal(data, v); err != nil {
		return fmt.Errorf("%s: the answer is not JSON", req.URL.Path)
	}
	return nil
}

// clean drops control characters from a server-provided string before it
// reaches the user's terminal.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
}

func trimRunes(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}
