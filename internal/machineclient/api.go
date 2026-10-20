package machineclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"
)

// Grant types of POST /machine/token.
const (
	grantDeviceCode = "urn:ietf:params:oauth:grant-type:device_code"
	grantJWTBearer  = "urn:ietf:params:oauth:grant-type:jwt-bearer"
)

// Bounds.
const (
	maxResponseBody   = 1 << 20
	maxErrDescription = 200
	assertionLifetime = 60 * time.Second // the gateway accepts up to 300 s
	refreshMargin     = 60 * time.Second // refresh this long before expiry (at most half the lifetime)
	requestTimeout    = 30 * time.Second
)

var (
	// ErrRevoked: the gateway says this machine is revoked (403 revoked).
	ErrRevoked = errors.New("this machine was revoked on the gateway; run `mcp-gateway login` to enroll it again")
	// ErrMachineRejected: the token endpoint refused the machine's
	// assertion (revoked or unknown machine, inactive owner, clock skew).
	ErrMachineRejected = errors.New("the gateway rejected this machine's credentials (revoked, unknown, the owner is not active, or the clock is off); run `mcp-gateway login` again")
)

// Client talks to the gateway's machine endpoints. It never logs or
// returns request or response bodies: they carry codes, keys and tokens.
type Client struct {
	// Gateway is the base URL without a trailing slash.
	Gateway string
	// Version is sent as client_version.
	Version string
	HTTP    *http.Client
	// Log gets one debug line per request (method, path, status); nil: none.
	Log *slog.Logger
}

// NewClient returns a client that never follows redirects (a token must
// not travel to another URL) and times out requests after 30 s.
func NewClient(gateway, version string, log *slog.Logger) *Client {
	return &Client{
		Gateway: gateway, Version: version, Log: log,
		HTTP: &http.Client{
			Timeout:       requestTimeout,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
	}
}

// APIError is an error response of the gateway. Code and Description come
// from the gateway's JSON error (the description is bounded and stripped
// of control characters).
type APIError struct {
	Status      int
	Code        string
	Description string
}

func (e *APIError) Error() string {
	switch {
	case e.Code == "":
		return fmt.Sprintf("the gateway answered HTTP %d", e.Status)
	case e.Description == "":
		return "the gateway answered " + e.Code
	default:
		return fmt.Sprintf("the gateway answered %s: %s", e.Code, e.Description)
	}
}

// DeviceAuth is the device authorization response (RFC 8628 3.2).
type DeviceAuth struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// Enrollment is the gateway's answer to an approved device flow or an
// enrollment code.
type Enrollment struct {
	MachineID string `json:"machine_id"`
	Name      string `json:"name"`
	Gateway   string `json:"gateway"`
}

// DeviceAuthorization starts the device flow for a new machine key.
func (c *Client) DeviceAuthorization(ctx context.Context, name string, pub JWK) (*DeviceAuth, error) {
	var out DeviceAuth
	body := map[string]any{"name": name, "public_key": pub, "client_version": c.Version}
	if err := c.doJSON(ctx, http.MethodPost, "/machine/device_authorization", "", body, &out); err != nil {
		return nil, err
	}
	if out.DeviceCode == "" || out.UserCode == "" || out.VerificationURI == "" {
		return nil, errors.New("the gateway's device authorization response is incomplete")
	}
	return &out, nil
}

// PollDeviceToken polls once; pending, slow_down, denied and expired come
// back as *APIError with the RFC 8628 code.
func (c *Client) PollDeviceToken(ctx context.Context, deviceCode string) (*Enrollment, error) {
	var out Enrollment
	form := url.Values{"grant_type": {grantDeviceCode}, "device_code": {deviceCode}}
	if err := c.doForm(ctx, "/machine/token", form, &out); err != nil {
		return nil, err
	}
	return checkEnrollment(&out)
}

// Enroll enrolls a machine key with a one-time enrollment code.
func (c *Client) Enroll(ctx context.Context, code, name string, pub JWK) (*Enrollment, error) {
	var out Enrollment
	body := map[string]any{"code": code, "name": name, "public_key": pub, "client_version": c.Version}
	if err := c.doJSON(ctx, http.MethodPost, "/machine/enroll", "", body, &out); err != nil {
		return nil, err
	}
	return checkEnrollment(&out)
}

func checkEnrollment(e *Enrollment) (*Enrollment, error) {
	if !uuidRE.MatchString(e.MachineID) || ValidateMachineName(e.Name) != nil {
		return nil, errors.New("the gateway's enrollment response is malformed")
	}
	return e, nil
}

type accessToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

func (c *Client) exchangeAssertion(ctx context.Context, assertion string) (*accessToken, error) {
	var out accessToken
	form := url.Values{"grant_type": {grantJWTBearer}, "assertion": {assertion}}
	if err := c.doForm(ctx, "/machine/token", form, &out); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(out.AccessToken, "mgm_") || !strings.EqualFold(out.TokenType, "Bearer") || out.ExpiresIn <= 0 {
		return nil, errors.New("the gateway's token response is malformed")
	}
	return &out, nil
}

func (c *Client) doForm(ctx context.Context, path string, form url.Values, out any) error {
	return c.do(ctx, http.MethodPost, path, "", "application/x-www-form-urlencoded", []byte(form.Encode()), out)
}

func (c *Client) doJSON(ctx context.Context, method, path, token string, in, out any) error {
	var body []byte
	ct := ""
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
		ct = "application/json"
	}
	return c.do(ctx, method, path, token, ct, body, out)
}

func (c *Client) do(ctx context.Context, method, path, token, contentType string, body []byte, out any) error {
	var rd io.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.Gateway+path, rd)
	if err != nil {
		return fmt.Errorf("build request %s: %w", path, err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "mcp-gateway/"+c.Version)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err // the URL is ours, the error text is the cause
		}
		return fmt.Errorf("%s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	if c.Log != nil {
		c.Log.Debug("gateway request", "method", method, "path", path, "status", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return fmt.Errorf("%s %s: read response: %w", method, path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return parseAPIError(resp.StatusCode, data)
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%s %s: the gateway's response is not valid JSON", method, path)
	}
	return nil
}

func parseAPIError(status int, data []byte) *APIError {
	e := &APIError{Status: status}
	var body struct {
		Error       string `json:"error"`
		Description string `json:"error_description"`
	}
	if json.Unmarshal(data, &body) == nil {
		e.Code = clean(body.Error, 64)
		e.Description = clean(body.Description, maxErrDescription)
	}
	return e
}

// clean bounds a server-provided string and drops control characters.
func clean(s string, n int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return -1
		}
		return r
	}, s)
	if r := []rune(s); len(r) > n {
		s = string(r[:n]) + "…"
	}
	return s
}

// MintAssertion signs the client assertion of RFC 7523 with the machine
// key: EdDSA, iss = sub = machine id, aud = the token endpoint, a 60 s
// lifetime and a random jti.
func MintAssertion(key ed25519.PrivateKey, machineID, audience string, now time.Time) (string, error) {
	jti := make([]byte, 18)
	if _, err := rand.Read(jti); err != nil {
		return "", err
	}
	claims, err := json.Marshal(map[string]any{
		"iss": machineID, "sub": machineID, "aud": audience,
		"iat": now.Unix(), "exp": now.Add(assertionLifetime).Unix(),
		"jti": base64.RawURLEncoding.EncodeToString(jti),
	})
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT"}`)) + "." + enc.EncodeToString(claims)
	return signing + "." + enc.EncodeToString(ed25519.Sign(key, []byte(signing))), nil
}

// Tokens supplies machine access tokens.
type Tokens interface {
	// Token returns a valid access token.
	Token(ctx context.Context) (string, error)
	// Invalidate drops tok if it is the cached token (the gateway refused it).
	Invalidate(tok string)
}

// TokenSource mints assertions and caches the access token, refreshing it
// shortly before it expires (a minute, at most half its lifetime).
// Safe for concurrent use; concurrent callers share one exchange.
type TokenSource struct {
	Client    *Client
	MachineID string
	Key       ed25519.PrivateKey
	// Now is the clock (nil: time.Now).
	Now func() time.Time

	mu      sync.Mutex
	token   string
	refresh time.Time // when to get a new token
}

func (ts *TokenSource) now() time.Time {
	if ts.Now != nil {
		return ts.Now()
	}
	return time.Now()
}

// Token implements Tokens.
func (ts *TokenSource) Token(ctx context.Context) (string, error) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	now := ts.now()
	if ts.token != "" && now.Before(ts.refresh) {
		return ts.token, nil
	}
	a, err := MintAssertion(ts.Key, ts.MachineID, ts.Client.Gateway+"/machine/token", now)
	if err != nil {
		return "", fmt.Errorf("sign the machine assertion: %w", err)
	}
	at, err := ts.Client.exchangeAssertion(ctx, a)
	var ae *APIError
	switch {
	case errors.As(err, &ae) && ae.Code == "invalid_grant":
		return "", ErrMachineRejected
	case err != nil:
		return "", fmt.Errorf("get a machine access token: %w", err)
	}
	ttl := time.Duration(at.ExpiresIn) * time.Second
	ts.token, ts.refresh = at.AccessToken, now.Add(ttl-min(refreshMargin, ttl/2))
	return ts.token, nil
}

// Invalidate implements Tokens.
func (ts *TokenSource) Invalidate(tok string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if tok == ts.token {
		ts.token = ""
	}
}

// MachineAPI is the machine-token API (/machine/v1/*).
type MachineAPI struct {
	Client *Client
	Tokens Tokens
}

// SelfServer is one server of GET /machine/v1/self.
type SelfServer struct {
	Name          string `json:"name"`
	ServerID      string `json:"server_id"`
	TunnelID      string `json:"tunnel_id"`
	Status        string `json:"status"`
	ApprovedTools int    `json:"approved_tools"`
	ReviewURL     string `json:"review_url"`
}

// Self is GET /machine/v1/self.
type Self struct {
	MachineID string       `json:"machine_id"`
	Name      string       `json:"name"`
	Owner     string       `json:"owner"`
	Servers   []SelfServer `json:"servers"`
}

// PutResult is PUT /machine/v1/servers/{name}.
type PutResult struct {
	Name      string `json:"name"`
	ServerID  string `json:"server_id"`
	TunnelID  string `json:"tunnel_id"`
	Created   bool   `json:"created"`
	ReviewURL string `json:"review_url"`
}

// RefreshResult is POST /machine/v1/servers/{name}/refresh.
type RefreshResult struct {
	Version   int    `json:"version"`
	Added     int    `json:"added"`
	Changed   int    `json:"changed"`
	Removed   int    `json:"removed"`
	ReviewURL string `json:"review_url"`
}

// Self returns the machine and its servers.
func (m *MachineAPI) Self(ctx context.Context) (*Self, error) {
	var out Self
	if err := m.call(ctx, http.MethodGet, "/machine/v1/self", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// PutServer ensures the server (and its tunnel) exist; idempotent.
func (m *MachineAPI) PutServer(ctx context.Context, name, kind string) (*PutResult, error) {
	var out PutResult
	body := map[string]string{"kind": kind, "path": ""}
	if err := m.call(ctx, http.MethodPut, "/machine/v1/servers/"+url.PathEscape(name), body, &out); err != nil {
		return nil, err
	}
	if out.TunnelID == "" {
		return nil, fmt.Errorf("server %q: the gateway's response has no tunnel id", name)
	}
	return &out, nil
}

// RefreshServer snapshots the server's tools through the live connection.
func (m *MachineAPI) RefreshServer(ctx context.Context, name string) (*RefreshResult, error) {
	var out RefreshResult
	if err := m.call(ctx, http.MethodPost, "/machine/v1/servers/"+url.PathEscape(name)+"/refresh", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Logout revokes this machine on the gateway.
func (m *MachineAPI) Logout(ctx context.Context) error {
	return m.call(ctx, http.MethodPost, "/machine/v1/logout", nil, nil)
}

// call does an authenticated request; one invalid_token is retried with a
// fresh token (the cached one expired or was dropped by the gateway).
func (m *MachineAPI) call(ctx context.Context, method, path string, in, out any) error {
	for attempt := 0; ; attempt++ {
		tok, err := m.Tokens.Token(ctx)
		if err != nil {
			return err
		}
		err = m.Client.doJSON(ctx, method, path, tok, in, out)
		var ae *APIError
		switch {
		case errors.As(err, &ae) && ae.Status == http.StatusForbidden && ae.Code == "revoked":
			return ErrRevoked
		case errors.As(err, &ae) && ae.Status == http.StatusUnauthorized && attempt == 0:
			m.Tokens.Invalidate(tok)
			continue
		}
		return err
	}
}
