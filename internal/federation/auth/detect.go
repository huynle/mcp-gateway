package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/federation/client"
	"github.com/huynle/mcp-gateway/internal/netguard"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
)

// Bounds for discovery requests.
const (
	maxMetadataBytes = 256 << 10
	metadataTimeout  = 15 * time.Second
)

// ErrInvalidServerURL means the server URL is not an absolute http(s) URL.
var ErrInvalidServerURL = errors.New("auth: invalid server URL")

// DiscoveryOptions configure a Discoverer.
type DiscoveryOptions struct {
	// HTTPClient is netguard's client (required). Every discovery request,
	// including the unauthenticated MCP initialize, goes through it.
	HTTPClient *http.Client
	// Log receives hosts and reasons only; default: discard.
	Log *slog.Logger
}

// Discoverer detects how an MCP server wants to be authenticated.
type Discoverer struct {
	http *http.Client
	mcp  *client.Client
	log  *slog.Logger
}

// NewDiscoverer builds a Discoverer over the guard's HTTP client.
func NewDiscoverer(o DiscoveryOptions) (*Discoverer, error) {
	if o.HTTPClient == nil {
		return nil, errors.New("auth: DiscoveryOptions.HTTPClient is required (netguard's client)")
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	mc, err := client.New(client.Options{HTTPClient: o.HTTPClient, Authorizer: client.NoAuth{}, Log: o.Log})
	if err != nil {
		return nil, err
	}
	return &Discoverer{http: o.HTTPClient, mcp: mc, log: o.Log}, nil
}

// ProtectedResourceMetadata is an RFC 9728 OAuth protected resource
// metadata document (the fields the gateway uses).
type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers,omitempty"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
	ResourceName           string   `json:"resource_name,omitempty"`
}

// AuthServerMetadata is an RFC 8414 (or OpenID Connect discovery)
// authorization server metadata document (the fields the gateway uses).
type AuthServerMetadata struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	RegistrationEndpoint                       string   `json:"registration_endpoint,omitempty"`
	RevocationEndpoint                         string   `json:"revocation_endpoint,omitempty"`
	ScopesSupported                            []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported                     []string `json:"response_types_supported,omitempty"`
	GrantTypesSupported                        []string `json:"grant_types_supported,omitempty"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported,omitempty"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	ClientIDMetadataDocumentSupported          bool     `json:"client_id_metadata_document_supported,omitempty"`
	AuthorizationResponseIssParameterSupported bool     `json:"authorization_response_iss_parameter_supported,omitempty"`
}

// SupportsS256 reports whether the AS advertises PKCE S256. OAuth 2.1 and
// the MCP authorization spec require clients to refuse when it does not.
func (m *AuthServerMetadata) SupportsS256() bool {
	return m != nil && slices.Contains(m.CodeChallengeMethodsSupported, "S256")
}

// DetectResult is what Detect learned about a server.
type DetectResult struct {
	// AuthKinds are the store.MCPAuth* kinds the server can be used with,
	// most preferred first: [none] for a server that answered initialize
	// without credentials; oauth first when OAuth metadata was found;
	// otherwise api_key, bearer and headers for the owner to choose from.
	AuthKinds []string
	// ResourceMetadata is the validated RFC 9728 document (nil if none) and
	// ResourceMetadataURL where it was found.
	ResourceMetadata    *ProtectedResourceMetadata
	ResourceMetadataURL string
	// AuthServerMetadata is the validated RFC 8414 / OIDC document (nil if
	// none).
	AuthServerMetadata *AuthServerMetadata
	// Resource is the RFC 8707 resource indicator to request tokens for:
	// the protected resource's own identifier when it published a valid
	// one, else the server URL's canonical form.
	Resource     string
	SupportsDCR  bool
	SupportsCIMD bool
	SupportsS256 bool
	// OfflineAccess reports that the AS advertises the offline_access scope.
	OfflineAccess bool
	// Scopes to request: the challenge's scope, else scopes_supported of
	// the protected resource.
	Scopes []string
	// Blocked lists discovery destinations netguard refused ("host:
	// reason"), for the owner to see why OAuth was not detected.
	Blocked []string
}

// Detect works out how serverURL wants to be authenticated: an
// unauthenticated MCP initialize through the federation client; a 401/403
// starts OAuth discovery (the challenge's resource_metadata, then the RFC
// 9728 path-aware and root well-known URLs, then RFC 8414 and OIDC
// discovery for the advertised authorization server, or the server's
// origin when there is no resource metadata). A server that answers
// initialize without credentials needs none. Failures other than an
// authentication challenge are returned (a *client.Error).
func (d *Discoverer) Detect(ctx context.Context, serverURL string) (*DetectResult, error) {
	u, err := parseServerURL(serverURL)
	if err != nil {
		return nil, err
	}
	sess, err := d.mcp.Connect(ctx, client.Endpoint{URL: serverURL})
	if err == nil {
		_ = sess.Close()
		return &DetectResult{AuthKinds: []string{store.MCPAuthNone}, Resource: CanonicalResource(u)}, nil
	}
	var ce *client.Error
	if !errors.As(err, &ce) || (ce.Class != client.ClassAuthRequired && ce.Class != client.ClassForbidden) {
		return nil, err
	}
	ch := parseChallenges(ce.WWWAuthenticate)
	res := &DetectResult{Resource: CanonicalResource(u)}
	prm, prmURL := d.findResourceMetadata(ctx, u, ch.param("resource_metadata"), res)
	issuers := []string{originOf(u)} // legacy (2025-03-26): the server's origin is the AS
	if prm != nil {
		res.ResourceMetadata, res.ResourceMetadataURL = prm, prmURL
		res.Resource = CanonicalResourceString(prm.Resource)
		issuers = prm.AuthorizationServers
	}
	for _, iss := range issuers {
		if asm := d.findAuthServerMetadata(ctx, iss, res); asm != nil {
			res.AuthServerMetadata = asm
			break
		}
	}
	if scope := ch.param("scope"); scope != "" {
		res.Scopes = strings.Fields(scope)
	} else if prm != nil {
		res.Scopes = slices.Clone(prm.ScopesSupported)
	}
	if asm := res.AuthServerMetadata; asm != nil {
		res.AuthKinds = []string{store.MCPAuthOAuth, store.MCPAuthAPIKey, store.MCPAuthBearer, store.MCPAuthHeaders}
		res.SupportsDCR = asm.RegistrationEndpoint != ""
		res.SupportsCIMD = asm.ClientIDMetadataDocumentSupported
		res.SupportsS256 = asm.SupportsS256()
		res.OfflineAccess = slices.Contains(asm.ScopesSupported, "offline_access")
	} else {
		res.AuthKinds = []string{store.MCPAuthAPIKey, store.MCPAuthBearer, store.MCPAuthHeaders}
	}
	d.log.Info("auth detected", "event", "federation.auth_detected", "host", u.Hostname(),
		"kinds", strings.Join(res.AuthKinds, ","), "dcr", res.SupportsDCR, "cimd", res.SupportsCIMD, "blocked", len(res.Blocked))
	return res, nil
}

// findResourceMetadata tries the challenge's resource_metadata URL, the
// RFC 9728 path-aware URL, then the root URL, and returns the first
// document that names authorization servers and whose resource identifies
// the server.
func (d *Discoverer) findResourceMetadata(ctx context.Context, server *url.URL, fromChallenge string, res *DetectResult) (*ProtectedResourceMetadata, string) {
	var candidates []string
	if fromChallenge != "" {
		if cu, err := url.Parse(fromChallenge); err == nil && (cu.Scheme == "https" || cu.Scheme == "http") && cu.Host != "" {
			candidates = append(candidates, cu.String())
		}
	}
	origin := originOf(server)
	if p := strings.TrimSuffix(server.EscapedPath(), "/"); p != "" {
		candidates = append(candidates, origin+"/.well-known/oauth-protected-resource"+p)
	}
	candidates = append(candidates, origin+"/.well-known/oauth-protected-resource")
	for _, c := range uniq(candidates) {
		var prm ProtectedResourceMetadata
		if !d.getJSON(ctx, c, &prm, res) {
			continue
		}
		if len(prm.AuthorizationServers) == 0 || !resourceMatches(prm.Resource, server) {
			d.log.Warn("protected resource metadata rejected", "event", "federation.auth_prm_rejected", "host", server.Hostname())
			continue
		}
		return &prm, c
	}
	return nil, ""
}

// findAuthServerMetadata fetches issuer's metadata: RFC 8414 (path
// inserted after the well-known prefix), then OpenID Connect discovery
// (path inserted, then appended). The document's issuer must equal the
// issuer it was fetched for (RFC 8414 section 3.3) and it must name the
// authorization and token endpoints.
func (d *Discoverer) findAuthServerMetadata(ctx context.Context, issuer string, res *DetectResult) *AuthServerMetadata {
	iu, err := url.Parse(issuer)
	if err != nil || (iu.Scheme != "https" && iu.Scheme != "http") || iu.Host == "" || iu.RawQuery != "" || iu.Fragment != "" {
		return nil
	}
	origin := originOf(iu)
	p := strings.TrimSuffix(iu.EscapedPath(), "/")
	candidates := []string{
		origin + "/.well-known/oauth-authorization-server" + p,
		origin + "/.well-known/openid-configuration" + p,
	}
	if p != "" {
		candidates = append(candidates, origin+p+"/.well-known/openid-configuration")
	}
	for _, c := range candidates {
		var m AuthServerMetadata
		if !d.getJSON(ctx, c, &m, res) {
			continue
		}
		if strings.TrimSuffix(m.Issuer, "/") != strings.TrimSuffix(issuer, "/") ||
			!absHTTPURL(m.AuthorizationEndpoint) || !absHTTPURL(m.TokenEndpoint) ||
			(m.RegistrationEndpoint != "" && !absHTTPURL(m.RegistrationEndpoint)) {
			d.log.Warn("authorization server metadata rejected", "event", "federation.auth_asm_rejected", "host", iu.Hostname())
			continue
		}
		return &m
	}
	return nil
}

// getJSON GETs u through the guard and decodes a 200 JSON answer into v.
// A netguard refusal is recorded in res.Blocked.
func (d *Discoverer) getJSON(ctx context.Context, u string, v any, res *DetectResult) bool {
	ctx, cancel := context.WithTimeout(ctx, metadataTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Accept", "application/json")
	resp, err := d.http.Do(req)
	if err != nil {
		var be *netguard.BlockedError
		if errors.As(err, &be) {
			res.Blocked = append(res.Blocked, fmt.Sprintf("%s: %s", be.Host, be.Reason))
		}
		d.log.Debug("metadata fetch failed", "event", "federation.auth_fetch_failed", "error", observability.RedactError(err))
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxMetadataBytes))
		return false
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxMetadataBytes+1))
	if err != nil || len(body) > maxMetadataBytes {
		return false
	}
	return json.Unmarshal(body, v) == nil
}

// --- URLs ---------------------------------------------------------------------------

func parseServerURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.User != nil {
		return nil, ErrInvalidServerURL
	}
	return u, nil
}

func absHTTPURL(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && (u.Scheme == "https" || u.Scheme == "http") && u.Host != "" && u.User == nil && u.Fragment == ""
}

// originOf returns scheme://host[:port] with the scheme and host lowercased
// and the default port dropped.
func originOf(u *url.URL) string {
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host
}

// CanonicalResource is the RFC 8707 / MCP canonical URI of a server: the
// origin lowercased without a default port, the path without a trailing
// slash, the query kept, no fragment.
func CanonicalResource(u *url.URL) string {
	out := originOf(u) + strings.TrimSuffix(u.EscapedPath(), "/")
	if u.RawQuery != "" {
		out += "?" + u.RawQuery
	}
	return out
}

// CanonicalResourceString is CanonicalResource for a raw URL (returned
// unchanged when it does not parse).
func CanonicalResourceString(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return raw
	}
	return CanonicalResource(u)
}

// resourceMatches reports whether a protected resource identifier names
// the server: same origin, and its path equal to or a segment-wise prefix
// of the server's path (servers such as Brain name their origin).
func resourceMatches(resource string, server *url.URL) bool {
	ru, err := url.Parse(resource)
	if err != nil || ru.Host == "" || ru.Fragment != "" || ru.RawQuery != "" {
		return false
	}
	if originOf(ru) != originOf(server) {
		return false
	}
	rp := strings.TrimSuffix(ru.EscapedPath(), "/")
	sp := strings.TrimSuffix(server.EscapedPath(), "/")
	return rp == "" || rp == sp || strings.HasPrefix(sp, rp+"/")
}

func uniq(in []string) []string {
	var out []string
	for _, s := range in {
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// --- WWW-Authenticate ---------------------------------------------------------------

// challenges are parsed WWW-Authenticate challenges (RFC 9110 section
// 11.6.1). Only the Bearer challenge's parameters are used; the value is
// upstream-controlled, so it is parsed defensively and never displayed.
type challenges map[string]map[string]string

func (c challenges) param(name string) string {
	return c["bearer"][name]
}

func parseChallenges(h string) challenges {
	out := challenges{}
	var scheme string
	s := h
	for len(s) > 0 {
		s = strings.TrimLeft(s, " \t,")
		if s == "" {
			break
		}
		tok, rest := readToken(s)
		if tok == "" {
			break // malformed: stop
		}
		rest = strings.TrimLeft(rest, " \t")
		if strings.HasPrefix(rest, "=") {
			// auth-param of the current challenge
			val, after := readValue(strings.TrimLeft(rest[1:], " \t"))
			if scheme != "" {
				out[scheme][strings.ToLower(tok)] = val
			}
			s = after
			continue
		}
		scheme = strings.ToLower(tok)
		if _, ok := out[scheme]; !ok {
			out[scheme] = map[string]string{}
		}
		s = rest
	}
	return out
}

func isTokenChar(c byte) bool {
	return c > 0x20 && c < 0x7f && !strings.ContainsRune("\"(),/:;<=>?@[\\]{} ", rune(c))
}

func readToken(s string) (string, string) {
	i := 0
	for i < len(s) && (isTokenChar(s[i]) || s[i] == '/') {
		i++
	}
	return s[:i], s[i:]
}

func readValue(s string) (string, string) {
	if !strings.HasPrefix(s, `"`) {
		i := 0
		for i < len(s) && s[i] != ',' && s[i] != ' ' && s[i] != '\t' {
			i++
		}
		return s[:i], s[i:]
	}
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if i+1 < len(s) {
				i++
				b.WriteByte(s[i])
			}
		case '"':
			return b.String(), s[i+1:]
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String(), ""
}
