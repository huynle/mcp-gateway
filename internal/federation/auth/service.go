package auth

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/huynle/mcp-gateway/internal/crypto"
)

// Errors the package reports. Messages are safe to show to the user; they
// never carry upstream text, URLs or secrets.
var (
	// ErrNotConnected means the user has no credential for the server yet.
	ErrNotConnected = errors.New("auth: not connected to this server")
	// ErrNeedsReconnect means the user's credential is dead (invalid_grant,
	// no refresh token, repeated 401): the user must connect again.
	ErrNeedsReconnect = errors.New("auth: connection needs to be reconnected")
	// ErrNotConfigured means the server's auth settings are incomplete
	// (auth kind auto, missing shared credential, unknown kind).
	ErrNotConfigured = errors.New("auth: server authentication is not configured")
	// ErrUnsupported means the combination is not supported (shared OAuth
	// tokens, OAuth for a server whose credential mode is shared).
	ErrUnsupported = errors.New("auth: unsupported authentication setup")
	// ErrNoOAuth means discovery found no usable authorization server.
	ErrNoOAuth = errors.New("auth: server does not advertise OAuth")
	// ErrPKCEUnsupported means the authorization server does not advertise
	// PKCE S256; the gateway refuses to run the flow without it.
	ErrPKCEUnsupported = errors.New("auth: authorization server does not support PKCE S256")
	// ErrNoClient means there is no way to obtain a client ID: no CIMD,
	// no registration endpoint and no static client.
	ErrNoClient = errors.New("auth: no OAuth client available (ask the server owner to set a static client)")
	// ErrFlowInvalid covers an unknown, expired, foreign, tampered or
	// replayed state, an issuer mismatch and a failed code exchange.
	ErrFlowInvalid = errors.New("auth: connect flow invalid")
	// ErrDenied means the authorization server sent back an error (the user
	// cancelled or consent was refused).
	ErrDenied = errors.New("auth: authorization was refused")
	// ErrSharedCredentialRejected means the upstream rejected the shared
	// credential; only the owner or an admin can fix it.
	ErrSharedCredentialRejected = errors.New("auth: the server rejected the shared credential")
	// ErrInvalidCredential means a credential to store is malformed.
	ErrInvalidCredential = errors.New("auth: invalid credential")
)

// Defaults.
const (
	DefaultStateTTL    = 10 * time.Minute
	DefaultRefreshSkew = time.Minute
	DefaultClientName  = "MCP Gateway"

	// CallbackPath is where the authorization server sends the user back.
	CallbackPath = "/servers/oauth/callback"
	// ClientMetadataPath is where the gateway publishes its OAuth client ID
	// metadata document (the CIMD client_id).
	ClientMetadataPath = "/.well-known/mcp-gateway-client.json"
)

// Options configure a Service.
type Options struct {
	// HTTPClient is netguard's client (required): discovery, registration,
	// token and refresh requests all go through it.
	HTTPClient *http.Client
	// Store persists credentials (required); NewPostgresStore in
	// production.
	Store Store
	// Keys seal credentials and connect-flow states (required).
	Keys crypto.KeyProvider
	// BaseURL is GATEWAY_BASE_URL (required): the redirect URI and the CIMD
	// client_id derive from it.
	BaseURL string
	// ClientName is shown by authorization servers (default "MCP Gateway").
	ClientName string
	// Log never receives secrets; default: discard.
	Log *slog.Logger
	// Clock defaults to time.Now.
	Clock func() time.Time
	// StateTTL bounds a connect flow (default 10 minutes).
	StateTTL time.Duration
	// RefreshSkew refreshes tokens this long before they expire (default 1
	// minute).
	RefreshSkew time.Duration
	// Replay makes connect-flow states one-use; default: in-memory
	// (per process).
	Replay ReplayGuard
	// Finish renders the end of the callback. Default: a short plain-text
	// page (success or a safe error message).
	Finish func(w http.ResponseWriter, r *http.Request, serverID string, err error)
}

// Service holds upstream credentials: OAuth connections per user, shared
// and per-user static credentials, and the Authorizers the federation
// client uses.
type Service struct {
	http   *http.Client
	store  Store
	keys   crypto.KeyProvider
	base   string
	name   string
	log    *slog.Logger
	clock  func() time.Time
	ttl    time.Duration
	skew   time.Duration
	replay ReplayGuard
	finish func(http.ResponseWriter, *http.Request, string, error)
	disc   *Discoverer
}

// New builds a Service.
func New(o Options) (*Service, error) {
	switch {
	case o.HTTPClient == nil:
		return nil, errors.New("auth: Options.HTTPClient is required (netguard's client)")
	case o.Store == nil:
		return nil, errors.New("auth: Options.Store is required")
	case o.Keys == nil:
		return nil, errors.New("auth: Options.Keys is required")
	}
	base := strings.TrimSuffix(o.BaseURL, "/")
	if u, err := url.Parse(base); err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
		return nil, fmt.Errorf("auth: Options.BaseURL %q is not an absolute URL", o.BaseURL)
	}
	s := &Service{
		http: o.HTTPClient, store: o.Store, keys: o.Keys, base: base, name: o.ClientName, log: o.Log,
		clock: o.Clock, ttl: o.StateTTL, skew: o.RefreshSkew, replay: o.Replay, finish: o.Finish,
	}
	if s.name == "" {
		s.name = DefaultClientName
	}
	if s.log == nil {
		s.log = slog.New(slog.DiscardHandler)
	}
	if s.clock == nil {
		s.clock = time.Now
	}
	if s.ttl <= 0 {
		s.ttl = DefaultStateTTL
	}
	if s.skew <= 0 {
		s.skew = DefaultRefreshSkew
	}
	if s.replay == nil {
		s.replay = NewMemoryReplayGuard(s.clock)
	}
	if s.finish == nil {
		s.finish = defaultFinish
	}
	d, err := NewDiscoverer(DiscoveryOptions{HTTPClient: o.HTTPClient, Log: s.log})
	if err != nil {
		return nil, err
	}
	s.disc = d
	return s, nil
}

// Detect is Discoverer.Detect over the service's HTTP client.
func (s *Service) Detect(ctx context.Context, serverURL string) (*DetectResult, error) {
	return s.disc.Detect(ctx, serverURL)
}

// RedirectURL is the OAuth redirect URI registered with every upstream
// authorization server.
func (s *Service) RedirectURL() string { return s.base + CallbackPath }

// ClientMetadataURL is the gateway's CIMD client_id.
func (s *Service) ClientMetadataURL() string { return s.base + ClientMetadataPath }
