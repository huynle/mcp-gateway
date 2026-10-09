package authserver

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/jobs"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// Options configures New. Everything is optional.
type Options struct {
	// Metrics counts access-token rejections; nil disables that.
	Metrics *observability.Metrics
	// Audit records consent, revocation and reuse events; nil records
	// nothing.
	Audit audit.Recorder
	// ClientIP derives the registration rate-limit key from the request.
	// The default is the host part of RemoteAddr; a deployment behind a
	// trusted proxy supplies one that reads the proxy's header.
	ClientIP func(*http.Request) string
	// Log defaults to slog.Default().
	Log *slog.Logger
}

// Service is the MCP OAuth 2.1 authorization server: it owns the
// discovery documents, dynamic client registration, the authorization and
// consent pages, the token, revocation and JWKS endpoints, the connected
// harnesses page, the access-token authenticator and the background jobs.
type Service struct {
	cfg      Config
	st       Store
	keys     *Keys
	mint     *Minter
	auth     *JWTAuthenticator
	limiter  *tokens.FailureLimiter
	clientIP func(*http.Request) string
	who      Identity
	tpl      *template.Template
	metrics  *observability.Metrics
	audit    audit.Recorder
	log      *slog.Logger
	now      func() time.Time
}

// New builds the service over the store and the envelope-encryption key
// provider (signing keys are stored encrypted).
func New(cfg Config, st Store, kp crypto.KeyProvider, opts Options) (*Service, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	switch {
	case st == nil:
		return nil, errors.New("authserver: store must not be nil")
	case kp == nil:
		return nil, errors.New("authserver: key provider must not be nil")
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Audit == nil {
		opts.Audit = audit.NopRecorder{}
	}
	if opts.ClientIP == nil {
		opts.ClientIP = remoteIP
	}
	s := &Service{
		cfg:      cfg,
		st:       st,
		limiter:  tokens.NewFailureLimiter(cfg.RegisterPerMin, time.Minute),
		clientIP: opts.ClientIP,
		metrics:  opts.Metrics,
		audit:    opts.Audit,
		log:      opts.Log,
		now:      func() time.Time { return time.Now().UTC() },
	}
	tpl, err := parseTemplates()
	if err != nil {
		return nil, fmt.Errorf("authserver: templates: %w", err)
	}
	s.tpl = tpl
	s.keys = NewKeys(st, kp, KeysOptions{Grace: cfg.KeyGrace, Log: opts.Log})
	s.mint = NewMinter(cfg, s.keys)
	s.auth = NewJWTAuthenticator(cfg, st, s.keys, AuthenticatorOptions{Metrics: opts.Metrics, Log: opts.Log})
	return s, nil
}

// SetClock replaces the time source everywhere (tests).
func (s *Service) SetClock(now func() time.Time) {
	s.now = now
	s.keys.SetClock(now)
	s.mint.SetClock(now)
	s.auth.SetClock(now)
	s.limiter.SetClock(now)
}

// Config returns the effective configuration.
func (s *Service) Config() Config { return s.cfg }

// Authenticator is the tokens.Authenticator for the gateway's access
// tokens; compose it with the generated-token one (Composite) for /mcp.
func (s *Service) Authenticator() *JWTAuthenticator { return s.auth }

// Keys exposes the signing-key manager (JWKS, rotation).
func (s *Service) Keys() *Keys { return s.keys }

// --- background jobs ---------------------------------------------------------

// Job intervals.
const (
	DefaultPruneInterval    = time.Hour
	DefaultRotationInterval = time.Hour
)

// Prune deletes clients idle for longer than ClientIdle (with their codes
// and refresh tokens) and codes past their expiry; it returns the counts.
func (s *Service) Prune(ctx context.Context) (clients, codes int64, err error) {
	now := s.now()
	err = s.st.Bypass(ctx, func(tx Tx) error {
		var err error
		if clients, err = tx.PruneClients(ctx, now.Add(-s.cfg.ClientIdle)); err != nil {
			return err
		}
		codes, err = tx.DeleteExpiredCodes(ctx, now)
		return err
	})
	if err != nil {
		return 0, 0, err
	}
	if clients > 0 || codes > 0 {
		s.log.Info("oauth state pruned", "event", "authserver.pruned", "clients", clients, "codes", codes)
	}
	return clients, codes, nil
}

// PruneJob returns the jobs.Job that runs Prune; interval 0 means
// DefaultPruneInterval.
func (s *Service) PruneJob(interval time.Duration) jobs.Job {
	if interval <= 0 {
		interval = DefaultPruneInterval
	}
	return jobFunc{name: "authserver.prune", interval: interval, run: func(ctx context.Context) error {
		_, _, err := s.Prune(ctx)
		return err
	}}
}

// KeyRotationJob returns the jobs.Job that rotates the signing key once
// it is older than KeyRotation and sweeps retired keys past the grace
// period; interval 0 means DefaultRotationInterval.
func (s *Service) KeyRotationJob(interval time.Duration) jobs.Job {
	if interval <= 0 {
		interval = DefaultRotationInterval
	}
	return jobFunc{name: "authserver.rotate_keys", interval: interval, run: func(ctx context.Context) error {
		_, err := s.keys.RotateIfDue(ctx, s.cfg.KeyRotation)
		return err
	}}
}

type jobFunc struct {
	name     string
	interval time.Duration
	run      func(context.Context) error
}

func (j jobFunc) Name() string                  { return j.name }
func (j jobFunc) Interval() time.Duration       { return j.interval }
func (j jobFunc) Run(ctx context.Context) error { return j.run(ctx) }

// --- helpers -----------------------------------------------------------------

// remoteIP is the default client key: the host part of RemoteAddr.
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// randomToken returns n random bytes as unpadded base64url.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// hashSecret is how codes, refresh tokens and client secrets are stored.
func hashSecret(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

// oauthError is the RFC 6749 section 5.2 error body.
type oauthError struct {
	Error       string `json:"error"`
	Description string `json:"error_description,omitempty"`
}

// writeError sends an OAuth JSON error.
func writeError(w http.ResponseWriter, status int, code, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(oauthError{Error: code, Description: description})
}

// writeJSON sends a JSON body that must not be cached (tokens, secrets).
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
