package authserver

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Environment variables ConfigFromEnv reads (every one optional).
const (
	EnvAccessTokenTTL   = "GATEWAY_OAUTH_ACCESS_TOKEN_TTL"
	EnvRefreshTokenTTL  = "GATEWAY_OAUTH_REFRESH_TOKEN_TTL"
	EnvCodeTTL          = "GATEWAY_OAUTH_CODE_TTL"
	EnvClientIdle       = "GATEWAY_OAUTH_CLIENT_IDLE"
	EnvRegisterPerMin   = "GATEWAY_OAUTH_REGISTER_PER_MIN"
	EnvMaxUnusedClients = "GATEWAY_OAUTH_MAX_UNUSED_CLIENTS"
	EnvKeyRotation      = "GATEWAY_OAUTH_KEY_ROTATION"
	EnvKeyGrace         = "GATEWAY_OAUTH_KEY_GRACE"
)

// Defaults (decisions 3ycafouv, ysorv868).
const (
	DefaultAccessTokenTTL   = time.Hour
	DefaultRefreshTokenTTL  = 30 * 24 * time.Hour
	DefaultCodeTTL          = 10 * time.Minute
	DefaultClientIdle       = 30 * 24 * time.Hour
	DefaultRegisterPerMin   = 10
	DefaultMaxUnusedClients = 1000
	DefaultKeyRotation      = 30 * 24 * time.Hour
	DefaultKeyGrace         = 2 * time.Hour
	DefaultSignInMaxAge     = 30 * 24 * time.Hour
)

// Config is the authorization server configuration. Issuer is
// GATEWAY_BASE_URL (the gateway is its own authorization server, decision
// 3ycafouv); every endpoint and the protected resource hang off it.
type Config struct {
	// Issuer is the public origin, without a trailing slash.
	Issuer string
	// ResourcePath is the MCP endpoint's path under Issuer (DefaultResourcePath).
	ResourcePath string
	// AccessTokenTTL is the JWT lifetime (1h).
	AccessTokenTTL time.Duration
	// RefreshTokenTTL is how long a refresh token lives from its issue (30d);
	// every rotation issues a fresh one.
	RefreshTokenTTL time.Duration
	// CodeTTL bounds an authorization code (10m).
	CodeTTL time.Duration
	// ClientIdle is how long an unused registered client is kept (30d).
	ClientIdle time.Duration
	// RegisterPerMin is the per-IP registration budget (10).
	RegisterPerMin int
	// MaxUnusedClients caps registrations that never completed a sign-in.
	MaxUnusedClients int
	// KeyRotation is how old the active signing key may get before the
	// rotation job replaces it (30d); KeyGrace is how long a retired key
	// still verifies (2h).
	KeyRotation time.Duration
	KeyGrace    time.Duration
	// SignInMaxAge: a refresh token stops working when its owner's last
	// company sign-in is older than this (the same rule as generated
	// tokens, decision uamxx6ba); GATEWAY_TOKEN_SIGNIN_MAX_AGE.
	SignInMaxAge time.Duration
}

// DefaultConfig returns every default; the caller sets Issuer.
func DefaultConfig() Config {
	return Config{
		ResourcePath:     DefaultResourcePath,
		AccessTokenTTL:   DefaultAccessTokenTTL,
		RefreshTokenTTL:  DefaultRefreshTokenTTL,
		CodeTTL:          DefaultCodeTTL,
		ClientIdle:       DefaultClientIdle,
		RegisterPerMin:   DefaultRegisterPerMin,
		MaxUnusedClients: DefaultMaxUnusedClients,
		KeyRotation:      DefaultKeyRotation,
		KeyGrace:         DefaultKeyGrace,
		SignInMaxAge:     DefaultSignInMaxAge,
	}
}

// ConfigFromEnv builds the configuration from the defaults, the issuer and
// the GATEWAY_OAUTH_* variables getenv returns.
func ConfigFromEnv(issuer string, getenv func(string) string) (Config, error) {
	cfg := DefaultConfig()
	cfg.Issuer = issuer
	for _, d := range []struct {
		env string
		dst *time.Duration
	}{
		{EnvAccessTokenTTL, &cfg.AccessTokenTTL}, {EnvRefreshTokenTTL, &cfg.RefreshTokenTTL}, {EnvCodeTTL, &cfg.CodeTTL},
		{EnvClientIdle, &cfg.ClientIdle}, {EnvKeyRotation, &cfg.KeyRotation}, {EnvKeyGrace, &cfg.KeyGrace},
	} {
		if v := strings.TrimSpace(getenv(d.env)); v != "" {
			dur, err := time.ParseDuration(v)
			if err != nil {
				return Config{}, fmt.Errorf("%s: %w", d.env, err)
			}
			*d.dst = dur
		}
	}
	for _, n := range []struct {
		env string
		dst *int
	}{{EnvRegisterPerMin, &cfg.RegisterPerMin}, {EnvMaxUnusedClients, &cfg.MaxUnusedClients}} {
		if v := strings.TrimSpace(getenv(n.env)); v != "" {
			i, err := strconv.Atoi(v)
			if err != nil {
				return Config{}, fmt.Errorf("%s: %w", n.env, err)
			}
			*n.dst = i
		}
	}
	if err := cfg.Validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

// Validate checks the configuration; it normalises Issuer.
func (c *Config) Validate() error {
	c.Issuer = strings.TrimRight(strings.TrimSpace(c.Issuer), "/")
	switch {
	case c.Issuer == "":
		return errors.New("authserver: issuer (GATEWAY_BASE_URL) is required")
	case !strings.HasPrefix(c.Issuer, "https://") && !strings.HasPrefix(c.Issuer, "http://"):
		return fmt.Errorf("authserver: issuer must be an http(s) URL, got %q", c.Issuer)
	case strings.ContainsAny(c.Issuer, "?#"):
		return fmt.Errorf("authserver: issuer must not carry a query or fragment, got %q", c.Issuer)
	case c.ResourcePath == "" || !strings.HasPrefix(c.ResourcePath, "/"):
		return fmt.Errorf("authserver: resource path must start with /, got %q", c.ResourcePath)
	case c.AccessTokenTTL <= 0 || c.RefreshTokenTTL <= 0 || c.CodeTTL <= 0 || c.ClientIdle <= 0 || c.KeyRotation <= 0 || c.KeyGrace <= 0 || c.SignInMaxAge <= 0:
		return errors.New("authserver: every lifetime must be positive")
	case c.RegisterPerMin < 1:
		return fmt.Errorf("authserver: %s must be at least 1", EnvRegisterPerMin)
	case c.MaxUnusedClients < 1:
		return fmt.Errorf("authserver: %s must be at least 1", EnvMaxUnusedClients)
	}
	return nil
}

// issuer is the normalised issuer (Validate may not have run on a
// hand-built Config).
func (c Config) issuer() string { return strings.TrimRight(strings.TrimSpace(c.Issuer), "/") }

// Resource is the protected resource identifier (RFC 8707 / RFC 9728):
// the MCP endpoint's canonical URL, which every authorization and token
// request must name and every access token is bound to.
func (c Config) Resource() string {
	p := c.ResourcePath
	if p == "" {
		p = DefaultResourcePath
	}
	return c.issuer() + p
}

// URL returns issuer + path.
func (c Config) URL(path string) string { return c.issuer() + path }
