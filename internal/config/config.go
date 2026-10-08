// Package config loads gateway configuration from an optional YAML file and
// GATEWAY_-prefixed environment variables.
//
// Precedence, lowest to highest: built-in defaults, the YAML file named by
// GATEWAY_CONFIG_FILE, then individual GATEWAY_* variables. Every variable is
// documented in .env.example at the repository root.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// EnvPrefix is the prefix shared by every environment variable the gateway reads.
const EnvPrefix = "GATEWAY_"

// Config is the fully resolved gateway configuration.
type Config struct {
	// ListenAddr is the TCP address the HTTP server binds (GATEWAY_LISTEN_ADDR).
	ListenAddr string `yaml:"listen_addr"`
	// DrainTimeout bounds how long shutdown waits for in-flight requests
	// (GATEWAY_DRAIN_TIMEOUT). Requests still running when it elapses are cut off.
	DrainTimeout time.Duration `yaml:"drain_timeout"`
	// LogLevel is one of debug, info, warn, error (GATEWAY_LOG_LEVEL).
	LogLevel string `yaml:"log_level"`
	// LogFormat is json or text (GATEWAY_LOG_FORMAT).
	LogFormat string `yaml:"log_format"`
	// DatabaseURL is the PostgreSQL connection string for the request path,
	// as the gateway_app role (GATEWAY_DATABASE_URL). Empty disables the store
	// (foundation-only mode); when set, JobsDatabaseURL is required too.
	DatabaseURL string `yaml:"database_url"`
	// JobsDatabaseURL is the connection string for background workers and
	// admin metadata reads, as the gateway_jobs role (GATEWAY_JOBS_DATABASE_URL).
	JobsDatabaseURL string `yaml:"jobs_database_url"`

	// BaseURL is the public origin users reach the gateway at
	// (GATEWAY_BASE_URL), used to build OIDC redirect URIs. No trailing slash.
	BaseURL string `yaml:"base_url"`
	// SessionIdleTimeout signs a browser session out after this long without
	// a request (GATEWAY_SESSION_IDLE_TIMEOUT).
	SessionIdleTimeout time.Duration `yaml:"session_idle_timeout"`
	// SessionAbsoluteTimeout signs a browser session out this long after
	// sign-in regardless of activity (GATEWAY_SESSION_ABSOLUTE_TIMEOUT).
	SessionAbsoluteTimeout time.Duration `yaml:"session_absolute_timeout"`
	// SessionCookieSecure sets the Secure flag on the session and sign-in
	// cookies (GATEWAY_SESSION_COOKIE_SECURE). Only disable for plain-http
	// localhost development.
	SessionCookieSecure bool `yaml:"session_cookie_secure"`
	// DefaultRole is the role name given to users created on first sign-in
	// (GATEWAY_DEFAULT_ROLE); the row is created when missing.
	DefaultRole string `yaml:"default_role"`
	// BootstrapAdmins lists "issuer|subject" pairs that receive the admin
	// role on every sign-in (GATEWAY_BOOTSTRAP_ADMINS, comma-separated).
	BootstrapAdmins []string `yaml:"bootstrap_admins"`
	// OIDCProviders are the company identity providers users may sign in
	// with. From the environment: GATEWAY_OIDC_PROVIDERS names them and
	// GATEWAY_OIDC_<NAME>_* (name upper-cased) configures each; a non-empty
	// GATEWAY_OIDC_PROVIDERS replaces the file's list entirely.
	OIDCProviders []OIDCProvider `yaml:"oidc_providers"`
}

// OIDCProvider is one company identity provider (Google, Entra, Okta, dex).
type OIDCProvider struct {
	// Name is the URL-safe key used in /auth/{name}/... routes: lower-case
	// letters, digits and hyphens.
	Name string `yaml:"name"`
	// DisplayName is the sign-in button label; defaults to Name.
	DisplayName string `yaml:"display_name"`
	// Issuer is the OIDC issuer URL discovery runs against.
	Issuer       string `yaml:"issuer"`
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
	// AllowedDomains admits users whose hosted domain (DomainClaim, default
	// "hd", falling back to the verified email's domain) is listed.
	AllowedDomains []string `yaml:"allowed_domains"`
	// AllowedTenants admits users whose "tid" claim (Entra tenant) is listed.
	AllowedTenants []string `yaml:"allowed_tenants"`
	// DomainClaim overrides the claim consulted for AllowedDomains.
	DomainClaim string `yaml:"domain_claim"`
}

// Default returns the built-in configuration used when nothing overrides it.
func Default() Config {
	return Config{
		ListenAddr:             ":18080",
		DrainTimeout:           25 * time.Second,
		LogLevel:               "info",
		LogFormat:              "json",
		BaseURL:                "http://localhost:18080",
		SessionIdleTimeout:     12 * time.Hour,
		SessionAbsoluteTimeout: 7 * 24 * time.Hour,
		SessionCookieSecure:    true,
		DefaultRole:            "member",
	}
}

// Load resolves the configuration using getenv (typically os.Getenv) for
// environment lookups. A getenv returning "" means "unset".
func Load(getenv func(string) string) (Config, error) {
	cfg := Default()

	if path := getenv(EnvPrefix + "CONFIG_FILE"); path != "" {
		if err := loadFile(path, &cfg); err != nil {
			return Config{}, err
		}
	}
	if err := applyEnv(getenv, &cfg); err != nil {
		return Config{}, err
	}
	cfg.normalize()
	if err := cfg.validate(); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func loadFile(path string, cfg *Config) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("config file: %w", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	// An empty file decodes to io.EOF; that is a valid "no overrides" file.
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("config file %s: %w", path, err)
	}
	return nil
}

func applyEnv(getenv func(string) string, cfg *Config) error {
	if v := getenv(EnvPrefix + "LISTEN_ADDR"); v != "" {
		cfg.ListenAddr = v
	}
	if v := getenv(EnvPrefix + "DRAIN_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("%sDRAIN_TIMEOUT: %w", EnvPrefix, err)
		}
		cfg.DrainTimeout = d
	}
	if v := getenv(EnvPrefix + "LOG_LEVEL"); v != "" {
		cfg.LogLevel = v
	}
	if v := getenv(EnvPrefix + "LOG_FORMAT"); v != "" {
		cfg.LogFormat = v
	}
	if v := getenv(EnvPrefix + "DATABASE_URL"); v != "" {
		cfg.DatabaseURL = v
	}
	if v := getenv(EnvPrefix + "JOBS_DATABASE_URL"); v != "" {
		cfg.JobsDatabaseURL = v
	}
	return applyIdentityEnv(getenv, cfg)
}

func applyIdentityEnv(getenv func(string) string, cfg *Config) error {
	if v := getenv(EnvPrefix + "BASE_URL"); v != "" {
		cfg.BaseURL = v
	}
	if v := getenv(EnvPrefix + "SESSION_IDLE_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("%sSESSION_IDLE_TIMEOUT: %w", EnvPrefix, err)
		}
		cfg.SessionIdleTimeout = d
	}
	if v := getenv(EnvPrefix + "SESSION_ABSOLUTE_TIMEOUT"); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			return fmt.Errorf("%sSESSION_ABSOLUTE_TIMEOUT: %w", EnvPrefix, err)
		}
		cfg.SessionAbsoluteTimeout = d
	}
	if v := getenv(EnvPrefix + "SESSION_COOKIE_SECURE"); v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return fmt.Errorf("%sSESSION_COOKIE_SECURE: %w", EnvPrefix, err)
		}
		cfg.SessionCookieSecure = b
	}
	if v := getenv(EnvPrefix + "DEFAULT_ROLE"); v != "" {
		cfg.DefaultRole = v
	}
	if v := getenv(EnvPrefix + "BOOTSTRAP_ADMINS"); v != "" {
		cfg.BootstrapAdmins = splitList(v)
	}
	if v := getenv(EnvPrefix + "OIDC_PROVIDERS"); v != "" {
		cfg.OIDCProviders = nil
		for _, name := range splitList(v) {
			prefix := EnvPrefix + "OIDC_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_")) + "_"
			cfg.OIDCProviders = append(cfg.OIDCProviders, OIDCProvider{
				Name:           name,
				DisplayName:    getenv(prefix + "DISPLAY_NAME"),
				Issuer:         getenv(prefix + "ISSUER"),
				ClientID:       getenv(prefix + "CLIENT_ID"),
				ClientSecret:   getenv(prefix + "CLIENT_SECRET"),
				AllowedDomains: splitList(getenv(prefix + "ALLOWED_DOMAINS")),
				AllowedTenants: splitList(getenv(prefix + "ALLOWED_TENANTS")),
				DomainClaim:    getenv(prefix + "DOMAIN_CLAIM"),
			})
		}
	}
	return nil
}

// splitList splits a comma-separated list, trimming blanks and dropping
// empty items.
func splitList(v string) []string {
	var out []string
	for _, item := range strings.Split(v, ",") {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	return out
}

func (c *Config) normalize() {
	c.ListenAddr = strings.TrimSpace(c.ListenAddr)
	c.LogLevel = strings.ToLower(strings.TrimSpace(c.LogLevel))
	c.LogFormat = strings.ToLower(strings.TrimSpace(c.LogFormat))
	c.DatabaseURL = strings.TrimSpace(c.DatabaseURL)
	c.JobsDatabaseURL = strings.TrimSpace(c.JobsDatabaseURL)
	c.BaseURL = strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	c.DefaultRole = strings.TrimSpace(c.DefaultRole)
	c.BootstrapAdmins = normalizeList(c.BootstrapAdmins, false)
	for i := range c.OIDCProviders {
		p := &c.OIDCProviders[i]
		p.Name = strings.ToLower(strings.TrimSpace(p.Name))
		p.DisplayName = strings.TrimSpace(p.DisplayName)
		if p.DisplayName == "" {
			p.DisplayName = p.Name
		}
		p.Issuer = strings.TrimSpace(p.Issuer)
		p.ClientID = strings.TrimSpace(p.ClientID)
		p.ClientSecret = strings.TrimSpace(p.ClientSecret)
		p.AllowedDomains = normalizeList(p.AllowedDomains, true)
		p.AllowedTenants = normalizeList(p.AllowedTenants, false)
		p.DomainClaim = strings.TrimSpace(p.DomainClaim)
	}
}

// normalizeList trims items, drops empty ones and optionally lower-cases them.
func normalizeList(items []string, lower bool) []string {
	var out []string
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if lower {
			item = strings.ToLower(item)
		}
		out = append(out, item)
	}
	return out
}

func (c Config) validate() error {
	var errs []error
	if c.ListenAddr == "" {
		errs = append(errs, errors.New("listen_addr must not be empty"))
	}
	if c.DrainTimeout <= 0 {
		errs = append(errs, fmt.Errorf("drain_timeout must be positive, got %v", c.DrainTimeout))
	}
	switch c.LogLevel {
	case "debug", "info", "warn", "error":
	default:
		errs = append(errs, fmt.Errorf("log_level must be debug, info, warn or error, got %q", c.LogLevel))
	}
	switch c.LogFormat {
	case "json", "text":
	default:
		errs = append(errs, fmt.Errorf("log_format must be json or text, got %q", c.LogFormat))
	}
	errs = append(errs, c.validateDatabase()...)
	errs = append(errs, c.validateIdentity()...)
	return errors.Join(errs...)
}

// providerNameRE bounds provider names so they are safe in URL paths and
// environment variable names.
var providerNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

func (c Config) validateIdentity() []error {
	var errs []error
	if u, err := url.Parse(c.BaseURL); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		errs = append(errs, fmt.Errorf("base_url must be an absolute http(s) URL without query or fragment, got %q", c.BaseURL))
	}
	if c.SessionIdleTimeout <= 0 {
		errs = append(errs, fmt.Errorf("session_idle_timeout must be positive, got %v", c.SessionIdleTimeout))
	}
	if c.SessionAbsoluteTimeout <= 0 {
		errs = append(errs, fmt.Errorf("session_absolute_timeout must be positive, got %v", c.SessionAbsoluteTimeout))
	}
	if c.SessionIdleTimeout > 0 && c.SessionAbsoluteTimeout > 0 && c.SessionIdleTimeout > c.SessionAbsoluteTimeout {
		errs = append(errs, fmt.Errorf("session_idle_timeout (%v) must not exceed session_absolute_timeout (%v)", c.SessionIdleTimeout, c.SessionAbsoluteTimeout))
	}
	if c.DefaultRole == "" {
		errs = append(errs, errors.New("default_role must not be empty"))
	}
	for _, a := range c.BootstrapAdmins {
		issuer, subject, ok := strings.Cut(a, "|")
		if !ok || strings.TrimSpace(issuer) == "" || strings.TrimSpace(subject) == "" {
			errs = append(errs, fmt.Errorf("bootstrap_admins entry %q must be \"issuer|subject\"", a))
		}
	}
	seen := map[string]bool{}
	for _, p := range c.OIDCProviders {
		errs = append(errs, p.validate()...)
		if seen[p.Name] {
			errs = append(errs, fmt.Errorf("oidc provider %q is configured twice", p.Name))
		}
		seen[p.Name] = true
	}
	return errs
}

func (p OIDCProvider) validate() []error {
	var errs []error
	label := fmt.Sprintf("oidc provider %q", p.Name)
	if !providerNameRE.MatchString(p.Name) {
		errs = append(errs, fmt.Errorf("%s: name must be lower-case letters, digits and hyphens", label))
	}
	if u, err := url.Parse(p.Issuer); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		errs = append(errs, fmt.Errorf("%s: issuer must be an absolute http(s) URL, got %q", label, p.Issuer))
	}
	if p.ClientID == "" {
		errs = append(errs, fmt.Errorf("%s: client_id must not be empty", label))
	}
	if p.ClientSecret == "" {
		errs = append(errs, fmt.Errorf("%s: client_secret must not be empty", label))
	}
	if len(p.AllowedDomains) == 0 && len(p.AllowedTenants) == 0 {
		errs = append(errs, fmt.Errorf("%s: at least one allowed domain or tenant is required", label))
	}
	return errs
}

// validateDatabase checks the two connection strings without ever echoing
// them (they carry passwords): both or neither, PostgreSQL URLs, and distinct
// roles so the bypass pool cannot silently be the request-path role.
func (c Config) validateDatabase() []error {
	if c.DatabaseURL == "" && c.JobsDatabaseURL == "" {
		return nil
	}
	var errs []error
	if c.DatabaseURL == "" {
		return []error{errors.New("jobs_database_url requires database_url")}
	}
	if c.JobsDatabaseURL == "" {
		return []error{errors.New("jobs_database_url must be set when database_url is set")}
	}
	appUser, err := postgresUser(c.DatabaseURL)
	if err != nil {
		errs = append(errs, fmt.Errorf("database_url: %w", err))
	}
	jobsUser, err := postgresUser(c.JobsDatabaseURL)
	if err != nil {
		errs = append(errs, fmt.Errorf("jobs_database_url: %w", err))
	}
	if len(errs) == 0 && appUser == jobsUser {
		errs = append(errs, fmt.Errorf("database_url and jobs_database_url must use different database roles, both use %q", appUser))
	}
	return errs
}

// postgresUser parses a postgres:// or postgresql:// URL and returns its user name.
func postgresUser(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", errors.New("not a valid URL")
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return "", fmt.Errorf("scheme must be postgres or postgresql, got %q", u.Scheme)
	}
	if u.User == nil || u.User.Username() == "" {
		return "", errors.New("must name the database role (user) to connect as")
	}
	return u.User.Username(), nil
}
