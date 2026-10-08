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
}

// Default returns the built-in configuration used when nothing overrides it.
func Default() Config {
	return Config{
		ListenAddr:   ":18080",
		DrainTimeout: 25 * time.Second,
		LogLevel:     "info",
		LogFormat:    "json",
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
	return nil
}

func (c *Config) normalize() {
	c.ListenAddr = strings.TrimSpace(c.ListenAddr)
	c.LogLevel = strings.ToLower(strings.TrimSpace(c.LogLevel))
	c.LogFormat = strings.ToLower(strings.TrimSpace(c.LogFormat))
	c.DatabaseURL = strings.TrimSpace(c.DatabaseURL)
	c.JobsDatabaseURL = strings.TrimSpace(c.JobsDatabaseURL)
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
	return errors.Join(errs...)
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
