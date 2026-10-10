package config_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/config"
)

func envFrom(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func writeFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "gateway.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadDefaults(t *testing.T) {
	cfg, err := config.Load(envFrom(nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddr != ":18080" {
		t.Errorf("ListenAddr = %q, want %q", cfg.ListenAddr, ":18080")
	}
	if cfg.DrainTimeout != 25*time.Second {
		t.Errorf("DrainTimeout = %v, want 25s", cfg.DrainTimeout)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want info", cfg.LogLevel)
	}
	if cfg.LogFormat != "json" {
		t.Errorf("LogFormat = %q, want json", cfg.LogFormat)
	}
}

func TestLoadFromFile(t *testing.T) {
	p := writeFile(t, "listen_addr: \"127.0.0.1:9999\"\ndrain_timeout: 5s\nlog_level: debug\nlog_format: text\n")
	cfg, err := config.Load(envFrom(map[string]string{"GATEWAY_CONFIG_FILE": p}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddr != "127.0.0.1:9999" || cfg.DrainTimeout != 5*time.Second || cfg.LogLevel != "debug" || cfg.LogFormat != "text" {
		t.Errorf("unexpected config from file: %+v", cfg)
	}
}

func TestEnvOverridesFile(t *testing.T) {
	p := writeFile(t, "listen_addr: \"127.0.0.1:9999\"\ndrain_timeout: 5s\n")
	cfg, err := config.Load(envFrom(map[string]string{
		"GATEWAY_CONFIG_FILE":   p,
		"GATEWAY_LISTEN_ADDR":   ":7070",
		"GATEWAY_DRAIN_TIMEOUT": "1m",
		"GATEWAY_LOG_LEVEL":     "warn",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.ListenAddr != ":7070" {
		t.Errorf("ListenAddr = %q, want env value :7070", cfg.ListenAddr)
	}
	if cfg.DrainTimeout != time.Minute {
		t.Errorf("DrainTimeout = %v, want env value 1m", cfg.DrainTimeout)
	}
	if cfg.LogLevel != "warn" {
		t.Errorf("LogLevel = %q, want warn", cfg.LogLevel)
	}
}

func TestMissingConfigFileIsAnError(t *testing.T) {
	_, err := config.Load(envFrom(map[string]string{"GATEWAY_CONFIG_FILE": filepath.Join(t.TempDir(), "nope.yaml")}))
	if err == nil {
		t.Fatal("expected error for missing config file")
	}
}

func TestUnknownFileKeyIsAnError(t *testing.T) {
	p := writeFile(t, "bind_port: \":1\"\n")
	_, err := config.Load(envFrom(map[string]string{"GATEWAY_CONFIG_FILE": p}))
	if err == nil || !strings.Contains(err.Error(), "bind_port") {
		t.Fatalf("expected unknown-key error mentioning bind_port, got %v", err)
	}
}

func TestValidation(t *testing.T) {
	cases := map[string]map[string]string{
		"bad duration":   {"GATEWAY_DRAIN_TIMEOUT": "soon"},
		"zero drain":     {"GATEWAY_DRAIN_TIMEOUT": "0s"},
		"negative drain": {"GATEWAY_DRAIN_TIMEOUT": "-1s"},
		"bad level":      {"GATEWAY_LOG_LEVEL": "loud"},
		"bad format":     {"GATEWAY_LOG_FORMAT": "xml"},
		"empty addr":     {"GATEWAY_LISTEN_ADDR": " "},
	}
	for name, env := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := config.Load(envFrom(env)); err == nil {
				t.Errorf("expected validation error for %v", env)
			}
		})
	}
}

func TestLogLevelIsCaseInsensitive(t *testing.T) {
	cfg, err := config.Load(envFrom(map[string]string{"GATEWAY_LOG_LEVEL": "DEBUG", "GATEWAY_LOG_FORMAT": "Text"}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.LogLevel != "debug" || cfg.LogFormat != "text" {
		t.Errorf("expected normalised lower-case values, got %+v", cfg)
	}
}

func TestDatabaseURLsDefaultEmpty(t *testing.T) {
	cfg, err := config.Load(envFrom(nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DatabaseURL != "" || cfg.JobsDatabaseURL != "" {
		t.Errorf("database URLs should default to empty (store disabled), got %+v", cfg)
	}
}

func TestDatabaseURLsFromEnvAndFile(t *testing.T) {
	p := writeFile(t, "database_url: postgres://gateway_app:x@db/gateway\njobs_database_url: postgres://gateway_jobs:x@db/gateway\n")
	cfg, err := config.Load(envFrom(map[string]string{"GATEWAY_CONFIG_FILE": p}))
	if err != nil {
		t.Fatalf("Load from file: %v", err)
	}
	if cfg.DatabaseURL != "postgres://gateway_app:x@db/gateway" || cfg.JobsDatabaseURL != "postgres://gateway_jobs:x@db/gateway" {
		t.Errorf("file values not applied: %+v", cfg)
	}

	cfg, err = config.Load(envFrom(map[string]string{
		"GATEWAY_CONFIG_FILE":       p,
		"GATEWAY_DATABASE_URL":      " postgresql://gateway_app:y@localhost:15432/gateway?sslmode=disable ",
		"GATEWAY_JOBS_DATABASE_URL": "postgresql://gateway_jobs:y@localhost:15432/gateway?sslmode=disable",
	}))
	if err != nil {
		t.Fatalf("Load with env: %v", err)
	}
	if cfg.DatabaseURL != "postgresql://gateway_app:y@localhost:15432/gateway?sslmode=disable" {
		t.Errorf("env should override file and be trimmed, got %q", cfg.DatabaseURL)
	}
	if cfg.JobsDatabaseURL != "postgresql://gateway_jobs:y@localhost:15432/gateway?sslmode=disable" {
		t.Errorf("JobsDatabaseURL = %q", cfg.JobsDatabaseURL)
	}
}

func TestDatabaseURLValidation(t *testing.T) {
	app := "postgres://gateway_app:x@db/gateway"
	jobs := "postgres://gateway_jobs:x@db/gateway"
	cases := map[string]struct {
		env     map[string]string
		wantErr string
	}{
		"jobs without app": {
			env:     map[string]string{"GATEWAY_JOBS_DATABASE_URL": jobs},
			wantErr: "jobs_database_url requires database_url",
		},
		"app without jobs": {
			env:     map[string]string{"GATEWAY_DATABASE_URL": app},
			wantErr: "jobs_database_url must be set",
		},
		"bad app scheme": {
			env:     map[string]string{"GATEWAY_DATABASE_URL": "mysql://x@db/gateway", "GATEWAY_JOBS_DATABASE_URL": jobs},
			wantErr: "database_url",
		},
		"bad jobs scheme": {
			env:     map[string]string{"GATEWAY_DATABASE_URL": app, "GATEWAY_JOBS_DATABASE_URL": "db/gateway"},
			wantErr: "jobs_database_url",
		},
		"same role for both": {
			env:     map[string]string{"GATEWAY_DATABASE_URL": app, "GATEWAY_JOBS_DATABASE_URL": app},
			wantErr: "different database roles",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := config.Load(envFrom(tc.env))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Load(%v) error = %v, want one containing %q", tc.env, err, tc.wantErr)
			}
		})
	}
	// A URL in the error message would leak the password.
	_, err := config.Load(envFrom(map[string]string{"GATEWAY_DATABASE_URL": "mysql://user:hunter2@db/gateway", "GATEWAY_JOBS_DATABASE_URL": jobs}))
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("validation error leaks the password: %v", err)
	}
}

// --- identity / sessions / OIDC ---------------------------------------------

func TestIdentityDefaults(t *testing.T) {
	cfg, err := config.Load(envFrom(nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BaseURL != "http://localhost:18080" {
		t.Errorf("BaseURL = %q, want http://localhost:18080", cfg.BaseURL)
	}
	if cfg.SessionIdleTimeout != 12*time.Hour {
		t.Errorf("SessionIdleTimeout = %v, want 12h", cfg.SessionIdleTimeout)
	}
	if cfg.SessionAbsoluteTimeout != 7*24*time.Hour {
		t.Errorf("SessionAbsoluteTimeout = %v, want 168h", cfg.SessionAbsoluteTimeout)
	}
	if !cfg.SessionCookieSecure {
		t.Error("SessionCookieSecure should default to true")
	}
	if cfg.DefaultRole != "member" {
		t.Errorf("DefaultRole = %q, want member", cfg.DefaultRole)
	}
	if cfg.TokenSignInMaxAge != 30*24*time.Hour {
		t.Errorf("TokenSignInMaxAge = %v, want 720h", cfg.TokenSignInMaxAge)
	}
	if cfg.PolicyReloadInterval != 15*time.Second {
		t.Errorf("PolicyReloadInterval = %v, want 15s", cfg.PolicyReloadInterval)
	}
	if cfg.MCPMaxBody != 1<<20 {
		t.Errorf("MCPMaxBody = %d, want 1 MiB", cfg.MCPMaxBody)
	}
	if cfg.RateUserPerMin != 60 || cfg.RateAppPerMin != 600 {
		t.Errorf("rate limits = %d/%d, want 60/600", cfg.RateUserPerMin, cfg.RateAppPerMin)
	}
	if cfg.EnableFakeConnector {
		t.Error("EnableFakeConnector must default to false")
	}
	if len(cfg.OIDCProviders) != 0 || len(cfg.BootstrapAdmins) != 0 {
		t.Errorf("no providers or admins expected by default, got %+v", cfg)
	}
}

func TestOIDCProvidersFromEnv(t *testing.T) {
	cfg, err := config.Load(envFrom(map[string]string{
		"GATEWAY_BASE_URL":                    "https://gw.example.com/",
		"GATEWAY_SESSION_IDLE_TIMEOUT":        "1h",
		"GATEWAY_SESSION_ABSOLUTE_TIMEOUT":    "48h",
		"GATEWAY_SESSION_COOKIE_SECURE":       "false",
		"GATEWAY_TOKEN_SIGNIN_MAX_AGE":        "240h",
		"GATEWAY_POLICY_RELOAD_INTERVAL":      "5s",
		"GATEWAY_MCP_MAX_BODY":                " 4096 ",
		"GATEWAY_DEFAULT_ROLE":                "staff",
		"GATEWAY_BOOTSTRAP_ADMINS":            "http://localhost:15556/dex|08a8684b, https://accounts.google.com|1234",
		"GATEWAY_OIDC_PROVIDERS":              "dex, google",
		"GATEWAY_OIDC_DEX_ISSUER":             "http://localhost:15556/dex",
		"GATEWAY_OIDC_DEX_CLIENT_ID":          "gateway",
		"GATEWAY_OIDC_DEX_CLIENT_SECRET":      "gateway-dev-secret",
		"GATEWAY_OIDC_DEX_ALLOWED_DOMAINS":    "Example.com, other.test",
		"GATEWAY_OIDC_DEX_DISPLAY_NAME":       "Local dex",
		"GATEWAY_OIDC_GOOGLE_ISSUER":          "https://accounts.google.com",
		"GATEWAY_OIDC_GOOGLE_CLIENT_ID":       "cid",
		"GATEWAY_OIDC_GOOGLE_CLIENT_SECRET":   "sec",
		"GATEWAY_OIDC_GOOGLE_ALLOWED_TENANTS": "tenant-1",
		"GATEWAY_OIDC_GOOGLE_DOMAIN_CLAIM":    "hd",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.BaseURL != "https://gw.example.com" {
		t.Errorf("BaseURL = %q, want trailing slash trimmed", cfg.BaseURL)
	}
	if cfg.TokenSignInMaxAge != 240*time.Hour {
		t.Errorf("TokenSignInMaxAge = %v, want 240h", cfg.TokenSignInMaxAge)
	}
	if cfg.PolicyReloadInterval != 5*time.Second {
		t.Errorf("PolicyReloadInterval = %v, want 5s", cfg.PolicyReloadInterval)
	}
	if cfg.MCPMaxBody != 4096 {
		t.Errorf("MCPMaxBody = %d, want 4096", cfg.MCPMaxBody)
	}
	if cfg.SessionIdleTimeout != time.Hour || cfg.SessionAbsoluteTimeout != 48*time.Hour || cfg.SessionCookieSecure {
		t.Errorf("session settings not applied: %+v", cfg)
	}
	if cfg.DefaultRole != "staff" {
		t.Errorf("DefaultRole = %q", cfg.DefaultRole)
	}
	wantAdmins := []string{"http://localhost:15556/dex|08a8684b", "https://accounts.google.com|1234"}
	if strings.Join(cfg.BootstrapAdmins, ",") != strings.Join(wantAdmins, ",") {
		t.Errorf("BootstrapAdmins = %q, want %q", cfg.BootstrapAdmins, wantAdmins)
	}
	if len(cfg.OIDCProviders) != 2 {
		t.Fatalf("OIDCProviders = %+v, want 2", cfg.OIDCProviders)
	}
	dex := cfg.OIDCProviders[0]
	if dex.Name != "dex" || dex.Issuer != "http://localhost:15556/dex" || dex.ClientID != "gateway" || dex.ClientSecret != "gateway-dev-secret" || dex.DisplayName != "Local dex" {
		t.Errorf("dex provider = %+v", dex)
	}
	if strings.Join(dex.AllowedDomains, ",") != "example.com,other.test" {
		t.Errorf("dex AllowedDomains = %q, want lower-cased, trimmed", dex.AllowedDomains)
	}
	google := cfg.OIDCProviders[1]
	if google.Name != "google" || strings.Join(google.AllowedTenants, ",") != "tenant-1" || google.DomainClaim != "hd" {
		t.Errorf("google provider = %+v", google)
	}
	if google.DisplayName != "google" {
		t.Errorf("DisplayName should default to the name, got %q", google.DisplayName)
	}
}

func TestOIDCProvidersFromFile(t *testing.T) {
	p := writeFile(t, `
base_url: http://localhost:18080
oidc_providers:
  - name: dex
    issuer: http://localhost:15556/dex
    client_id: gateway
    client_secret: s
    allowed_domains: [example.com]
`)
	cfg, err := config.Load(envFrom(map[string]string{"GATEWAY_CONFIG_FILE": p}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.OIDCProviders) != 1 || cfg.OIDCProviders[0].Name != "dex" {
		t.Fatalf("OIDCProviders = %+v", cfg.OIDCProviders)
	}
}

func TestIdentityValidation(t *testing.T) {
	good := map[string]string{
		"GATEWAY_OIDC_PROVIDERS":           "dex",
		"GATEWAY_OIDC_DEX_ISSUER":          "http://localhost:15556/dex",
		"GATEWAY_OIDC_DEX_CLIENT_ID":       "gateway",
		"GATEWAY_OIDC_DEX_CLIENT_SECRET":   "s",
		"GATEWAY_OIDC_DEX_ALLOWED_DOMAINS": "example.com",
	}
	if _, err := config.Load(envFrom(good)); err != nil {
		t.Fatalf("baseline should load: %v", err)
	}
	cases := map[string]map[string]string{
		"missing issuer":        {"GATEWAY_OIDC_DEX_ISSUER": ""},
		"issuer not a URL":      {"GATEWAY_OIDC_DEX_ISSUER": "dex"},
		"missing client id":     {"GATEWAY_OIDC_DEX_CLIENT_ID": ""},
		"missing client secret": {"GATEWAY_OIDC_DEX_CLIENT_SECRET": ""},
		"no allow-list":         {"GATEWAY_OIDC_DEX_ALLOWED_DOMAINS": ""},
		"bad provider name":     {"GATEWAY_OIDC_PROVIDERS": "my provider"},
		"bad base url":          {"GATEWAY_BASE_URL": "localhost:18080"},
		"base url with query":   {"GATEWAY_BASE_URL": "http://localhost:18080/?x=1"},
		"zero idle":             {"GATEWAY_SESSION_IDLE_TIMEOUT": "0s"},
		"idle above absolute":   {"GATEWAY_SESSION_IDLE_TIMEOUT": "200h"},
		"bad secure flag":       {"GATEWAY_SESSION_COOKIE_SECURE": "yes"},
		"empty default role":    {"GATEWAY_DEFAULT_ROLE": " "},
		"bad bootstrap admin":   {"GATEWAY_BOOTSTRAP_ADMINS": "no-pipe"},
		"zero token max age":    {"GATEWAY_TOKEN_SIGNIN_MAX_AGE": "0s"},
		"zero policy reload":    {"GATEWAY_POLICY_RELOAD_INTERVAL": "0s"},
		"bad policy reload":     {"GATEWAY_POLICY_RELOAD_INTERVAL": "soon"},
		"bad token max age":     {"GATEWAY_TOKEN_SIGNIN_MAX_AGE": "30 days"},
		"zero mcp max body":     {"GATEWAY_MCP_MAX_BODY": "0"},
		"bad mcp max body":      {"GATEWAY_MCP_MAX_BODY": "1MiB"},
		"zero user rate":        {"GATEWAY_RATE_USER_PER_MIN": "0"},
		"bad user rate":         {"GATEWAY_RATE_USER_PER_MIN": "many"},
		"negative app rate":     {"GATEWAY_RATE_APP_PER_MIN": "-5"},
		"bad fake flag":         {"GATEWAY_ENABLE_FAKE_CONNECTOR": "yes"},
	}
	for name, overrides := range cases {
		t.Run(name, func(t *testing.T) {
			env := map[string]string{}
			for k, v := range good {
				env[k] = v
			}
			for k, v := range overrides {
				env[k] = v
			}
			if _, err := config.Load(envFrom(env)); err == nil {
				t.Errorf("expected validation error for %v", overrides)
			}
		})
	}
}

func TestOIDCProviderNamesMustBeUnique(t *testing.T) {
	p := writeFile(t, `
oidc_providers:
  - {name: dex, issuer: http://a, client_id: a, client_secret: a, allowed_domains: [x.com]}
  - {name: dex, issuer: http://b, client_id: b, client_secret: b, allowed_domains: [x.com]}
`)
	if _, err := config.Load(envFrom(map[string]string{"GATEWAY_CONFIG_FILE": p})); err == nil || !strings.Contains(err.Error(), "dex") {
		t.Fatalf("expected duplicate-name error, got %v", err)
	}
}

func TestEnvProviderListReplacesFileProviders(t *testing.T) {
	p := writeFile(t, `
oidc_providers:
  - {name: file, issuer: http://a, client_id: a, client_secret: a, allowed_domains: [x.com]}
`)
	cfg, err := config.Load(envFrom(map[string]string{
		"GATEWAY_CONFIG_FILE":              p,
		"GATEWAY_OIDC_PROVIDERS":           "dex",
		"GATEWAY_OIDC_DEX_ISSUER":          "http://localhost:15556/dex",
		"GATEWAY_OIDC_DEX_CLIENT_ID":       "gateway",
		"GATEWAY_OIDC_DEX_CLIENT_SECRET":   "s",
		"GATEWAY_OIDC_DEX_ALLOWED_DOMAINS": "example.com",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.OIDCProviders) != 1 || cfg.OIDCProviders[0].Name != "dex" {
		t.Fatalf("env provider list should replace the file's, got %+v", cfg.OIDCProviders)
	}
}

func TestRateLimitsAndFakeConnectorFromEnvAndFile(t *testing.T) {
	p := writeFile(t, "rate_user_per_min: 10\nrate_app_per_min: 20\nenable_fake_connector: true\n")
	cfg, err := config.Load(envFrom(map[string]string{"GATEWAY_CONFIG_FILE": p}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.RateUserPerMin != 10 || cfg.RateAppPerMin != 20 || !cfg.EnableFakeConnector {
		t.Errorf("from file: %d/%d fake=%v", cfg.RateUserPerMin, cfg.RateAppPerMin, cfg.EnableFakeConnector)
	}
	cfg, err = config.Load(envFrom(map[string]string{
		"GATEWAY_CONFIG_FILE":           p,
		"GATEWAY_RATE_USER_PER_MIN":     " 30 ",
		"GATEWAY_RATE_APP_PER_MIN":      "900",
		"GATEWAY_ENABLE_FAKE_CONNECTOR": "false",
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.RateUserPerMin != 30 || cfg.RateAppPerMin != 900 || cfg.EnableFakeConnector {
		t.Errorf("env over file: %d/%d fake=%v", cfg.RateUserPerMin, cfg.RateAppPerMin, cfg.EnableFakeConnector)
	}
}
