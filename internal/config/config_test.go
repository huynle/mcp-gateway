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
