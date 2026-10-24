package config_test

import (
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/config"
)

func TestFederationCallTimeoutDefault(t *testing.T) {
	cfg, err := config.Load(envFrom(nil))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.FederationCallTimeout != 30*time.Second || config.DefaultFederationCallTimeout != 30*time.Second {
		t.Errorf("FederationCallTimeout = %v (default const %v), want 30s", cfg.FederationCallTimeout, config.DefaultFederationCallTimeout)
	}
}

func TestFederationCallTimeoutFromEnvAndFile(t *testing.T) {
	cfg, err := config.Load(envFrom(map[string]string{"GATEWAY_FEDERATION_CALL_TIMEOUT": "5m"}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.FederationCallTimeout != 5*time.Minute {
		t.Errorf("env: FederationCallTimeout = %v, want 5m", cfg.FederationCallTimeout)
	}

	p := writeFile(t, "federation_call_timeout: 3m\n")
	cfg, err = config.Load(envFrom(map[string]string{"GATEWAY_CONFIG_FILE": p}))
	if err != nil {
		t.Fatalf("Load file: %v", err)
	}
	if cfg.FederationCallTimeout != 3*time.Minute {
		t.Errorf("file: FederationCallTimeout = %v, want 3m", cfg.FederationCallTimeout)
	}

	cfg, err = config.Load(envFrom(map[string]string{"GATEWAY_CONFIG_FILE": p, "GATEWAY_FEDERATION_CALL_TIMEOUT": "15m"}))
	if err != nil {
		t.Fatalf("Load file+env: %v", err)
	}
	if cfg.FederationCallTimeout != config.MaxFederationCallTimeout || config.MaxFederationCallTimeout != 15*time.Minute {
		t.Errorf("env over file: FederationCallTimeout = %v, want the 15m maximum", cfg.FederationCallTimeout)
	}
}

func TestFederationCallTimeoutInvalid(t *testing.T) {
	for name, v := range map[string]string{
		"not a duration": "3 minutes",
		"no unit":        "300",
		"zero":           "0s",
		"negative":       "-1m",
		"above maximum":  "16m",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := config.Load(envFrom(map[string]string{"GATEWAY_FEDERATION_CALL_TIMEOUT": v}))
			if err == nil {
				t.Fatalf("GATEWAY_FEDERATION_CALL_TIMEOUT=%q: expected an error", v)
			}
			if !strings.Contains(strings.ToLower(err.Error()), "federation_call_timeout") {
				t.Errorf("error %q does not name the setting", err)
			}
		})
	}
}
