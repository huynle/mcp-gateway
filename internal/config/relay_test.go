package config_test

import (
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/config"
)

const relaySecret = "0123456789abcdef0123456789abcdef-relay"

func TestRelayDisabledByDefault(t *testing.T) {
	cfg, err := config.Load(envFrom(nil))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.RelayEnabled() || cfg.RelayListenAddr != "" || cfg.RelayAdvertiseAddr != "" || cfg.RelaySecret != "" {
		t.Fatalf("relay config by default: %+v", cfg)
	}
}

func TestRelayFromEnv(t *testing.T) {
	cfg, err := config.Load(envFrom(map[string]string{
		"GATEWAY_RELAY_LISTEN_ADDR":    " :18081 ",
		"GATEWAY_RELAY_ADVERTISE_ADDR": "http://10.42.0.7:18081/",
		"GATEWAY_RELAY_SECRET":         relaySecret,
	}))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.RelayEnabled() || cfg.RelayListenAddr != ":18081" || cfg.RelayAdvertiseAddr != "http://10.42.0.7:18081" || cfg.RelaySecret != relaySecret {
		t.Fatalf("relay config: listen %q advertise %q enabled %v", cfg.RelayListenAddr, cfg.RelayAdvertiseAddr, cfg.RelayEnabled())
	}
}

func TestRelayValidation(t *testing.T) {
	full := map[string]string{
		"GATEWAY_RELAY_LISTEN_ADDR":    ":18081",
		"GATEWAY_RELAY_ADVERTISE_ADDR": "http://10.42.0.7:18081",
		"GATEWAY_RELAY_SECRET":         relaySecret,
	}
	for name, change := range map[string]map[string]string{
		"no listen":          {"GATEWAY_RELAY_LISTEN_ADDR": ""},
		"no advertise":       {"GATEWAY_RELAY_ADVERTISE_ADDR": ""},
		"no secret":          {"GATEWAY_RELAY_SECRET": ""},
		"short secret":       {"GATEWAY_RELAY_SECRET": "too-short"},
		"advertise path":     {"GATEWAY_RELAY_ADVERTISE_ADDR": "http://10.42.0.7:18081/relay"},
		"advertise scheme":   {"GATEWAY_RELAY_ADVERTISE_ADDR": "tcp://10.42.0.7:18081"},
		"advertise userinfo": {"GATEWAY_RELAY_ADVERTISE_ADDR": "http://u:p@10.42.0.7:18081"},
		"listen = public":    {"GATEWAY_RELAY_LISTEN_ADDR": ":18080"},
	} {
		env := map[string]string{}
		for k, v := range full {
			env[k] = v
		}
		for k, v := range change {
			env[k] = v
		}
		_, err := config.Load(envFrom(env))
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), relaySecret) {
			t.Errorf("%s: the error echoes the secret", name)
		}
	}
}
