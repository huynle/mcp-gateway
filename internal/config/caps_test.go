package config_test

import (
	"testing"

	"github.com/huynle/mcp-gateway/internal/config"
)

func TestResourceCapDefaultsAndEnv(t *testing.T) {
	cfg, err := config.Load(envFrom(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c := cfg.Caps; c.Servers != 10 || c.Tunnels != 5 || c.ConnectionsPerApp != 5 || c.ConnectionsTotal != 20 || c.PendingApprovals != 50 || c.Machines != 5 {
		t.Errorf("defaults = %+v", c)
	}
	cfg, err = config.Load(envFrom(map[string]string{
		"GATEWAY_CAP_SERVERS": "3", "GATEWAY_CAP_TUNNELS": " 2 ", "GATEWAY_CAP_CONNECTIONS_PER_APP": "4",
		"GATEWAY_CAP_CONNECTIONS_TOTAL": "9", "GATEWAY_CAP_PENDING_APPROVALS": "11", "GATEWAY_CAP_MACHINES": "7",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if c := cfg.Caps; c.Servers != 3 || c.Tunnels != 2 || c.ConnectionsPerApp != 4 || c.ConnectionsTotal != 9 || c.PendingApprovals != 11 || c.Machines != 7 {
		t.Errorf("env = %+v", c)
	}
	// 0 (unlimited) is only an administrator setting, never ENV.
	for _, bad := range []map[string]string{
		{"GATEWAY_CAP_SERVERS": "0"}, {"GATEWAY_CAP_TUNNELS": "-1"}, {"GATEWAY_CAP_PENDING_APPROVALS": "many"},
		{"GATEWAY_CAP_CONNECTIONS_TOTAL": "100001"}, {"GATEWAY_CAP_MACHINES": "0"},
	} {
		if _, err := config.Load(envFrom(bad)); err == nil {
			t.Errorf("%v accepted", bad)
		}
	}
}
