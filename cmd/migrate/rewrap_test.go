package main

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestParseRewrapArgs(t *testing.T) {
	cases := []struct {
		args  []string
		mode  rewrapMode
		batch int
	}{
		{nil, modeRewrap, 100},
		{[]string{"--dry-run"}, modeDryRun, 100},
		{[]string{"--verify"}, modeVerify, 100},
		{[]string{"--batch", "25"}, modeRewrap, 25},
		{[]string{"--batch=7", "--dry-run"}, modeDryRun, 7},
	}
	for _, c := range cases {
		mode, batch, err := parseRewrapArgs(c.args)
		if err != nil || mode != c.mode || batch != c.batch {
			t.Errorf("parseRewrapArgs(%v) = %v, %d, %v; want %v, %d", c.args, mode, batch, err, c.mode, c.batch)
		}
	}
	for _, args := range [][]string{
		{"--dry-run", "--verify"},
		{"--batch", "0"},
		{"--batch", "-3"},
		{"--batch", "many"},
		{"--force"},
		{"extra"},
	} {
		if _, _, err := parseRewrapArgs(args); !errors.Is(err, errUsage) {
			t.Errorf("parseRewrapArgs(%v) = %v, want errUsage", args, err)
		}
	}
}

func TestResolveRewrapURL(t *testing.T) {
	got, err := resolveRewrapURL(envFrom(map[string]string{
		"GATEWAY_MIGRATE_DATABASE_URL": "postgres://owner@db/gateway",
		"GATEWAY_JOBS_DATABASE_URL":    "postgres://gateway_jobs@db/gateway",
		"GATEWAY_DATABASE_URL":         "postgres://gateway_app@db/gateway",
	}))
	if err != nil || got != "postgres://owner@db/gateway" {
		t.Errorf("resolveRewrapURL = %q, %v; want the migrate (owner) URL", got, err)
	}
	got, err = resolveRewrapURL(envFrom(map[string]string{
		"GATEWAY_JOBS_DATABASE_URL": "postgres://gateway_jobs@db/gateway",
		"GATEWAY_DATABASE_URL":      "postgres://gateway_app@db/gateway",
	}))
	if err != nil || got != "postgres://gateway_jobs@db/gateway" {
		t.Errorf("resolveRewrapURL = %q, %v; want the jobs URL", got, err)
	}
	// The request-path role is subject to row-level security: never used.
	_, err = resolveRewrapURL(envFrom(map[string]string{"GATEWAY_DATABASE_URL": "postgres://gateway_app@db/gateway"}))
	if err == nil || !strings.Contains(err.Error(), "GATEWAY_JOBS_DATABASE_URL") {
		t.Errorf("app URL only: want an error naming the variables to set, got %v", err)
	}
}

func TestRunRewrapConfigurationErrors(t *testing.T) {
	// No key provider selected: refuse before touching the database.
	err := run([]string{"rewrap"}, envFrom(map[string]string{"GATEWAY_MIGRATE_DATABASE_URL": "postgres://owner@127.0.0.1:1/none"}), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "GATEWAY_KEY_PROVIDER") {
		t.Errorf("no provider: want an error naming GATEWAY_KEY_PROVIDER, got %v", err)
	}
	// Provider selected but incomplete: the crypto package names the variable.
	err = run([]string{"rewrap"}, envFrom(map[string]string{
		"GATEWAY_MIGRATE_DATABASE_URL": "postgres://owner@127.0.0.1:1/none",
		"GATEWAY_KEY_PROVIDER":         "vault",
		"GATEWAY_VAULT_ADDR":           "http://127.0.0.1:1",
		"GATEWAY_VAULT_TOKEN":          "s.secret-token",
	}), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "GATEWAY_VAULT_TRANSIT_KEY") || strings.Contains(err.Error(), "s.secret-token") {
		t.Errorf("incomplete vault config: got %v", err)
	}
	// Bad flags are usage errors.
	if err := run([]string{"rewrap", "--dry-run", "--verify"}, envFrom(nil), io.Discard); !errors.Is(err, errUsage) {
		t.Errorf("conflicting flags: want errUsage, got %v", err)
	}
	// No usable database URL.
	err = run([]string{"rewrap"}, envFrom(map[string]string{"GATEWAY_DATABASE_URL": "postgres://gateway_app@db/gateway", "GATEWAY_KEY_PROVIDER": "file"}), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "GATEWAY_MIGRATE_DATABASE_URL") {
		t.Errorf("app URL only: got %v", err)
	}
}
