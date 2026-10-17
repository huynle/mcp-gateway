package main

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func envFrom(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestResolveURLPrefersMigrateVariable(t *testing.T) {
	got, err := resolveURL(envFrom(map[string]string{
		"GATEWAY_MIGRATE_DATABASE_URL": "postgres://owner@db/gateway",
		"GATEWAY_DATABASE_URL":         "postgres://gateway_app@db/gateway",
	}))
	if err != nil || got != "postgres://owner@db/gateway" {
		t.Errorf("resolveURL = %q, %v; want the migrate variable", got, err)
	}
	got, err = resolveURL(envFrom(map[string]string{"GATEWAY_DATABASE_URL": "postgres://gateway_app@db/gateway"}))
	if err != nil || got != "postgres://gateway_app@db/gateway" {
		t.Errorf("resolveURL fallback = %q, %v", got, err)
	}
	if _, err := resolveURL(envFrom(nil)); err == nil || !strings.Contains(err.Error(), "GATEWAY_MIGRATE_DATABASE_URL") {
		t.Errorf("resolveURL with nothing set = %v, want an error naming the variable", err)
	}
}

func TestRunUsageErrors(t *testing.T) {
	env := envFrom(map[string]string{"GATEWAY_DATABASE_URL": "postgres://owner@db/gateway"})
	for _, args := range [][]string{nil, {"sideways"}, {"down-to"}, {"down-to", "x"}, {"down-to", "-1"}} {
		if err := run(args, env, io.Discard); !errors.Is(err, errUsage) {
			t.Errorf("run(%v) = %v, want errUsage", args, err)
		}
	}
	// No URL: fails before any command runs.
	if err := run([]string{"up"}, envFrom(nil), io.Discard); err == nil || errors.Is(err, errUsage) {
		t.Errorf("run(up) without URL = %v, want a configuration error", err)
	}
}
