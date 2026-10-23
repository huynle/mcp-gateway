package main

import (
	"bytes"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/secrets"
)

// TestNewSecretsStaysOffUnlessEnabledAndPossible: the flag defaults off;
// an unparsable flag fails startup; with the flag on but no key provider
// or no federation the feature stays off with a warning, registers no
// tool and its extras are no-ops.
func TestNewSecretsStaysOffUnlessEnabledAndPossible(t *testing.T) {
	var logs bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logs, nil))
	cfg := config.Default()
	env := map[string]string{}
	get := func(k string) string { return env[k] }
	keys, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{1}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	vis := mcp.PolicyVisibility{}
	registry := connectors.NewRegistry()

	f, err := newSecrets(cfg, nil, keys, nil, registry, vis, nil, get, log)
	if err != nil || f != nil {
		t.Fatalf("flag unset = %v, %v", f, err)
	}
	env[secrets.EnvEnabled] = "maybe"
	if _, err := newSecrets(cfg, nil, keys, nil, registry, vis, nil, get, log); err == nil {
		t.Error("unparsable flag accepted")
	}
	env[secrets.EnvEnabled] = "true"
	if f, err := newSecrets(cfg, nil, nil, nil, registry, vis, nil, get, log); err != nil || f != nil {
		t.Errorf("no key provider = %v, %v", f, err)
	}
	if !strings.Contains(logs.String(), "no key provider") {
		t.Errorf("no warning without a key provider:\n%s", logs.String())
	}
	if f, err := newSecrets(cfg, nil, keys, nil, registry, vis, nil, get, log); err != nil || f != nil {
		t.Errorf("no federation = %v, %v", f, err)
	}
	if !strings.Contains(logs.String(), "user-added MCP servers are not mounted") {
		t.Errorf("no warning without a federation:\n%s", logs.String())
	}
	if _, ok := registry.Get(secrets.App + "." + secrets.ToolRequest); ok {
		t.Error("secrets.request registered while the feature is off")
	}

	// Off: the extras do nothing.
	if err := withSecretStage(nil)(nil, nil); err != nil {
		t.Errorf("stage extra = %v", err)
	}
	mounted := false
	withSecretPages(nil)(nil, func(string, http.Handler) { mounted = true }, nil, log, nil)
	if mounted {
		t.Error("pages mounted while the feature is off")
	}
	if jobs := secretsJobs(nil); len(jobs) != 0 {
		t.Errorf("jobs = %v", jobs)
	}
}
