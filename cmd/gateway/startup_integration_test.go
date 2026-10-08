//go:build integration

package main

import (
	"errors"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
)

// The store package's integration tests own the migrated test database; this
// test points the gateway at the server's maintenance database ("postgres"),
// which is reachable but has never been migrated, and expects startup to
// refuse it.
func TestIntegrationStartupRefusesSchemaMismatch(t *testing.T) {
	raw := os.Getenv("GATEWAY_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("GATEWAY_TEST_DATABASE_URL not set; skipping integration test")
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/postgres"
	cfg := config.Config{DatabaseURL: u.String(), JobsDatabaseURL: u.String()}

	readiness := observability.NewReadiness(time.Second)
	st, err := openStore(t.Context(), cfg, readiness, slog.New(slog.DiscardHandler))
	if err == nil {
		st.Close()
		t.Fatal("openStore accepted a database without the gateway schema")
	}
	if !errors.Is(err, store.ErrSchemaVersionMismatch) && !strings.Contains(err.Error(), "schema") {
		t.Errorf("error = %v, want a schema version error", err)
	}
	if _, ready := readiness.Run(t.Context()); !ready {
		t.Error("a refused store must not leave readiness checks registered")
	}
}
