// Command gateway runs the Team MCP Gateway service.
//
// It loads configuration (GATEWAY_* environment variables plus an optional
// YAML file), sets up structured logging, opens the PostgreSQL store when
// GATEWAY_DATABASE_URL is set (refusing to start on a schema version
// mismatch; migrations are cmd/migrate's job), exposes /healthz and /readyz
// and shuts down gracefully on SIGTERM/SIGINT, draining in-flight requests
// for the configured period. Later tasks mount /mcp, OAuth, the portal and
// metrics on the same mux.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/server"
	"github.com/huynle/mcp-gateway/internal/store"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

// readinessCheckTimeout bounds each registered /readyz check.
const readinessCheckTimeout = 5 * time.Second

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "gateway:", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load(os.Getenv)
	if err != nil {
		return err
	}
	log, err := observability.NewLogger(os.Stdout, cfg.LogLevel, cfg.LogFormat)
	if err != nil {
		return err
	}
	slog.SetDefault(log)

	readiness := observability.NewReadiness(readinessCheckTimeout)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	st, err := openStore(ctx, cfg, readiness, log)
	if err != nil {
		return err
	}
	if st != nil {
		defer st.Close()
	}
	// Later modules register further checks here, e.g.:
	//   readiness.Register("key-provider", crypto.ProviderReachable)

	log.Info("gateway starting", "version", version, "addr", cfg.ListenAddr, "drain", cfg.DrainTimeout)
	srv := server.New(newMux(readiness), cfg.DrainTimeout, log)
	err = srv.ListenAndServe(ctx, cfg.ListenAddr)
	switch {
	case err == nil:
		log.Info("gateway stopped")
		return nil
	case errors.Is(err, server.ErrDrainTimeout):
		// The process did what it was asked; the cut-off calls are visible in
		// the warn log and, once the ledger exists, as stale in_progress rows.
		log.Warn("gateway stopped with requests cut off", "error", err)
		return nil
	default:
		return err
	}
}

// openStore connects to PostgreSQL when cfg.DatabaseURL is set, verifies the
// schema version and registers the "database" and "schema" readiness checks.
// It returns (nil, nil) when no database is configured (foundation-only
// mode) and an error, with nothing registered, when the database is
// unreachable or at a different schema version: the process must not serve
// against a schema it was not built for, and migrating is cmd/migrate's job.
func openStore(ctx context.Context, cfg config.Config, readiness *observability.Readiness, log *slog.Logger) (*store.Store, error) {
	if cfg.DatabaseURL == "" {
		log.Warn("no GATEWAY_DATABASE_URL: running without a database")
		return nil, nil
	}
	st, err := store.New(ctx, cfg.DatabaseURL, store.WithJobsURL(cfg.JobsDatabaseURL))
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := st.SchemaVersionMatches(ctx); err != nil {
		st.Close()
		log.Error("refusing to start: database schema version does not match this binary",
			"expected", store.ExpectedSchemaVersion, "error", err)
		return nil, fmt.Errorf("schema check: %w", err)
	}
	readiness.Register("database", st.Ping)
	readiness.Register("schema", st.SchemaVersionMatches)
	log.Info("database ready", "schema_version", store.ExpectedSchemaVersion)
	return st, nil
}

// newMux builds the public HTTP routes. Health endpoints are unauthenticated.
func newMux(readiness *observability.Readiness) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", observability.Liveness())
	mux.Handle("GET /readyz", readiness)
	return mux
}
