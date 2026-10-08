// Command gateway runs the Team MCP Gateway service.
//
// It loads configuration (GATEWAY_* environment variables plus an optional
// YAML file), sets up structured logging, exposes /healthz and /readyz and
// shuts down gracefully on SIGTERM/SIGINT, draining in-flight requests for the
// configured period. Later tasks mount /mcp, OAuth, the portal and metrics on
// the same mux.
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
	// Later modules register checks here, e.g.:
	//   readiness.Register("database", store.Ping)
	//   readiness.Register("schema", store.SchemaVersionMatches)
	//   readiness.Register("key-provider", crypto.ProviderReachable)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

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

// newMux builds the public HTTP routes. Health endpoints are unauthenticated.
func newMux(readiness *observability.Readiness) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", observability.Liveness())
	mux.Handle("GET /readyz", readiness)
	return mux
}
