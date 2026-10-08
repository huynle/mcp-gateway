// Command gateway runs the Team MCP Gateway service.
//
// It loads configuration (GATEWAY_* environment variables plus an optional
// YAML file), sets up structured logging, opens the PostgreSQL store when
// GATEWAY_DATABASE_URL is set (refusing to start on a schema version
// mismatch; migrations are cmd/migrate's job), exposes /healthz and /readyz
// mounts the portal and company sign-in routes when a database is
// configured, mounts the token pages and wires the token authenticator
// (whose BearerMiddleware the /mcp endpoint will use), and shuts down
// gracefully on SIGTERM/SIGINT, draining in-flight requests for the
// configured period. Later tasks mount /mcp and OAuth on the same mux.
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

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/portal"
	"github.com/huynle/mcp-gateway/internal/server"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/tokens"
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
	if err := openKeyProvider(readiness, log); err != nil {
		return err
	}
	metrics := observability.NewMetrics()
	go func() {
		if err := observability.ServeMetrics(ctx, "", metrics.Handler()); err != nil {
			log.Error("metrics listener stopped", "error", err)
		}
	}()

	var recorder audit.Recorder = audit.NopRecorder{}
	var portalHandler http.Handler
	var authenticator tokens.Authenticator
	if st != nil {
		rec := audit.NewStoreRecorder(st)
		recorder = rec
		tokenSvc, err := tokens.New(tokens.Config{SignInMaxAge: cfg.TokenSignInMaxAge}, tokens.NewPostgresStore(st), metrics, rec, log)
		if err != nil {
			return fmt.Errorf("tokens: %w", err)
		}
		authenticator = tokenSvc
		portalHandler, err = newPortal(cfg, identity.NewPostgresStore(st), rec, tokenSvc, log)
		if err != nil {
			return err
		}
	} else {
		log.Warn("no database: portal, sign-in and tokens are not mounted")
	}
	_ = recorder      // handed to the MCP pipeline once it exists
	_ = authenticator // /mcp wraps itself in tokens.BearerMiddleware(authenticator, ...) once it exists

	log.Info("gateway starting", "version", version, "addr", cfg.ListenAddr, "drain", cfg.DrainTimeout)
	handler := observability.RequestID(metrics.HTTPMiddleware(newMux(readiness, portalHandler)))
	srv := server.New(handler, cfg.DrainTimeout, log)
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

// openKeyProvider builds the envelope-encryption key provider selected by
// GATEWAY_KEY_PROVIDER / GATEWAY_KEY_FILE and registers the "key-provider"
// readiness check. With neither variable set the gateway runs without one
// (foundation-only mode, mirroring openStore); modules that need encryption
// are not wired yet, so nothing else depends on the provider here.
func openKeyProvider(readiness *observability.Readiness, log *slog.Logger) error {
	if os.Getenv(crypto.EnvKeyProvider) == "" && os.Getenv(crypto.EnvKeyFile) == "" {
		log.Warn("no GATEWAY_KEY_PROVIDER or GATEWAY_KEY_FILE: running without a key provider")
		return nil
	}
	kp, err := crypto.NewProviderFromEnv(os.Getenv)
	if err != nil {
		return fmt.Errorf("key provider: %w", err)
	}
	readiness.Register("key-provider", crypto.ReadinessCheck(kp))
	log.Info("key provider ready", "provider", os.Getenv(crypto.EnvKeyProvider))
	return nil
}

// newPortal builds the identity service and the portal over the given
// store, mounts the activity, audit and token pages, and registers the
// token service's disable hook so disabling a user revokes their tokens in
// the same transaction. Providers come from GATEWAY_OIDC_PROVIDERS; with
// none configured the sign-in page says so instead of failing startup.
func newPortal(cfg config.Config, st identity.Store, reader audit.Reader, tokenSvc *tokens.Service, log *slog.Logger) (http.Handler, error) {
	svc, err := identity.New(identity.FromConfig(cfg), st, log)
	if err != nil {
		return nil, fmt.Errorf("identity: %w", err)
	}
	if len(cfg.OIDCProviders) == 0 {
		log.Warn("no GATEWAY_OIDC_PROVIDERS configured: nobody can sign in")
	}
	for _, p := range svc.Providers() {
		log.Info("identity provider configured", "provider", p.Name, "display_name", p.DisplayName)
	}
	p, err := portal.New(svc, log)
	if err != nil {
		return nil, fmt.Errorf("portal: %w", err)
	}
	who := func(r *http.Request) (string, bool) {
		pr := identity.PrincipalFrom(r.Context())
		if pr == nil {
			return "", false
		}
		return pr.UserID, pr.IsAdmin()
	}
	p.MountUser("GET /activity", audit.ActivityHandler(reader, who))
	p.MountAdmin("GET /admin/audit", audit.AdminSearchHandler(reader, who))
	session := func(r *http.Request) (string, string) {
		pr := identity.PrincipalFrom(r.Context())
		if pr == nil {
			return "", ""
		}
		return pr.UserID, pr.CSRFToken
	}
	tokens.NewPortal(tokenSvc, session, cfg.BaseURL, log).Mount(p.MountUser)
	svc.OnDisable(tokenSvc.DisableHook())
	return p.Handler(), nil
}

// newMux builds the public HTTP routes. Health endpoints are unauthenticated
// and stay outside the portal; the portal (when mounted) owns everything
// else, including /auth/ and /static/.
func newMux(readiness *observability.Readiness, portalHandler http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", observability.Liveness())
	mux.Handle("GET /readyz", readiness)
	if portalHandler != nil {
		mux.Handle("/", portalHandler)
	}
	return mux
}
