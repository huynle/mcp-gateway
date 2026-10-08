// Command gateway runs the Team MCP Gateway service.
//
// It loads configuration (GATEWAY_* environment variables plus an optional
// YAML file), sets up structured logging, opens the PostgreSQL store when
// GATEWAY_DATABASE_URL is set (refusing to start on a schema version
// mismatch; migrations are cmd/migrate's job), exposes /healthz and /readyz
// mounts the portal and company sign-in routes when a database is
// configured, mounts the token pages and the /mcp endpoint (stateless
// Streamable HTTP behind the token authenticator's BearerMiddleware, tools
// from the connector registry), and shuts down gracefully on
// SIGTERM/SIGINT, draining in-flight requests for the configured period.
// Later tasks register connectors on the registry, insert pipeline stages
// and mount OAuth on the same mux.
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
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/fake"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/mcp"
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

	var portalHandler, mcpHandler http.Handler
	if st != nil {
		rec := audit.NewStoreRecorder(st)
		tokenSvc, err := tokens.New(tokens.Config{SignInMaxAge: cfg.TokenSignInMaxAge}, tokens.NewPostgresStore(st), metrics, rec, log)
		if err != nil {
			return fmt.Errorf("tokens: %w", err)
		}
		portalHandler, err = newPortal(cfg, identity.NewPostgresStore(st), rec, tokenSvc, log)
		if err != nil {
			return err
		}
		mcpHandler, err = newMCP(cfg, tokenSvc, rec, metrics, log)
		if err != nil {
			return err
		}
	} else {
		log.Warn("no database: portal, sign-in, tokens and /mcp are not mounted")
	}

	log.Info("gateway starting", "version", version, "addr", cfg.ListenAddr, "drain", cfg.DrainTimeout)
	handler := observability.RequestID(metrics.HTTPMiddleware(newMux(readiness, portalHandler, mcpHandler)))
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

// newMCP builds the /mcp endpoint: the connector registry, the account
// source, the per-user / per-app rate limiter, the default pipeline
// (authenticate, audit, resolve, strip, account, ratelimit, dispatch)
// with the store-backed audit recorder, and the token authenticator with
// the production failure limiter. The fake connector is registered only
// when GATEWAY_ENABLE_FAKE_CONNECTOR=true; the real connectors register
// here too. The account source is an in-memory one until the connections
// task supplies the store-backed implementation. Later tasks obtain the
// pipeline here to insert their stages.
func newMCP(cfg config.Config, auth tokens.Authenticator, rec audit.Recorder, metrics *observability.Metrics, log *slog.Logger) (http.Handler, error) {
	registry := connectors.NewRegistry()
	accounts, err := registerConnectors(cfg, registry, log)
	if err != nil {
		return nil, fmt.Errorf("connectors: %w", err)
	}
	limiter := mcp.NewRateLimiter(mcp.RateLimitConfig{UserPerMinute: cfg.RateUserPerMin, AppPerMinute: cfg.RateAppPerMin})
	pipeline, err := mcp.DefaultPipeline(mcp.PipelineDeps{
		Registry: registry, RateLimiter: limiter, Accounts: accounts, Audit: rec, Metrics: metrics, Log: log,
	})
	if err != nil {
		return nil, fmt.Errorf("mcp: %w", err)
	}
	h, err := mcp.Handler(mcp.Options{
		Registry:      registry,
		Pipeline:      pipeline,
		Authenticator: auth,
		Auth: tokens.MiddlewareOptions{
			Limiter: tokens.NewFailureLimiter(tokens.DefaultFailureBurst, tokens.DefaultFailureWindow),
			Metrics: metrics,
			Log:     log,
		},
		BaseURL: cfg.BaseURL,
		MaxBody: cfg.MCPMaxBody,
		Log:     log,
		Version: version,
	})
	if err != nil {
		return nil, fmt.Errorf("mcp: %w", err)
	}
	log.Info("mcp endpoint ready", "path", "/mcp", "tools", len(registry.List()), "body_limit", cfg.MCPMaxBody,
		"stages", pipeline.Names(), "rate_user_per_min", cfg.RateUserPerMin, "rate_app_per_min", cfg.RateAppPerMin)
	return h, nil
}

// registerConnectors fills the registry and returns the account source the
// account stage consults. Today that source is a static, in-memory one
// (the connections task replaces it with the connections table); the
// fake connector, when enabled, seeds one company account per user on
// first use so a local harness can call its tools right away.
func registerConnectors(cfg config.Config, registry *connectors.Registry, log *slog.Logger) (connectors.AccountSource, error) {
	static := connectors.NewStaticAccountSource()
	if !cfg.EnableFakeConnector {
		return static, nil
	}
	f := fake.New(fake.Options{Accounts: static, AutoAccount: true})
	if err := connectors.RegisterConnector(registry, f, f.Accounts()); err != nil {
		return nil, err
	}
	log.Warn("fake connector registered (GATEWAY_ENABLE_FAKE_CONNECTOR=true): development only", "app", fake.App)
	return f.Accounts(), nil
}

// newMux builds the public HTTP routes. Health endpoints are unauthenticated
// and stay outside the portal; /mcp (when mounted) takes every method so
// the SDK can answer 405 for the ones a stateless server does not serve;
// the portal (when mounted) owns everything else, including /auth/ and
// /static/.
func newMux(readiness *observability.Readiness, portalHandler, mcpHandler http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", observability.Liveness())
	mux.Handle("GET /readyz", readiness)
	if mcpHandler != nil {
		mux.Handle("/mcp", mcpHandler)
	}
	if portalHandler != nil {
		mux.Handle("/", portalHandler)
	}
	return mux
}
