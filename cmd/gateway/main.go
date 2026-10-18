// Command gateway runs the Team MCP Gateway service.
//
// It loads configuration (GATEWAY_* environment variables plus an optional
// YAML file), sets up structured logging, opens the PostgreSQL store when
// GATEWAY_DATABASE_URL is set (refusing to start on a schema version
// mismatch; migrations are cmd/migrate's job), exposes /healthz and /readyz
// mounts the portal and company sign-in routes when a database is
// configured, mounts the token, connection, harness and admin role /
// vendor app pages, the MCP OAuth authorization server (discovery,
// registration, authorize, token, revoke, JWKS) and the /mcp endpoint
// (stateless Streamable HTTP behind the composite bearer authenticator:
// generated tokens and OAuth access tokens, tools from the connector
// registry filtered and decided by the compiled policy), and shuts down
// gracefully on SIGTERM/SIGINT, draining in-flight requests for the
// configured period. Later tasks register connectors on the registry and
// insert pipeline stages.
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

	"github.com/huynle/mcp-gateway/internal/approvals"
	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/authserver"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/fake"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/ledger"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/permissions"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/portal"
	"github.com/huynle/mcp-gateway/internal/server"
	"github.com/huynle/mcp-gateway/internal/settings"
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
	keys, err := openKeyProvider(readiness, log)
	if err != nil {
		return err
	}
	metrics := observability.NewMetrics()
	go func() {
		if err := observability.ServeMetrics(ctx, "", metrics.Handler()); err != nil {
			log.Error("metrics listener stopped", "error", err)
		}
	}()

	var portalHandler, mcpHandler, slackHandler http.Handler
	var muxExtras []muxExtra
	var ledgerSvc *ledger.Service
	var authSvc *authserver.Service
	if st != nil {
		rec := audit.NewStoreRecorder(st)
		tokenSvc, err := tokens.New(tokens.Config{SignInMaxAge: cfg.TokenSignInMaxAge}, tokens.NewPostgresStore(st), metrics, rec, log)
		if err != nil {
			return fmt.Errorf("tokens: %w", err)
		}
		// The tool registry: built-in connectors, then user-added servers.
		// The policy validates vendor app approval modes against it.
		registry := connectors.NewRegistry()
		policySvc, err := policy.New(policy.NewPostgresStore(st), policy.Options{
			Audit: rec, Metrics: metrics, Log: log, MaxAge: cfg.PolicyReloadInterval, Tools: registry,
		})
		if err != nil {
			return fmt.Errorf("policy: %w", err)
		}
		var connSvc *connections.Service
		if keys != nil {
			connSvc, err = connections.New(connections.Config{BaseURL: cfg.BaseURL}, connections.NewPostgresStore(st), keys, connections.Options{
				Audit: rec, Policy: connections.PolicyAllowance{Service: policySvc}, Metrics: metrics, Log: log,
			})
			if err != nil {
				return fmt.Errorf("connections: %w", err)
			}
			// Grant more access, the connect flow's scope checks and
			// list_accounts' hints read the tools' scopes from the
			// registry and the user's visible tools from the policy.
			connSvc.SetToolCatalog(registry, connections.PolicyAllowance{Service: policySvc})
		} else {
			log.Warn("no key provider: app connections are not mounted (tokens cannot be encrypted)")
		}
		accounts, err := registerConnectors(cfg, registry, connSvc, log)
		if err != nil {
			return fmt.Errorf("connectors: %w", err)
		}
		// Who may add MCP servers, and each user's "Gateway management
		// tools" setting (internal/permissions; decision bnneszc1).
		perms := permissions.NewPostgres(st, permissions.Options{Audit: rec, Log: log})
		rateSvc := settings.New(settings.NewPostgresStore(st), settings.Options{
			DefaultUserPerMinute: cfg.RateUserPerMin, DefaultAppPerMinute: cfg.RateAppPerMin, Audit: rec, Log: log,
		})
		if err := rateSvc.Refresh(ctx); err != nil {
			return fmt.Errorf("rate settings: %w", err)
		}
		limiter := mcp.NewRateLimiter(mcp.RateLimitConfig{UserPerMinute: cfg.RateUserPerMin, AppPerMinute: cfg.RateAppPerMin, Provider: rateSvc})
		// User-added MCP servers: their tools join the registry after the
		// built-in connectors (federation.go).
		fed, err := newFederation(ctx, cfg, st, keys, registry, policySvc, perms, metrics, log)
		if err != nil {
			return err
		}
		// The gateway.* management tools (behind the permission and the
		// per-user setting; gatewaytools).
		gw, err := newGatewayTools(fed, st, registry, perms, rateSvc, policySvc, connSvc, rec, cfg.BaseURL, log)
		if err != nil {
			return err
		}
		if cfg.RelayEnabled() {
			if fed == nil {
				log.Warn("GATEWAY_RELAY_* set but user-added MCP servers are not mounted: no tunnel relay")
			} else if err := serveRelay(ctx, cfg, fed, log); err != nil {
				return err
			}
		}
		accounts = gw.Accounts(federationAccounts(fed, accounts))
		muxExtras = append(muxExtras, withFederationRoutes(fed))
		slackNotifier, err := newSlackNotifier(cfg, connSvc, log)
		if err != nil {
			return err
		}
		approvalSvc, err := newApprovals(cfg, st, keys, rec, metrics, getenv, log, slackNotifier)
		if err != nil {
			return err
		}
		if slackNotifier != nil && approvalSvc != nil {
			slackNotifier.SetArguments(approvalSvc)
		}
		slackHandler, err = newSlackInteractions(approvalSvc, connSvc, rec, log)
		if err != nil {
			return err
		}
		ledgerSvc, err = newLedger(cfg, ledger.NewPostgresStore(st), registry, approvalSvc, rec, metrics, getenv, log)
		if err != nil {
			return err
		}
		authSvc, err = newAuthServer(cfg, st, keys, rec, metrics, getenv, log)
		if err != nil {
			return err
		}
		// My account's switch goes through the gate so switching off
		// takes effect at once.
		portalHandler, err = newPortalWithAccount(cfg, identity.NewPostgresStore(st), rec, tokenSvc, policySvc, approvalSvc, connSvc, registry, gw.Setting(perms), rateSvc, newAccountLifecycle(st, fed, log), log, withOperationsPage(ledgerSvc), withHarnessPages(authSvc), withFederationPages(fed, st, cfg.BaseURL, policySvc, rec), withFederationAdmin(fed, st, rec))
		if err != nil {
			return err
		}
		mcpHandler, err = newMCPWithResources(cfg, registry, accounts, composeAuthenticator(tokenSvc, authSvc), gw.Decider(federationDecider(fed, policySvc)), approvalSvc, rec, metrics, log,
			federationResources(fed, policySvc), limiter, withFederationPrecheck(fed, log), withLedgerStage(ledgerSvc))
		if err != nil {
			return err
		}
		jobList := append(ledgerJobs(ledgerSvc), authServerJobs(authSvc)...)
		if approvalSvc != nil {
			jobList = append(jobList, approvalSvc.ExpiryJob(0))
		}
		if connSvc != nil {
			jobList = append(jobList, connSvc.KeepAliveJob())
		}
		purge, err := audit.NewPurgeJob(st, audit.PurgeOptions{Retention: cfg.AuditRetention, Recorder: rec, Metrics: metrics, Log: log})
		if err != nil {
			return err
		}
		jobList = append(jobList, purge)
		if len(jobList) > 0 {
			if _, err := startJobs(ctx, st, log, jobList...); err != nil {
				return err
			}
		}
		if cur, err := policySvc.Current(ctx); err != nil {
			// Not fatal: the service keeps retrying on use and every call
			// fails closed until the policy loads.
			log.Error("policy not loaded at startup; tool calls fail closed until it is", "error", err)
		} else {
			log.Info("policy ready", "version", cur.Version, "version_id", cur.ID)
		}
	} else {
		log.Warn("no database: portal, sign-in, tokens and /mcp are not mounted")
	}

	log.Info("gateway starting", "version", version, "addr", cfg.ListenAddr, "drain", cfg.DrainTimeout)
	handler := observability.RequestID(metrics.HTTPMiddleware(newMux(readiness, portalHandler, mcpHandler, slackHandler, append(muxExtras, withOAuthRoutes(authSvc))...)))
	srv := server.New(handler, cfg.DrainTimeout, log)
	err = srv.ListenAndServe(ctx, cfg.ListenAddr)
	markInFlightUnknown(ledgerSvc, log)
	switch {
	case err == nil:
		log.Info("gateway stopped")
		return nil
	case errors.Is(err, server.ErrDrainTimeout):
		// The process did what it was asked; the cut-off calls are visible in
		// the warn log and as unknown ledger operations (markInFlightUnknown).
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
	readiness.Register("schema", st.SchemaVersionReady)
	log.Info("database ready", "schema_version", store.ExpectedSchemaVersion)
	return st, nil
}

// openKeyProvider builds the envelope-encryption key provider selected by
// GATEWAY_KEY_PROVIDER / GATEWAY_KEY_FILE and registers the "key-provider"
// readiness check. With neither variable set the gateway runs without one
// (foundation-only mode, mirroring openStore) and returns (nil, nil); the
// modules that encrypt (approvals and connections) are then not wired.
func openKeyProvider(readiness *observability.Readiness, log *slog.Logger) (crypto.KeyProvider, error) {
	if os.Getenv(crypto.EnvKeyProvider) == "" && os.Getenv(crypto.EnvKeyFile) == "" {
		log.Warn("no GATEWAY_KEY_PROVIDER or GATEWAY_KEY_FILE: running without a key provider")
		return nil, nil
	}
	kp, err := crypto.NewProviderFromEnv(os.Getenv)
	if err != nil {
		return nil, fmt.Errorf("key provider: %w", err)
	}
	readiness.Register("key-provider", crypto.ReadinessCheck(kp))
	log.Info("key provider ready", "provider", os.Getenv(crypto.EnvKeyProvider))
	return kp, nil
}

// newPortal builds the identity service and the portal over the given
// store, mounts the activity, audit, token and admin role pages, and
// registers the token service's disable hook so disabling a user revokes
// their tokens in the same transaction. Providers come from
// GATEWAY_OIDC_PROVIDERS; with none configured the sign-in page says so
// instead of failing startup.
//
//nolint:unparam // the form without the account lifecycle (tests); production calls newPortalWithAccount
func newPortal(cfg config.Config, st identity.Store, reader audit.Reader, tokenSvc *tokens.Service, policySvc *policy.Service, approvalSvc *approvals.Service, connSvc *connections.Service, registry *connectors.Registry, gatewayTools portal.GatewayTools, rateSettings portal.RateSettings, log *slog.Logger, extras ...portalExtra) (http.Handler, error) {
	return newPortalWithAccount(cfg, st, reader, tokenSvc, policySvc, approvalSvc, connSvc, registry, gatewayTools, rateSettings, nil, log, extras...)
}

// newPortalWithAccount is newPortal with the account lifecycle (data
// export, account deletion; account.go): lifecycle builds the service over
// the portal's identity service (nil: neither is mounted).
func newPortalWithAccount(cfg config.Config, st identity.Store, reader audit.Reader, tokenSvc *tokens.Service, policySvc *policy.Service, approvalSvc *approvals.Service, connSvc *connections.Service, registry *connectors.Registry, gatewayTools portal.GatewayTools, rateSettings portal.RateSettings, lifecycle accountLifecycle, log *slog.Logger, extras ...portalExtra) (http.Handler, error) {
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
	legal, err := portal.LegalFromEnv(os.Getenv)
	if err != nil {
		return nil, fmt.Errorf("portal: %w", err)
	}
	p.SetLegal(legal) // homepage, /privacy, /terms, /support (docs/public-launch.md)
	if missing := legal.Placeholders(); len(missing) > 0 || legal.Draft {
		log.Warn("public legal pages show placeholders or the draft marker", "unset", missing, "draft", legal.Draft)
	}
	if gatewayTools != nil {
		p.SetGatewayTools(gatewayTools) // My account: "Gateway management tools"
	}
	if rateSettings != nil {
		p.SetRateSettings(rateSettings)
	}
	if lifecycle != nil {
		p.SetAccount(lifecycle(svc)) // My account: "Your data"; /admin/users: Delete
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
	if approvalSvc != nil {
		approvals.NewPortal(approvalSvc, session, log).Mount(p.MountUser)
	}
	adminSession := func(r *http.Request) (string, string, bool) {
		pr := identity.PrincipalFrom(r.Context())
		if pr == nil {
			return "", "", false
		}
		return pr.UserID, pr.CSRFToken, pr.IsAdmin()
	}
	policy.NewPortal(policySvc, registry, adminSession, log).Mount(p.MountAdmin)
	svc.OnDisable(tokenSvc.DisableHook())
	if connSvc != nil {
		cp := connections.NewPortal(connSvc, adminSession, log)
		// Settings → Vendor apps → <vendor>: Tool approvals (Ask / Auto).
		cp.SetToolApprovals(policySvc)
		cp.MountUser(p.MountUser)    // /connections, /connections/{id}/disconnect
		cp.MountConnect(p.MountUser) // /connect/{vendor}/start, /connect/{vendor}/callback
		cp.MountAdmin(p.MountAdmin)  // /admin/vendor-apps...
		svc.OnDisable(connSvc.DisableHook())
	}
	for _, extra := range extras {
		extra(svc, portalMount(p), session, log)
	}
	return p.Handler(), nil
}

// portalExtra mounts a module's user pages (the ledger's /operations, the
// authorization server's authorize / consent / harnesses pages) and may
// register disable hooks on the identity service.
type portalExtra func(idSvc *identity.Service, mountUser func(string, http.Handler), session func(*http.Request) (string, string), log *slog.Logger)

// muxExtra registers public routes (the OAuth endpoints) on the top-level mux.
type muxExtra func(*http.ServeMux)

// mcpExtra adjusts the /mcp pipeline after the default stages are built
// (the ledger stage, which also switches the confirm handler to deferred
// consumption).
type mcpExtra func(p *mcp.Pipeline, confirm mcp.ConfirmHandler) error

// newMCP builds the /mcp endpoint over the connector registry and account
// source: the per-user / per-app rate limiter, policy-driven visibility,
// the default pipeline (authenticate, audit, resolve, strip, account,
// policy, ratelimit, dispatch) with the store-backed audit recorder and
// the approvals confirm handler (decision s0p05diu; the default handler,
// which only answers "approval required", when approvals are not
// available), and the token authenticator with the production failure
// limiter. Later tasks obtain the pipeline here to insert their stages.
//
//nolint:unparam // the no-resources form; production serves resources through newMCPWithResources
func newMCP(cfg config.Config, registry *connectors.Registry, accounts connectors.AccountSource, auth tokens.Authenticator, policySvc mcp.Decider, approvalSvc *approvals.Service, rec audit.Recorder, metrics *observability.Metrics, log *slog.Logger, extras ...mcpExtra) (http.Handler, error) {
	return newMCPWithResources(cfg, registry, accounts, auth, policySvc, approvalSvc, rec, metrics, log, nil, nil, extras...)
}

// newMCPWithResources is newMCP that also serves resources/* and
// prompts/* from resources (the federation's user-added servers; nil
// serves neither), audited by rec and rate limited by the same limiter as
// tool calls.
func newMCPWithResources(cfg config.Config, registry *connectors.Registry, accounts connectors.AccountSource, auth tokens.Authenticator, policySvc mcp.Decider, approvalSvc *approvals.Service, rec audit.Recorder, metrics *observability.Metrics, log *slog.Logger, resources mcp.ResourceProvider, limiter *mcp.TokenBucketLimiter, extras ...mcpExtra) (http.Handler, error) {
	if limiter == nil {
		limiter = mcp.NewRateLimiter(mcp.RateLimitConfig{UserPerMinute: cfg.RateUserPerMin, AppPerMinute: cfg.RateAppPerMin})
	}
	visibility := mcp.PolicyVisibility{Decider: policySvc, Log: log}
	confirm := mcp.DefaultConfirmHandler()
	if approvalSvc != nil {
		confirm = approvals.NewConfirmHandler(approvalSvc, metrics, log)
	}
	pipeline, err := mcp.DefaultPipeline(mcp.PipelineDeps{
		Registry: registry, Visibility: visibility, RateLimiter: limiter, Accounts: accounts,
		Policy: policySvc, Confirm: confirm, Audit: rec, Metrics: metrics, Log: log, BaseURL: cfg.BaseURL,
	})
	if err != nil {
		return nil, fmt.Errorf("mcp: %w", err)
	}
	for _, extra := range extras {
		if err := extra(pipeline, confirm); err != nil {
			return nil, fmt.Errorf("mcp: %w", err)
		}
	}
	h, err := mcp.Handler(mcp.Options{
		Registry:      registry,
		Pipeline:      pipeline,
		Visibility:    visibility,
		Authenticator: auth,
		Auth: tokens.MiddlewareOptions{
			Limiter: tokens.NewFailureLimiter(tokens.DefaultFailureBurst, tokens.DefaultFailureWindow),
			Metrics: metrics,
			Log:     log,
		},
		BaseURL:     cfg.BaseURL,
		MaxBody:     cfg.MCPMaxBody,
		Log:         log,
		Version:     version,
		Resources:   resources,
		Audit:       rec,
		RateLimiter: limiter,
	})
	if err != nil {
		return nil, fmt.Errorf("mcp: %w", err)
	}
	log.Info("mcp endpoint ready", "path", "/mcp", "tools", len(registry.List()), "body_limit", cfg.MCPMaxBody,
		"stages", pipeline.Names(), "resources", resources != nil, "rate_user_per_min", cfg.RateUserPerMin, "rate_app_per_min", cfg.RateAppPerMin)
	return h, nil
}

// registerConnectors fills the registry (which the admin role editor also
// reads for its tool grid) and returns the account source the account
// stage consults: the connections service (accounts are the user's
// connections rows) when it is available, else a static, in-memory one.
// The fake connector, registered only when GATEWAY_ENABLE_FAKE_CONNECTOR=true,
// gets one company account per user on first use so a local harness can
// call its tools right away: a real connections row seeded through the
// connections service when it is mounted (newFakeAccountSource, quirk
// enqgtw5y), else the fake's own in-memory source; the composite source
// routes app "fake" to it and every other app to the connections table.
// The real connectors register here too, with their vendor's Binder
// (connSvc.RegisterBinder) and app mapping (connSvc.MapApp).
func registerConnectors(cfg config.Config, registry *connectors.Registry, connSvc *connections.Service, log *slog.Logger) (connectors.AccountSource, error) {
	sources := routedAccountSource{byApp: map[string]connectors.AccountSource{}, fallback: connectors.NewStaticAccountSource()}
	if connSvc != nil {
		sources.fallback = connSvc
		if err := registerGitHub(cfg, registry, connSvc, log); err != nil {
			return nil, err
		}
		if err := registerAtlassian(cfg, registry, connSvc, log); err != nil {
			return nil, err
		}
		if err := registerMicrosoft(cfg, registry, connSvc, log); err != nil {
			return nil, err
		}
		if err := registerSlack(cfg, registry, connSvc, log); err != nil {
			return nil, err
		}
		if err := registerGoogle(cfg, registry, connSvc, log); err != nil {
			return nil, err
		}
	}
	if cfg.EnableFakeConnector {
		f := fake.New(fake.Options{AutoAccount: true})
		src := newFakeAccountSource(f, connSvc)
		if err := connectors.RegisterConnector(registry, f, src); err != nil {
			return nil, err
		}
		sources.byApp[fake.App] = src
		log.Warn("fake connector registered (GATEWAY_ENABLE_FAKE_CONNECTOR=true): development only", "app", fake.App, "accounts_backed_by_connections", connSvc != nil)
	}
	return sources, nil
}

// routedAccountSource sends each app to its own account source and
// everything else to the fallback.
type routedAccountSource struct {
	byApp    map[string]connectors.AccountSource
	fallback connectors.AccountSource
}

func (r routedAccountSource) ListAccounts(ctx context.Context, userID, app string) ([]connectors.Account, error) {
	if src, ok := r.byApp[app]; ok {
		return src.ListAccounts(ctx, userID, app)
	}
	return r.fallback.ListAccounts(ctx, userID, app)
}

// newMux builds the public HTTP routes. Health endpoints are unauthenticated
// and stay outside the portal; /mcp (when mounted) takes every method so
// the SDK can answer 405 for the ones a stateless server does not serve;
// /slack/interactions (when mounted) is Slack's signed button-press
// callback, outside the portal's session checks; the portal (when
// mounted) owns everything else, including /auth/ and /static/.
func newMux(readiness *observability.Readiness, portalHandler, mcpHandler, slackHandler http.Handler, extras ...muxExtra) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", observability.Liveness())
	mux.Handle("GET /readyz", readiness)
	for _, extra := range extras {
		extra(mux)
	}
	if mcpHandler != nil {
		mux.Handle("/mcp", mcpHandler)
	}
	if slackHandler != nil {
		mux.Handle("POST /slack/interactions", slackHandler)
	}
	if portalHandler != nil {
		mux.Handle("/", portalHandler)
	}
	return mux
}
