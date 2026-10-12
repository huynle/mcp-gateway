//go:build integration || e2e || security

// Package security is the security acceptance suite (Brain task kwcbub3k,
// decision bt8ukyrd: the pilot gate). It boots the whole gateway
// in-process the way cmd/gateway and test/e2e do (identity, portal,
// tokens, the OAuth authorization server, policy, connections,
// approvals, ledger, /mcp with every stage, audit) against PostgreSQL,
// with the fake connector AND the real GitHub and Slack connectors
// pointed at stub vendor servers whose answers the tests control
// (including error bodies full of secrets), and drives adversarial
// scenarios: cross-user and cross-account reach through every connector
// path, redaction under concurrent load, policy bypass attempts, rate
// limits under load, scope enforcement and portal hardening.
//
// Run with `make test-security` (GATEWAY_TEST_DATABASE_URL must point at
// a superuser; the package creates and migrates gateway_security_test).
// Every world captures the redacted gateway log and asserts at the end
// that no registered secret reached it or any audit row.
package security

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/oauth2"

	"github.com/huynle/mcp-gateway/internal/approvals"
	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/authserver"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/fake"
	"github.com/huynle/mcp-gateway/internal/connectors/github"
	slackconn "github.com/huynle/mcp-gateway/internal/connectors/slack"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/federation/connector"
	"github.com/huynle/mcp-gateway/internal/federation/gatewaytools"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/ledger"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/permissions"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/portal"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

const (
	testDB      = "gateway_security_test"
	appPassword = "gateway-app-test"
	jobsPass    = "gateway-jobs-test"
	dexIssuer   = "http://localhost:15556/dex"
	baseURL     = "http://localhost:18080"

	roleMember     = "member"
	roleRestricted = "restricted"

	githubStubToken = "ghu_sec-stub-token-41ac"
	slackUserToken  = "xoxp-sec-stub-user-token-9e1d"
	vendorTimeout   = 1500 * time.Millisecond
)

// --- database bootstrap ---------------------------------------------------

// openTestStore creates and migrates the package's own database (quirk
// 01mepmn6), gives the two cluster-global roles the shared test password
// (retrying the ALTER ROLE race, quirk aihn7hjb) and empties every table.
func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	raw := os.Getenv("GATEWAY_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("GATEWAY_TEST_DATABASE_URL not set; skipping security test")
	}
	ctx := t.Context()
	admin, err := pgx.Connect(ctx, raw)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = admin.Close(ctx) }()
	var exists bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, testDB).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		if _, err := admin.Exec(ctx, `CREATE DATABASE `+testDB); err != nil {
			t.Fatalf("create database: %v", err)
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + testDB
	superURL := u.String()
	if err := retryConcurrentUpdate(func() error { return migrations.Up(ctx, superURL) }); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	super, err := pgx.Connect(ctx, superURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = super.Close(ctx) }()
	for _, stmt := range []string{
		"ALTER ROLE gateway_app LOGIN PASSWORD '" + appPassword + "'",
		"ALTER ROLE gateway_jobs LOGIN PASSWORD '" + jobsPass + "'",
		"TRUNCATE users, identities, sessions, roles, role_assignments, user_restrictions, policy_versions, tokens, vendor_apps, connections, connection_secrets, connect_flows, approvals, ledger_operations, ledger_attempts, audit_events, job_locks, oauth_clients, oauth_refresh_tokens, oauth_authorization_codes, signing_keys CASCADE",
	} {
		err := retryConcurrentUpdate(func() error {
			_, err := super.Exec(ctx, stmt)
			return err
		})
		if err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	appURL, jobsURL := *u, *u
	appURL.User = url.UserPassword("gateway_app", appPassword)
	jobsURL.User = url.UserPassword("gateway_jobs", jobsPass)
	st, err := store.New(ctx, appURL.String(), store.WithJobsURL(jobsURL.String()))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(st.Close)
	return st
}

func retryConcurrentUpdate(fn func() error) error {
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		if err = fn(); err == nil || !strings.Contains(err.Error(), "concurrently updated") {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return err
}

// --- the world --------------------------------------------------------------

// user is a signed-in person: their id, portal session cookie and CSRF
// token.
type user struct {
	id     string
	cookie *http.Cookie
	csrf   string
}

// options tune one world.
type options struct {
	// approvalWait is Config.Wait of the approvals service (0: answer
	// "approval required" at once).
	approvalWait time.Duration
	// rateUser / rateApp override the limiter budgets (0: defaults).
	rateUser, rateApp int
	// federation wires user-added MCP servers as cmd/gateway does
	// (fed_world_test.go): connector.Wire with the store-backed netguard
	// allow list, the Manager's decider, account source and resource
	// provider, the servers portal, the admin pages, the upstream OAuth
	// connect pages and the tunnel endpoint.
	federation bool
	// fedTimeout bounds each upstream operation (0: client default).
	fedTimeout time.Duration
}

// world is the gateway wired like cmd/gateway plus the handles the
// scenarios need: two coworkers (alice, bob) with fake, GitHub and Slack
// accounts, an admin, the vendor stubs and the captured log.
type world struct {
	t        *testing.T
	st       *store.Store
	logs     *syncBuffer
	rec      *audit.StoreRecorder
	idSvc    *identity.Service
	policy   *policy.Service
	tokens   *tokens.Service
	conn     *connections.Service
	approval *approvals.Service
	ledger   *ledger.Service
	auth     *authserver.Service
	fake     *fake.Connector
	github   *stubGitHub
	slack    *stubSlack
	reg      *connectors.Registry
	limiter  *mcp.TokenBucketLimiter
	srv      *httptest.Server
	fed      *connector.Federation // nil unless options.federation
	gw       *gatewaytools.Tools   // nil unless options.federation
	perms    *permissions.Service

	admin, alice, bob    user
	aliceAcc             string // alice's company fake account (connections row)
	bobAcc, bobPersonal  string // bob's company and personal fake accounts
	aliceGH, bobGH       string // GitHub connection ids
	aliceSlack, bobSlack string // Slack connection ids
	now                  func() time.Time
	nowMu                sync.Mutex
	offset               time.Duration
	secretsMu            sync.Mutex
	secrets              map[string]string // value -> what it is; must never appear in logs or audit
	tokensByUser         map[string][]string
}

func newWorld(t *testing.T, opts options) *world {
	t.Helper()
	st := openTestStore(t)
	ctx := t.Context()
	w := &world{t: t, st: st, logs: &syncBuffer{}, secrets: map[string]string{}, tokensByUser: map[string][]string{}}
	w.now = func() time.Time {
		w.nowMu.Lock()
		defer w.nowMu.Unlock()
		return time.Now().UTC().Add(w.offset)
	}
	log, err := observability.NewLogger(w.logs, "debug", "text")
	if err != nil {
		t.Fatal(err)
	}
	metrics := observability.NewMetrics()
	w.rec = audit.NewStoreRecorder(st)
	keys, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{7}, 32)})
	if err != nil {
		t.Fatal(err)
	}

	cfg := config.Default()
	cfg.BaseURL = baseURL
	w.idSvc, err = identity.New(identity.Config{
		BaseURL:         baseURL,
		Providers:       []config.OIDCProvider{{Name: "dex", DisplayName: "dex", Issuer: dexIssuer, ClientID: "gateway", ClientSecret: "s", AllowedDomains: []string{"example.com"}}},
		DefaultRole:     roleMember,
		BootstrapAdmins: []string{dexIssuer + "|admin-subject"},
		IdleTimeout:     12 * time.Hour,
		AbsoluteTimeout: 7 * 24 * time.Hour,
	}, identity.NewPostgresStore(st), log)
	if err != nil {
		t.Fatal(err)
	}
	w.admin = w.signIn("admin-subject", "Admin")
	w.alice = w.signIn("alice-subject", "Alice")
	w.bob = w.signIn("bob-subject", "Bob")

	w.tokens, err = tokens.New(tokens.Config{SignInMaxAge: 30 * 24 * time.Hour}, tokens.NewPostgresStore(st), metrics, w.rec, log)
	if err != nil {
		t.Fatal(err)
	}
	w.policy, err = policy.New(policy.NewPostgresStore(st), policy.Options{Audit: w.rec, Metrics: metrics, Log: log})
	if err != nil {
		t.Fatal(err)
	}
	w.conn, err = connections.New(connections.Config{BaseURL: baseURL}, connections.NewPostgresStore(st), keys, connections.Options{
		Audit: w.rec, Policy: connections.PolicyAllowance{Service: w.policy}, Metrics: metrics, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	w.saveRoles()

	// Fake accounts are real connections rows (quirk enqgtw5y).
	w.aliceAcc = w.seed(w.alice, "alice-work", store.AccountCompany, "Alice at work")
	w.bobAcc = w.seed(w.bob, "bob-work", store.AccountCompany, "Bob at work")
	w.bobPersonal = w.seed(w.bob, "bob-home", store.AccountPersonal, "Bob at home")

	// Vendor apps and connection rows for GitHub and Slack (as the
	// connect flow would leave them, minus the token bundle: the
	// connectors get static token sources and the stubs check them).
	w.github = newStubGitHub(t)
	w.slack = newStubSlack(t)
	w.forbid(githubStubToken, "github stub token")
	w.forbid(slackUserToken, "slack user token")
	gh := connections.Defaults(connections.VendorGitHub, "")
	gh.ClientID, gh.ClientSecret = "gh-cid", "gh-client-secret-sec"
	gh.Extra[connections.ExtraCompanyOrgs] = "acme"
	ghApp, err := w.conn.SaveVendorApp(ctx, w.admin.id, gh)
	if err != nil {
		t.Fatalf("SaveVendorApp github: %v", err)
	}
	w.forbid("gh-client-secret-sec", "github client secret")
	sl := connections.Defaults(connections.VendorSlack, "")
	sl.ClientID, sl.ClientSecret = "slack-cid", "slack-client-secret-sec"
	slApp, err := w.conn.SaveVendorApp(ctx, w.admin.id, sl)
	if err != nil {
		t.Fatalf("SaveVendorApp slack: %v", err)
	}
	w.forbid("slack-client-secret-sec", "slack client secret")
	w.aliceGH = w.connect(w.alice, ghApp.ID, "github:1001", "alice-gh", nil)
	w.bobGH = w.connect(w.bob, ghApp.ID, "github:1002", "bob-gh", nil)
	slackScopes := []string{"channels:read", "groups:read", "chat:write", "users:read"}
	w.aliceSlack = w.connect(w.alice, slApp.ID, connections.SlackAccountID("TACME", "UALICE"), "alice@acme", slackScopes)
	w.bobSlack = w.connect(w.bob, slApp.ID, connections.SlackAccountID("TACME", "UBOB"), "bob@acme", slackScopes)

	w.approval, err = approvals.New(approvals.Config{TTL: 15 * time.Minute, Wait: opts.approvalWait, BaseURL: baseURL}, approvals.NewPostgresStore(st), keys, approvals.Options{
		Audit: w.rec, Metrics: metrics, Notifier: approvals.PortalNotifier{}, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	w.approval.SetClock(w.now)

	w.fake = fake.New(fake.Options{})
	w.reg = connectors.NewRegistry()
	if err := connectors.RegisterConnector(w.reg, w.fake, w.conn); err != nil {
		t.Fatal(err)
	}
	ghc, err := github.New(github.Options{
		Tokens: func(context.Context, string, string) oauth2.TokenSource {
			return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: githubStubToken})
		},
		BaseURL: w.github.URL(), Timeout: vendorTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := connectors.RegisterConnector(w.reg, ghc, w.conn); err != nil {
		t.Fatal(err)
	}
	slc, err := slackconn.New(slackconn.Options{
		Tokens: func(context.Context, string, string) oauth2.TokenSource {
			return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: slackUserToken})
		},
		BaseURL: w.slack.URL(), Timeout: vendorTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := connectors.RegisterConnector(w.reg, slc, w.conn); err != nil {
		t.Fatal(err)
	}
	w.conn.MapApp(github.App, connections.VendorGitHub)
	w.conn.MapApp(slackconn.App, connections.VendorSlack)

	// Who may add MCP servers and the "Gateway management tools" setting.
	w.perms = permissions.NewPostgres(w.st, permissions.Options{Audit: w.rec, Log: log})
	// User-added MCP servers, as cmd/gateway's newFederation wires them.
	var decider mcp.Decider = w.policy
	var accounts connectors.AccountSource = w.conn
	if opts.federation {
		decider, accounts = w.wireFederation(keys, log, opts)
	}

	lcfg := ledger.DefaultConfig()
	lcfg.BaseURL = baseURL
	w.ledger, err = ledger.New(lcfg, ledger.NewPostgresStore(st), ledger.Options{
		Approvals: w.approval.LedgerConsumer(), Registry: w.reg,
		Notifier: ledger.LogNotifier{Log: log, BaseURL: baseURL},
		Audit:    w.rec, Metrics: metrics, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	w.ledger.SetClock(w.now)

	// The OAuth authorization server (for /harnesses and the composite
	// authenticator), as cmd/gateway builds it.
	acfg, err := authserver.ConfigFromEnv(baseURL, func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	acfg.SignInMaxAge = 30 * 24 * time.Hour
	w.auth, err = authserver.New(acfg, authserver.NewPostgresStore(st), keys, authserver.Options{Audit: w.rec, Metrics: metrics, Log: log})
	if err != nil {
		t.Fatal(err)
	}

	confirm := approvals.NewConfirmHandler(w.approval, metrics, log)
	confirm.DeferConsumption(true)
	visibility := mcp.PolicyVisibility{Decider: decider, Log: log}
	rateUser, rateApp := cfg.RateUserPerMin, cfg.RateAppPerMin
	if opts.rateUser > 0 {
		rateUser = opts.rateUser
	}
	if opts.rateApp > 0 {
		rateApp = opts.rateApp
	}
	w.limiter = mcp.NewRateLimiter(mcp.RateLimitConfig{UserPerMinute: rateUser, AppPerMinute: rateApp})
	pipeline, err := mcp.DefaultPipeline(mcp.PipelineDeps{
		Registry: w.reg, Visibility: visibility, RateLimiter: w.limiter, Accounts: accounts, Policy: decider, Confirm: confirm,
		Audit: w.rec, Metrics: metrics, Log: log, BaseURL: baseURL,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pipeline.Insert(mcp.Before, mcp.StageRateLimit, mcp.LedgerStage(w.ledger, log)); err != nil {
		t.Fatal(err)
	}
	mopts := mcp.Options{
		Registry: w.reg, Pipeline: pipeline, Visibility: visibility, Authenticator: authserver.Composite(w.tokens, w.auth.Authenticator()),
		Auth:    tokens.MiddlewareOptions{Limiter: tokens.NewFailureLimiter(tokens.DefaultFailureBurst, tokens.DefaultFailureWindow), Metrics: metrics, Log: log},
		BaseURL: baseURL, MaxBody: cfg.MCPMaxBody, Log: log, Version: "security",
	}
	if w.fed != nil {
		// Resources and prompts of user-added servers, audited and rate
		// limited like tool calls (cmd/gateway's newMCPWithResources).
		mopts.Resources, mopts.Audit, mopts.RateLimiter = w.fed.Manager.ResourceProvider(w.policy), w.rec, w.limiter
	}
	mcpHandler, err := mcp.Handler(mopts)
	if err != nil {
		t.Fatal(err)
	}

	p, err := portal.New(w.idSvc, log)
	if err != nil {
		t.Fatal(err)
	}
	// My account: "Gateway management tools", as cmd/gateway wires it
	// (through the gate when the gateway tools are wired).
	p.SetGatewayTools(w.gw.Setting(w.perms))
	who := func(r *http.Request) (string, bool) {
		pr := identity.PrincipalFrom(r.Context())
		if pr == nil {
			return "", false
		}
		return pr.UserID, pr.IsAdmin()
	}
	session := func(r *http.Request) (string, string) {
		pr := identity.PrincipalFrom(r.Context())
		if pr == nil {
			return "", ""
		}
		return pr.UserID, pr.CSRFToken
	}
	adminSession := func(r *http.Request) (string, string, bool) {
		pr := identity.PrincipalFrom(r.Context())
		if pr == nil {
			return "", "", false
		}
		return pr.UserID, pr.CSRFToken, pr.IsAdmin()
	}
	p.MountUser("GET /activity", audit.ActivityHandler(w.rec, who))
	p.MountAdmin("GET /admin/audit", audit.AdminSearchHandler(w.rec, who))
	tokens.NewPortal(w.tokens, session, baseURL, log).Mount(p.MountUser)
	approvals.NewPortal(w.approval, session, log).Mount(p.MountUser)
	policy.NewPortal(w.policy, w.reg, adminSession, log).Mount(p.MountAdmin)
	cp := connections.NewPortal(w.conn, adminSession, log)
	cp.MountUser(p.MountUser)
	cp.MountConnect(p.MountUser)
	cp.MountAdmin(p.MountAdmin)
	ledger.NewPortal(w.ledger, session, log).Mount(p.MountUser)
	w.auth.MountPortal(p.MountUser, session)
	w.idSvc.OnDisable(w.tokens.DisableHook())
	w.idSvc.OnDisable(w.conn.DisableHook())
	w.idSvc.OnDisable(w.auth.DisableHook())
	if w.fed != nil {
		w.mountFederationPages(p, session, log)
	}

	mux := http.NewServeMux()
	mux.Handle("GET /healthz", observability.Liveness())
	mux.Handle("/mcp", mcpHandler)
	w.auth.Mount(mux)
	if w.fed != nil {
		w.mountFederationRoutes(mux)
	}
	mux.Handle("/", p.Handler())
	w.srv = httptest.NewServer(observability.RequestID(metrics.HTTPMiddleware(mux)))
	t.Cleanup(w.srv.Close)
	t.Cleanup(w.scanForLeaks)
	return w
}

// signIn completes a company sign-in the way the OIDC callback does.
func (w *world) signIn(sub, name string) user {
	w.t.Helper()
	res, err := w.idSvc.SignIn(w.t.Context(), "dex", identity.Claims{Issuer: dexIssuer, Subject: sub, Name: name, Email: sub + "@example.com", EmailVerified: true})
	if err != nil {
		w.t.Fatalf("SignIn %s: %v", sub, err)
	}
	w.forbid(res.Cookie.Value, "session cookie of "+name)
	return user{id: res.Principal.UserID, cookie: res.Cookie, csrf: res.Principal.CSRFToken}
}

// memberRules are the member role's rules:
//
//   - fake.* allow, create_item confirm, get_item denied when id starts
//     with "secret-";
//   - github.create_issue confirm in org acme, allow in acme-labs (so
//     any other org is denied); get_me, search_issues, list_accounts;
//   - slack.post_message confirm for #eng-*; list_channels, list_accounts.
func memberRules() []policy.ToolRule {
	return []policy.ToolRule{
		{App: fake.App, Tool: policy.Wildcard, Outcome: policy.OutcomeAllow},
		{App: fake.App, Tool: fake.ToolCreateItem, Outcome: policy.OutcomeConfirm},
		{App: fake.App, Tool: fake.ToolGetItem, Outcome: policy.OutcomeDeny, Conditions: []policy.Condition{{Key: "id", Op: policy.OpPrefix, Value: "secret-"}}},
		{App: github.App, Tool: github.ToolCreateIssue, Outcome: policy.OutcomeConfirm, Conditions: []policy.Condition{{Key: "org", Op: policy.OpEquals, Value: "acme"}}},
		{App: github.App, Tool: github.ToolCreateIssue, Outcome: policy.OutcomeAllow, Conditions: []policy.Condition{{Key: "org", Op: policy.OpEquals, Value: "acme-labs"}}},
		{App: github.App, Tool: github.ToolGetMe, Outcome: policy.OutcomeAllow},
		{App: github.App, Tool: github.ToolSearchIssues, Outcome: policy.OutcomeAllow},
		{App: github.App, Tool: connectors.ListAccountsName, Outcome: policy.OutcomeAllow},
		{App: slackconn.App, Tool: slackconn.ToolPostMessage, Outcome: policy.OutcomeConfirm, Conditions: []policy.Condition{{Key: "channel", Op: policy.OpPrefix, Value: "eng-"}}},
		{App: slackconn.App, Tool: slackconn.ToolListChannels, Outcome: policy.OutcomeAllow},
		{App: slackconn.App, Tool: connectors.ListAccountsName, Outcome: policy.OutcomeAllow},
	}
}

// saveRoles writes the member role (memberRules) and the restricted
// role (the same with fake.get_item hidden and personal fake accounts
// denied), which bob holds.
func (w *world) saveRoles() {
	w.t.Helper()
	ctx := w.t.Context()
	w.setMemberRules(memberRules())
	restricted := policy.Role{
		Name: roleRestricted, Description: "member without get_item or personal accounts",
		Rules:            append(memberRules(), policy.ToolRule{App: fake.App, Tool: fake.ToolGetItem, Outcome: policy.OutcomeHidden}),
		PersonalAccounts: map[string]policy.Allowance{fake.App: policy.AllowanceDeny},
	}
	if err := w.policy.SaveRole(ctx, w.admin.id, restricted); err != nil {
		w.t.Fatalf("SaveRole restricted: %v", err)
	}
	if err := w.idSvc.SetUserRole(ctx, w.admin.id, w.bob.id, roleRestricted); err != nil {
		w.t.Fatalf("SetUserRole bob: %v", err)
	}
	w.policy.Invalidate()
}

// setMemberRules replaces the member role's rules and reloads policy.
func (w *world) setMemberRules(rules []policy.ToolRule) {
	w.t.Helper()
	ctx := w.t.Context()
	member, err := w.policy.Role(ctx, roleMember)
	if err != nil {
		w.t.Fatal(err)
	}
	member.Rules = rules
	if err := w.policy.SaveRole(ctx, w.admin.id, member); err != nil {
		w.t.Fatalf("SaveRole member: %v", err)
	}
	w.policy.Invalidate()
}

// seed gives u a fake account backed by a connections row.
func (w *world) seed(u user, external, label, name string) string {
	w.t.Helper()
	info, err := w.conn.SeedAccount(w.t.Context(), u.id, connections.Seed{ExternalAccountID: external, Label: label, DisplayName: name})
	if err != nil {
		w.t.Fatalf("SeedAccount %s: %v", external, err)
	}
	return info.ID
}

// connect creates an active company connection row for u on the vendor
// app with the recorded scopes.
func (w *world) connect(u user, appID, external, name string, scopes []string) string {
	w.t.Helper()
	ctx := w.t.Context()
	var id string
	err := w.st.WithUser(ctx, u.id, func(tx store.Tx) error {
		row := &store.Connection{
			UserID: u.id, VendorAppID: appID, ExternalAccountID: external,
			Label: store.AccountCompany, DisplayName: name, Scopes: scopes, Status: store.ConnectionActive,
		}
		if err := tx.Connections().Create(ctx, row); err != nil {
			return err
		}
		id = row.ID
		return nil
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return id
}

// forbid registers a value that must never appear in the logs or audit.
func (w *world) forbid(value, what string) {
	if value == "" {
		return
	}
	w.secretsMu.Lock()
	defer w.secretsMu.Unlock()
	w.secrets[value] = what
}

// token mints a harness token for u and registers its secret.
func (w *world) token(u user, req tokens.CreateRequest) string {
	w.t.Helper()
	if req.Name == "" {
		req.Name = "security"
	}
	created, err := w.tokens.Create(w.t.Context(), u.id, req)
	if err != nil {
		w.t.Fatal(err)
	}
	w.forbid(created.Raw, "harness token")
	w.tokensByUser[u.id] = append(w.tokensByUser[u.id], created.Raw)
	return created.Raw
}

// client connects an SDK client with a fresh token for u.
func (w *world) client(u user) *sdk.ClientSession {
	w.t.Helper()
	return w.clientWith(w.token(u, tokens.CreateRequest{}))
}

// clientWith connects an SDK client with the given token.
func (w *world) clientWith(token string) *sdk.ClientSession {
	w.t.Helper()
	transport := &sdk.StreamableClientTransport{Endpoint: w.srv.URL + "/mcp", HTTPClient: bearerClient(token)}
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "security", Version: "0"}, nil).Connect(w.t.Context(), transport, nil)
	if err != nil {
		w.t.Fatal(err)
	}
	w.t.Cleanup(func() { _ = cs.Close() })
	return cs
}

// call runs tools/call and returns the result or the JSON-RPC error.
func (w *world) call(cs *sdk.ClientSession, tool string, args map[string]any) (*sdk.CallToolResult, error) {
	return cs.CallTool(w.t.Context(), &sdk.CallToolParams{Name: tool, Arguments: args})
}

// rawCall posts one tools/call over plain HTTP and returns the HTTP
// status, the headers and the body (the wire form).
func (w *world) rawCall(token, tool string, args map[string]any) (int, http.Header, []byte) {
	w.t.Helper()
	body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": tool, "arguments": args}})
	req, _ := http.NewRequestWithContext(w.t.Context(), http.MethodPost, w.srv.URL+"/mcp", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	out, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, out
}

// --- portal HTTP as a browser ------------------------------------------------

// get fetches a portal page as u (session cookie).
func (w *world) get(u user, path string) (int, http.Header, string) {
	w.t.Helper()
	req, _ := http.NewRequestWithContext(w.t.Context(), http.MethodGet, w.srv.URL+path, nil)
	if u.cookie != nil {
		req.AddCookie(u.cookie)
	}
	res, err := noRedirect.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, string(b)
}

// post submits a portal form as u with the CSRF token.
func (w *world) post(u user, path string, form url.Values) (int, http.Header, string) {
	w.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	form.Set("_csrf", u.csrf)
	req, _ := http.NewRequestWithContext(w.t.Context(), http.MethodPost, w.srv.URL+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if u.cookie != nil {
		req.AddCookie(u.cookie)
	}
	res, err := noRedirect.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, string(b)
}

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// --- store reads -----------------------------------------------------------------

// ops lists a user's ledger rows (every state) through the bypass scope.
func (w *world) ops(u user) []store.LedgerOperation {
	w.t.Helper()
	var out []store.LedgerOperation
	err := w.st.WithJobs(w.t.Context(), func(tx store.Tx) error {
		var err error
		out, err = store.ListLedgerOperations(w.t.Context(), tx, store.LedgerFilter{UserID: u.id})
		return err
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return out
}

// opFor finds the user's operation for tool in state ("" for any).
func (w *world) opFor(u user, tool, state string) *store.LedgerOperation {
	for _, row := range w.ops(u) {
		if row.Tool == tool && (state == "" || row.State == state) {
			r := row
			return &r
		}
	}
	return nil
}

// exec runs SQL through the bypass scope.
func (w *world) exec(sql string, args ...any) {
	w.t.Helper()
	err := w.st.WithJobs(w.t.Context(), func(tx store.Tx) error {
		_, err := tx.Exec(w.t.Context(), sql, args...)
		return err
	})
	if err != nil {
		w.t.Fatalf("%s: %v", sql, err)
	}
}

// queryString runs a one-value SQL query through the bypass scope.
func (w *world) queryString(sql string, args ...any) string {
	w.t.Helper()
	var out string
	err := w.st.WithJobs(w.t.Context(), func(tx store.Tx) error {
		return tx.QueryRow(w.t.Context(), sql, args...).Scan(&out)
	})
	if err != nil {
		w.t.Fatalf("%s: %v", sql, err)
	}
	return out
}

// events lists a user's audit rows (their own view).
func (w *world) events(u user) []audit.Record {
	w.t.Helper()
	rows, err := w.rec.ListForUser(w.t.Context(), u.id, audit.Filter{}, audit.Page{Limit: audit.MaxPageSize})
	if err != nil {
		w.t.Fatal(err)
	}
	return rows
}

// allEvents lists every audit row through the admin view.
func (w *world) allEvents() []audit.Record {
	w.t.Helper()
	var out []audit.Record
	for offset := 0; ; offset += audit.MaxPageSize {
		rows, err := w.rec.AdminSearch(context.Background(), audit.Filter{}, audit.Page{Limit: audit.MaxPageSize, Offset: offset})
		if err != nil {
			w.t.Fatal(err)
		}
		out = append(out, rows...)
		if len(rows) < audit.MaxPageSize {
			return out
		}
	}
}

// --- leak scan ---------------------------------------------------------------------

// scanForLeaks asserts that no registered secret reached the gateway log
// or any audit row.
func (w *world) scanForLeaks() {
	w.secretsMu.Lock()
	secrets := make(map[string]string, len(w.secrets))
	for k, v := range w.secrets {
		secrets[k] = v
	}
	w.secretsMu.Unlock()
	logs := w.logs.String()
	if logs == "" {
		w.t.Error("no gateway log output captured")
	}
	for value, what := range secrets {
		if strings.Contains(logs, value) {
			w.t.Errorf("log leak: %s (%q) appears in the gateway log", what, value)
		}
	}
	for _, raw := range w.tokensByUser {
		for _, tok := range raw {
			secret := tok[strings.LastIndex(tok, "_")+1:]
			if strings.Contains(logs, secret) {
				w.t.Errorf("log leak: token secret appears in the gateway log")
			}
		}
	}
	rows := w.allEvents()
	if len(rows) == 0 {
		w.t.Error("no audit rows recorded")
	}
	for _, r := range rows {
		b, _ := json.Marshal(r)
		for value, what := range secrets {
			if strings.Contains(string(b), value) {
				w.t.Errorf("audit leak: %s (%q) in audit row %s", what, value, b)
			}
		}
	}
}

// syncBuffer is a bytes.Buffer safe for concurrent writers.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// --- assertions --------------------------------------------------------------------

// rpcError asserts err is a JSON-RPC error with the code and returns it.
func rpcError(t *testing.T, err error, code int64) *jsonrpc.Error {
	t.Helper()
	var je *jsonrpc.Error
	if !errors.As(err, &je) {
		t.Fatalf("err = %v (%T), want *jsonrpc.Error", err, err)
	}
	if je.Code != code {
		t.Fatalf("error = %d %q, want code %d", je.Code, je.Message, code)
	}
	return je
}

// approvalRequired asserts err is the approval-required answer and
// returns the id.
func approvalRequired(t *testing.T, err error) string {
	t.Helper()
	je := rpcError(t, err, mcp.CodeApprovalRequired)
	var data map[string]any
	if err := json.Unmarshal(je.Data, &data); err != nil {
		t.Fatalf("error data %s: %v", je.Data, err)
	}
	id, _ := data["approval_id"].(string)
	if id == "" || !strings.Contains(je.Message, id) {
		t.Fatalf("no approval id: %q %v", je.Message, data)
	}
	return id
}

// text returns the first text block of a result.
func text(t *testing.T, res *sdk.CallToolResult) string {
	t.Helper()
	for _, c := range res.Content {
		if tc, ok := c.(*sdk.TextContent); ok {
			return tc.Text
		}
	}
	t.Fatalf("no text content in %+v", res)
	return ""
}

// toolNames lists the names of a tools/list result.
func toolNames(t *testing.T, cs *sdk.ClientSession) []string {
	t.Helper()
	res, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(res.Tools))
	for _, tl := range res.Tools {
		out = append(out, tl.Name)
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// bearerClient adds Authorization to every request.
func bearerClient(token string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		r.Header.Set("Authorization", "Bearer "+token)
		return http.DefaultTransport.RoundTrip(r)
	})}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// stripID removes the JSON-RPC id from a wire response so two answers to
// different requests can be compared byte for byte.
func stripID(b []byte) string {
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		return string(b)
	}
	delete(m, "id")
	out, _ := json.Marshal(m)
	return string(out)
}
