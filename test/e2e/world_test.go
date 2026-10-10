//go:build integration || e2e

// Package e2e is the safety-core end-to-end gate (Brain task sougju69,
// decision bt8ukyrd): the whole gateway wired in-process the way
// cmd/gateway wires it (identity, portal, tokens, policy, connections,
// approvals with the Slack notifier, ledger, jobs, /mcp with every stage,
// /slack/interactions, audit) against a real PostgreSQL, driven through
// the official MCP Go SDK client and plain HTTP for the portal pages.
//
// Run with `make test-e2e` (GATEWAY_TEST_DATABASE_URL must point at a
// superuser; the package creates and migrates gateway_e2e_test). Every
// world captures the gateway's redacted log output and asserts, when the
// test ends, that no token secret, argument value or Slack secret reached
// it.
package e2e

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/approvals"
	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/fake"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/jobs"
	"github.com/huynle/mcp-gateway/internal/ledger"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/portal"
	"github.com/huynle/mcp-gateway/internal/slack"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

const (
	testDB      = "gateway_e2e_test"
	appPassword = "gateway-app-test"
	jobsPass    = "gateway-jobs-test"
	dexIssuer   = "http://localhost:15556/dex"
	baseURL     = "http://localhost:18080"

	roleMember     = "member"
	roleRestricted = "restricted"

	slackSigningSecret = "e2e-signing-secret-7f3a"
	slackBotToken      = "xoxb-e2e-bot-token-91c2"
)

// --- database bootstrap ---------------------------------------------------

// openTestStore creates and migrates the package's own database (quirk
// 01mepmn6), gives the two cluster-global roles the shared test password
// (retrying the ALTER ROLE race, quirk aihn7hjb) and empties every table.
func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	raw := os.Getenv("GATEWAY_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("GATEWAY_TEST_DATABASE_URL not set; skipping end-to-end test")
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
		"TRUNCATE users, identities, sessions, roles, role_assignments, user_restrictions, policy_versions, tokens, vendor_apps, connections, connection_secrets, connect_flows, approvals, ledger_operations, ledger_attempts, audit_events, job_locks CASCADE",
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
// token (what a browser holds after the OIDC callback).
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
	// register adds further connectors to the registry after the fake
	// (the GitHub world registers the real connector against a stub API).
	register func(reg *connectors.Registry) error
}

// world is the gateway wired like cmd/gateway, plus the handles the
// scenarios need.
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
	notifier *memNotifier
	fake     *fake.Connector
	slack    *fakeSlack
	srv      *httptest.Server

	admin, alice, bob    user
	aliceAcc             string // alice's company fake account (connections row)
	bobAcc, bobPersonal  string // bob's company and personal fake accounts
	aliceSlackUser, team string
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
	w := &world{t: t, st: st, logs: &syncBuffer{}, notifier: &memNotifier{}, secrets: map[string]string{}, tokensByUser: map[string][]string{}}
	w.now = func() time.Time {
		w.nowMu.Lock()
		defer w.nowMu.Unlock()
		return time.Now().UTC().Add(w.offset)
	}
	// The production logger: redacting, debug level, text format, into a
	// buffer the redaction scan reads at the end.
	log, err := observability.NewLogger(w.logs, "debug", "text")
	if err != nil {
		t.Fatal(err)
	}
	metrics := observability.NewMetrics()
	w.rec = audit.NewStoreRecorder(st)
	keys, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{9}, 32)})
	if err != nil {
		t.Fatal(err)
	}

	// Identity and sign-in (three users; the admin is a bootstrap admin).
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

	// Tokens, policy, connections.
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

	// Fake accounts are real connections rows (quirk enqgtw5y): alice has
	// a company account, bob a company and a personal one.
	w.aliceAcc = w.seed(w.alice, "alice-work", store.AccountCompany, "Alice at work")
	w.bobAcc = w.seed(w.bob, "bob-work", store.AccountCompany, "Bob at work")
	w.bobPersonal = w.seed(w.bob, "bob-home", store.AccountPersonal, "Bob at home")

	// Slack: the vendor app with bot token and signing secret, alice's
	// company Slack connection, the fake Slack API.
	w.slack = newFakeSlack(t)
	w.aliceSlackUser, w.team = "UALICE", "TACME"
	app := connections.Defaults(connections.VendorSlack, "")
	app.ClientID, app.ClientSecret = "slack-cid", "slack-client-secret-e2e"
	app.Secrets = map[string]string{connections.SecretSlackBotToken: slackBotToken, connections.SecretSlackSigningSecret: slackSigningSecret}
	saved, err := w.conn.SaveVendorApp(ctx, w.admin.id, app)
	if err != nil {
		t.Fatalf("SaveVendorApp: %v", err)
	}
	w.forbid(slackBotToken, "slack bot token")
	w.forbid(slackSigningSecret, "slack signing secret")
	w.forbid("slack-client-secret-e2e", "slack client secret")
	err = st.WithUser(ctx, w.alice.id, func(tx store.Tx) error {
		return tx.Connections().Create(ctx, &store.Connection{
			UserID: w.alice.id, VendorAppID: saved.ID, ExternalAccountID: connections.SlackAccountID(w.team, w.aliceSlackUser),
			Label: store.AccountCompany, DisplayName: "alice@acme", Status: store.ConnectionActive,
		})
	})
	if err != nil {
		t.Fatal(err)
	}
	slackNotifier, err := approvals.NewSlackNotifier(approvals.SlackNotifierOptions{
		Identity: w.conn, Secrets: w.conn, APIURL: w.slack.URL(), PortalURL: baseURL + "/approvals", Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Approvals (portal + Slack notifiers), ledger (memory + log notifier).
	w.approval, err = approvals.New(approvals.Config{TTL: 15 * time.Minute, Wait: opts.approvalWait, BaseURL: baseURL}, approvals.NewPostgresStore(st), keys, approvals.Options{
		Audit: w.rec, Metrics: metrics, Notifier: approvals.MultiNotifier{approvals.PortalNotifier{}, slackNotifier}, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	slackNotifier.SetArguments(w.approval)
	w.approval.SetClock(w.now)

	w.fake = fake.New(fake.Options{})
	reg := connectors.NewRegistry()
	// The account source is the connections table, as in production.
	if err := connectors.RegisterConnector(reg, w.fake, w.conn); err != nil {
		t.Fatal(err)
	}
	if opts.register != nil {
		if err := opts.register(reg); err != nil {
			t.Fatal(err)
		}
	}
	lcfg := ledger.DefaultConfig()
	lcfg.BaseURL = baseURL
	w.ledger, err = ledger.New(lcfg, ledger.NewPostgresStore(st), ledger.Options{
		Approvals: w.approval.LedgerConsumer(), Registry: reg,
		Notifier: ledger.MultiNotifier{ledger.LogNotifier{Log: log, BaseURL: baseURL}, w.notifier},
		Audit:    w.rec, Metrics: metrics, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	w.ledger.SetClock(w.now)

	// /mcp: the default pipeline with the ledger stage before ratelimit
	// and the confirm handler in deferred-consumption mode.
	confirm := approvals.NewConfirmHandler(w.approval, metrics, log)
	confirm.DeferConsumption(true)
	visibility := mcp.PolicyVisibility{Decider: w.policy, Log: log}
	limiter := mcp.NewRateLimiter(mcp.RateLimitConfig{UserPerMinute: cfg.RateUserPerMin, AppPerMinute: cfg.RateAppPerMin})
	pipeline, err := mcp.DefaultPipeline(mcp.PipelineDeps{
		Registry: reg, Visibility: visibility, RateLimiter: limiter, Accounts: w.conn, Policy: w.policy, Confirm: confirm,
		Audit: w.rec, Metrics: metrics, Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pipeline.Insert(mcp.Before, mcp.StageRateLimit, mcp.LedgerStage(w.ledger, log)); err != nil {
		t.Fatal(err)
	}
	mcpHandler, err := mcp.Handler(mcp.Options{
		Registry: reg, Pipeline: pipeline, Visibility: visibility, Authenticator: w.tokens,
		Auth:    tokens.MiddlewareOptions{Limiter: tokens.NewFailureLimiter(tokens.DefaultFailureBurst, tokens.DefaultFailureWindow), Metrics: metrics, Log: log},
		BaseURL: baseURL, MaxBody: cfg.MCPMaxBody, Log: log, Version: "e2e",
	})
	if err != nil {
		t.Fatal(err)
	}

	// Slack interactions on the public mux, outside the portal.
	slackHandler, err := slack.NewInteractionsHandler(slack.Options{Approvals: w.approval, Identity: w.conn, Secrets: w.conn, Audit: w.rec, APIURL: w.slack.URL(), Log: log})
	if err != nil {
		t.Fatal(err)
	}

	// Portal: activity, admin audit, tokens, approvals, roles, connections,
	// operations, exactly as cmd/gateway.newPortal mounts them.
	p, err := portal.New(w.idSvc, log)
	if err != nil {
		t.Fatal(err)
	}
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
	policy.NewPortal(w.policy, reg, adminSession, log).Mount(p.MountAdmin)
	cp := connections.NewPortal(w.conn, adminSession, log)
	cp.MountUser(p.MountUser)
	cp.MountConnect(p.MountUser)
	cp.MountAdmin(p.MountAdmin)
	ledger.NewPortal(w.ledger, session, log).Mount(p.MountUser)
	w.idSvc.OnDisable(w.tokens.DisableHook())
	w.idSvc.OnDisable(w.conn.DisableHook())

	mux := http.NewServeMux()
	mux.Handle("GET /healthz", observability.Liveness())
	mux.Handle("/mcp", mcpHandler)
	mux.Handle("POST /slack/interactions", slackHandler)
	mux.Handle("/", p.Handler())
	w.srv = httptest.NewServer(observability.RequestID(metrics.HTTPMiddleware(mux)))
	t.Cleanup(w.srv.Close)
	t.Cleanup(w.scanForLeaks)
	return w
}

// signIn completes a company sign-in the way the OIDC callback does and
// returns the user with their session cookie and CSRF token.
func (w *world) signIn(sub, name string) user {
	w.t.Helper()
	res, err := w.idSvc.SignIn(w.t.Context(), "dex", identity.Claims{Issuer: dexIssuer, Subject: sub, Name: name, Email: sub + "@example.com", EmailVerified: true})
	if err != nil {
		w.t.Fatalf("SignIn %s: %v", sub, err)
	}
	w.forbid(res.Cookie.Value, "session cookie of "+name)
	return user{id: res.Principal.UserID, cookie: res.Cookie, csrf: res.Principal.CSRFToken}
}

// saveRoles writes the two roles and assigns bob the restricted one:
//
//   - member: fake.* allow; create_item confirm; post_note and
//     flaky_write allow; get_item denied when id starts with "secret-"
//     (a conditional deny leaves the tool listed);
//   - restricted: the same, get_item hidden, personal fake accounts
//     denied.
func (w *world) saveRoles() {
	w.t.Helper()
	ctx := w.t.Context()
	member, err := w.policy.Role(ctx, roleMember)
	if err != nil {
		w.t.Fatal(err)
	}
	member.Rules = []policy.ToolRule{
		{App: fake.App, Tool: policy.Wildcard, Outcome: policy.OutcomeAllow},
		{App: fake.App, Tool: fake.ToolCreateItem, Outcome: policy.OutcomeConfirm},
		{App: fake.App, Tool: fake.ToolPostNote, Outcome: policy.OutcomeAllow},
		{App: fake.App, Tool: fake.ToolFlakyWrite, Outcome: policy.OutcomeAllow},
		{App: fake.App, Tool: fake.ToolGetItem, Outcome: policy.OutcomeDeny, Conditions: []policy.Condition{{Key: "id", Op: policy.OpPrefix, Value: "secret-"}}},
	}
	if err := w.policy.SaveRole(ctx, w.admin.id, member); err != nil {
		w.t.Fatalf("SaveRole member: %v", err)
	}
	restricted := policy.Role{
		Name: roleRestricted, Description: "member without get_item or personal accounts",
		Rules:            append(append([]policy.ToolRule(nil), member.Rules...), policy.ToolRule{App: fake.App, Tool: fake.ToolGetItem, Outcome: policy.OutcomeHidden}),
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

// seed gives u a fake account backed by a connections row.
func (w *world) seed(u user, external, label, name string) string {
	w.t.Helper()
	info, err := w.conn.SeedAccount(w.t.Context(), u.id, connections.Seed{ExternalAccountID: external, Label: label, DisplayName: name})
	if err != nil {
		w.t.Fatalf("SeedAccount %s: %v", external, err)
	}
	return info.ID
}

// advance moves the service clocks (approvals, ledger) forward.
func (w *world) advance(d time.Duration) {
	w.nowMu.Lock()
	defer w.nowMu.Unlock()
	w.offset += d
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

// contentKeys are the fake tools' content arguments: values under them
// are app content and must never be logged or audited. Identifier
// arguments (id, prefix, marker) are the resource identity the audit row
// carries by design (decision dovthftx).
var contentKeys = map[string]bool{"name": true, "body": true, "text": true, "payload": true}

// args builds tool arguments and registers every content value as a
// string that must never appear in the logs or the audit rows.
func (w *world) args(kv ...any) map[string]any {
	out := make(map[string]any, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		k, _ := kv[i].(string)
		out[k] = kv[i+1]
		if s, ok := kv[i+1].(string); ok && contentKeys[k] {
			w.forbid(s, "argument "+k)
		}
	}
	return out
}

// token mints a harness token for u and registers its secret.
func (w *world) token(u user, req tokens.CreateRequest) string {
	w.t.Helper()
	if req.Name == "" {
		req.Name = "e2e"
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
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "e2e", Version: "0"}, nil).Connect(w.t.Context(), transport, nil)
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

// rawCall posts one tools/call over plain HTTP and returns the response
// body: the byte-for-byte checks need the wire form, not the SDK's view.
func (w *world) rawCall(token, tool string, args map[string]any) []byte {
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
	return out
}

// --- portal HTTP as a browser ------------------------------------------------

// get fetches a portal page as u (session cookie) and returns status and body.
func (w *world) get(u user, path string) (int, string) {
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
	return res.StatusCode, string(b)
}

// post submits an empty portal form (the approve/deny buttons) as u.
// withCSRF false leaves the token out.
func (w *world) post(u user, path string, withCSRF bool) (int, string) {
	w.t.Helper()
	form := url.Values{}
	if withCSRF {
		form.Set("_csrf", u.csrf)
	}
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
	return res.StatusCode, string(b)
}

// postRaw posts a body with the given headers (no session) and returns
// the status and body.
func (w *world) postRaw(path, body string, headers map[string]string) (int, string) {
	w.t.Helper()
	req, _ := http.NewRequestWithContext(w.t.Context(), http.MethodPost, w.srv.URL+path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	res, err := noRedirect.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b)
}

// rawStatus posts one tools/call over plain HTTP and returns the HTTP
// status (401 for a refused token).
func (w *world) rawStatus(token string) int {
	w.t.Helper()
	body := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	req, _ := http.NewRequestWithContext(w.t.Context(), http.MethodPost, w.srv.URL+"/mcp", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	_, _ = io.Copy(io.Discard, res.Body)
	return res.StatusCode
}

var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

// --- Slack ----------------------------------------------------------------------

// press sends a signed block_actions payload to /slack/interactions.
func (w *world) press(action, approvalID, slackUser, team string) int {
	w.t.Helper()
	payload, _ := json.Marshal(map[string]any{
		"type":      "block_actions",
		"team":      map[string]any{"id": team},
		"user":      map[string]any{"id": slackUser, "team_id": team},
		"container": map[string]any{"type": "message", "message_ts": "1700000000.000100", "channel_id": "D-" + slackUser},
		"actions":   []map[string]any{{"action_id": action, "block_id": "approval:" + approvalID, "type": "button", "value": approvalID}},
	})
	body := []byte(url.Values{"payload": {string(payload)}}.Encode())
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(slackSigningSecret))
	mac.Write([]byte("v0:" + ts + ":"))
	mac.Write(body)
	req, _ := http.NewRequestWithContext(w.t.Context(), http.MethodPost, w.srv.URL+"/slack/interactions", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Slack-Request-Timestamp", ts)
	req.Header.Set("X-Slack-Signature", "v0="+hex.EncodeToString(mac.Sum(nil)))
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		w.t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	_, _ = io.Copy(io.Discard, res.Body)
	return res.StatusCode
}

// fakeSlack is an httptest stand-in for conversations.open,
// chat.postMessage and chat.update; it records every call.
type fakeSlack struct {
	srv            *httptest.Server
	mu             sync.Mutex
	calls          []string
	posts, updates []map[string]string
}

func newFakeSlack(t *testing.T) *fakeSlack {
	t.Helper()
	f := &fakeSlack{}
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeSlack) URL() string { return f.srv.URL + "/api/" }

func (f *fakeSlack) serve(w http.ResponseWriter, r *http.Request) {
	method := strings.TrimPrefix(r.URL.Path, "/api/")
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	form := map[string]string{}
	for k := range r.PostForm {
		form[k] = r.PostForm.Get(k)
	}
	f.mu.Lock()
	f.calls = append(f.calls, method)
	switch method {
	case "chat.postMessage":
		f.posts = append(f.posts, form)
	case "chat.update":
		f.updates = append(f.updates, form)
	}
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch method {
	case "conversations.open":
		_, _ = w.Write([]byte(`{"ok":true,"channel":{"id":"D-` + form["users"] + `"}}`))
	case "chat.postMessage":
		_, _ = w.Write([]byte(`{"ok":true,"channel":"` + form["channel"] + `","ts":"1700000000.000100"}`))
	case "chat.update":
		_, _ = w.Write([]byte(`{"ok":true,"channel":"` + form["channel"] + `","ts":"` + form["ts"] + `"}`))
	default:
		_, _ = w.Write([]byte(`{"ok":false,"error":"unknown_method"}`))
	}
}

func (f *fakeSlack) lastPost() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.posts) == 0 {
		return nil
	}
	return f.posts[len(f.posts)-1]
}

func (f *fakeSlack) lastUpdate() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.updates) == 0 {
		return nil
	}
	return f.updates[len(f.updates)-1]
}

// --- jobs ----------------------------------------------------------------------------

// runJobs starts a real jobs runner (Postgres lease) with the given jobs
// until the test ends.
func (w *world) runJobs(list ...jobs.Job) {
	w.t.Helper()
	runner := jobs.NewRunner(jobs.NewPostgresLocker(w.st), jobs.Options{Holder: "e2e", Lease: 30 * time.Second, Log: slog.New(slog.DiscardHandler)})
	for _, j := range list {
		if err := runner.Register(j); err != nil {
			w.t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = runner.Run(ctx)
	}()
	w.t.Cleanup(func() {
		cancel()
		<-done
	})
}

// eventually polls cond until it holds or the deadline passes.
func (w *world) eventually(what string, d time.Duration, cond func() bool) {
	w.t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	w.t.Fatalf("timed out waiting for %s", what)
}

// --- store reads -----------------------------------------------------------------

// op reads a ledger row through the bypass scope.
func (w *world) op(id string) *store.LedgerOperation {
	w.t.Helper()
	var op *store.LedgerOperation
	err := w.st.WithJobs(w.t.Context(), func(tx store.Tx) error {
		var err error
		op, err = store.GetLedgerOperation(w.t.Context(), tx, id)
		return err
	})
	if err != nil {
		w.t.Fatalf("read operation %s: %v", id, err)
	}
	return op
}

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

// exec runs SQL through the bypass scope (backdating rows, etc.).
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

// events lists a user's audit rows (their own view).
func (w *world) events(u user) []audit.Record {
	w.t.Helper()
	rows, err := w.rec.ListForUser(w.t.Context(), u.id, audit.Filter{}, audit.Page{Limit: audit.MaxPageSize})
	if err != nil {
		w.t.Fatal(err)
	}
	return rows
}

// --- leak scan ---------------------------------------------------------------------

// scanForLeaks asserts that no registered secret or argument value reached
// the gateway log or any audit row (user views and the admin view).
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
			// The public id may be logged; the secret half never.
			secret := tok[strings.LastIndex(tok, "_")+1:]
			if strings.Contains(logs, secret) {
				w.t.Errorf("log leak: token secret appears in the gateway log")
			}
		}
	}
	if strings.Contains(logs, "mgw_") && !strings.Contains(logs, "mgw_[REDACTED]") && !strings.Contains(logs, "[REDACTED]") {
		w.t.Errorf("log contains an unredacted mgw_ token")
	}
	// Audit rows: the admin view sees every row of every user.
	rows, err := w.rec.AdminSearch(context.Background(), audit.Filter{}, audit.Page{Limit: audit.MaxPageSize})
	if err != nil {
		w.t.Errorf("admin search: %v", err)
		return
	}
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

// syncBuffer is a bytes.Buffer safe for concurrent writers (the logger is
// used from many goroutines).
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

// memNotifier records unresolved-operation notifications.
type memNotifier struct {
	mu  sync.Mutex
	ops []ledger.Operation
}

func (m *memNotifier) NotifyUnresolved(_ context.Context, op ledger.Operation) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.ops = append(m.ops, op)
	return nil
}

func (m *memNotifier) list() []ledger.Operation {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]ledger.Operation(nil), m.ops...)
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

// approvalRequired asserts err is the -32005 answer and returns the id.
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
