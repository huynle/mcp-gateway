//go:build integration

package mcp_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/fake"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// The mcp integration test runs against its own database (gateway_mcp_test,
// created from GATEWAY_TEST_DATABASE_URL) so it never races the store
// package's TRUNCATE (quirk 01mepmn6). It needs a superuser URL and gives
// the two application roles a temporary LOGIN password.

const (
	mcpTestDB   = "gateway_mcp_test"
	appPassword = "gateway-app-test"
	jobsPass    = "gateway-jobs-test"
	dexIssuer   = "http://localhost:15556/dex"
)

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	raw := os.Getenv("GATEWAY_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("GATEWAY_TEST_DATABASE_URL not set; skipping integration test")
	}
	ctx := t.Context()
	admin, err := pgx.Connect(ctx, raw)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = admin.Close(ctx) }()
	var exists bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, mcpTestDB).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		if _, err := admin.Exec(ctx, `CREATE DATABASE `+mcpTestDB); err != nil {
			t.Fatalf("create database: %v", err)
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + mcpTestDB
	superURL := u.String()
	if err := migrations.Up(ctx, superURL); err != nil {
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
		"TRUNCATE users, identities, sessions, roles, role_assignments, tokens CASCADE",
	} {
		if err := execRetryingConcurrentUpdate(ctx, super, stmt); err != nil {
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

// TestIntegrationEndToEndWithRealToken mints a token through the tokens
// service for a user created by a company sign-in, then drives /mcp with
// the SDK client: initialize, tools/list, tools/call, and checks the audit
// rows the store recorder wrote.
func TestIntegrationEndToEndWithRealToken(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()
	log := slog.New(slog.DiscardHandler)

	idSvc, err := identity.New(identity.Config{
		BaseURL:         "http://localhost:18080",
		Providers:       []config.OIDCProvider{{Name: "dex", DisplayName: "dex", Issuer: dexIssuer, ClientID: "gateway", ClientSecret: "s", AllowedDomains: []string{"example.com"}}},
		DefaultRole:     "member",
		IdleTimeout:     12 * time.Hour,
		AbsoluteTimeout: 7 * 24 * time.Hour,
	}, identity.NewPostgresStore(st), log)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := idSvc.SignIn(ctx, "dex", identity.Claims{Issuer: dexIssuer, Subject: "alice-subject", Name: "Alice", Email: "alice@example.com", EmailVerified: true})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	alice := signed.Principal.UserID

	rec := audit.NewStoreRecorder(st)
	tokenSvc, err := tokens.New(tokens.Config{SignInMaxAge: 30 * 24 * time.Hour}, tokens.NewPostgresStore(st), observability.NewMetrics(), rec, log)
	if err != nil {
		t.Fatal(err)
	}
	created, err := tokenSvc.Create(ctx, alice, tokens.CreateRequest{Name: "laptop", ReadOnly: true})
	if err != nil {
		t.Fatalf("Create token: %v", err)
	}

	read := stubTool("github", "list_issues", connectors.KindRead)
	read.ResourceIdentity = func(args map[string]any) map[string]string {
		repo, _ := args["repo"].(string)
		return map[string]string{"repo": repo}
	}
	read.Handler = func(_ context.Context, call connectors.Call) (connectors.Result, error) {
		return connectors.Result{Content: map[string]any{"user": call.Principal.UserID, "account": call.Account, "args": call.Args}}, nil
	}
	write := stubTool("github", "create_issue", connectors.KindWrite)
	reg := newRegistry(t, read, write)
	h, err := mcp.Handler(mcp.Options{
		Registry:      reg,
		Authenticator: tokenSvc,
		Auth:          tokens.MiddlewareOptions{Limiter: tokens.NewFailureLimiter(tokens.DefaultFailureBurst, tokens.DefaultFailureWindow)},
		BaseURL:       "http://localhost:18080",
		Audit:         rec,
		Log:           log,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(observability.RequestID(h))
	defer srv.Close()

	// No token: 401 with the challenge. Well-formed but unknown token: 401.
	for _, tok := range []string{"", "mgw_" + strings.Repeat("a", 8) + "_" + strings.Repeat("b", 43)} {
		resp := post(t, srv.URL, tok, callCreateIssue)
		if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(resp.Header.Get("WWW-Authenticate"), "resource_metadata=") {
			t.Errorf("token %q: status %d, WWW-Authenticate %q", tok, resp.StatusCode, resp.Header.Get("WWW-Authenticate"))
		}
	}

	cs := connect(t, srv.URL, created.Raw, "2025-11-25")
	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(list.Tools) != 1 || list.Tools[0].Name != "github.list_issues" {
		t.Fatalf("read-only token sees %v, want only github.list_issues", list.Tools)
	}
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "github.list_issues", Arguments: map[string]any{"repo": "acme/web", "account": "acct-1", "body": "SECRET"}})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	var echo struct {
		User    string         `json:"user"`
		Account string         `json:"account"`
		Args    map[string]any `json:"args"`
	}
	if err := json.Unmarshal([]byte(text(t, res)), &echo); err != nil {
		t.Fatal(err)
	}
	if echo.User != alice || echo.Account != "acct-1" || echo.Args["repo"] != "acme/web" {
		t.Errorf("echo = %+v", echo)
	}
	if _, ok := echo.Args["account"]; ok {
		t.Error("account reached the handler")
	}
	if _, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "github.create_issue", Arguments: map[string]any{}}); err == nil || !strings.Contains(err.Error(), "unknown tool") {
		t.Errorf("hidden write tool: err = %v", err)
	}

	// The audit trail: token_created (user event) plus one tool_call per
	// call, newest first, with metadata only.
	events, err := rec.ListForUser(ctx, alice, audit.Filter{}, audit.Page{})
	if err != nil {
		t.Fatal(err)
	}
	var calls []audit.Record
	for _, ev := range events {
		if ev.EventType == audit.EventTypeToolCall {
			calls = append(calls, ev)
		}
	}
	if len(calls) != 2 {
		t.Fatalf("tool_call events = %d, want 2: %+v", len(calls), events)
	}
	denied, ok := calls[0], calls[1]
	if ok.Tool != "github.list_issues" || ok.UserID != alice || ok.TokenID != created.Token.ID || ok.Decision != "allow" || ok.Outcome != "succeeded" {
		t.Errorf("successful call audit = %+v", ok)
	}
	if ok.ResourceIdentity["repo"] != "acme/web" || len(ok.ResourceIdentity) != 1 {
		t.Errorf("resource identity = %v", ok.ResourceIdentity)
	}
	if ok.RequestID == "" {
		t.Error("request id missing from audit row")
	}
	if denied.Tool != "github.create_issue" || denied.Decision != "deny" || denied.Outcome != "denied" || denied.ErrorClass != "tool_not_found" {
		t.Errorf("denied call audit = %+v", denied)
	}
	for _, ev := range calls {
		raw, _ := json.Marshal(ev)
		if strings.Contains(string(raw), "SECRET") {
			t.Errorf("argument content reached the audit table: %s", raw)
		}
	}
}

// TestIntegrationFakeConnectorAccountsAndAudit registers the fake
// connector the way cmd/gateway does, drives it with a real token through
// the SDK client, and checks the audit rows carry the resolved account.
func TestIntegrationFakeConnectorAccountsAndAudit(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()
	log := slog.New(slog.DiscardHandler)

	idSvc, err := identity.New(identity.Config{
		BaseURL:         "http://localhost:18080",
		Providers:       []config.OIDCProvider{{Name: "dex", DisplayName: "dex", Issuer: dexIssuer, ClientID: "gateway", ClientSecret: "s", AllowedDomains: []string{"example.com"}}},
		DefaultRole:     "member",
		IdleTimeout:     12 * time.Hour,
		AbsoluteTimeout: 7 * 24 * time.Hour,
	}, identity.NewPostgresStore(st), log)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := idSvc.SignIn(ctx, "dex", identity.Claims{Issuer: dexIssuer, Subject: "bob-subject", Name: "Bob", Email: "bob@example.com", EmailVerified: true})
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	bob := signed.Principal.UserID
	rec := audit.NewStoreRecorder(st)
	tokenSvc, err := tokens.New(tokens.Config{SignInMaxAge: 30 * 24 * time.Hour}, tokens.NewPostgresStore(st), observability.NewMetrics(), rec, log)
	if err != nil {
		t.Fatal(err)
	}
	created, err := tokenSvc.Create(ctx, bob, tokens.CreateRequest{Name: "laptop"})
	if err != nil {
		t.Fatalf("Create token: %v", err)
	}

	f := fake.New(fake.Options{})
	// Account IDs are connection UUIDs: audit_events.connection_id is uuid.
	bobAcct := f.SeedAccount(bob, connectors.Account{Label: connectors.LabelPersonal, DisplayName: "Bob's fake"})
	reg := connectors.NewRegistry()
	if err := connectors.RegisterConnector(reg, f, f.Accounts()); err != nil {
		t.Fatal(err)
	}
	h, err := mcp.Handler(mcp.Options{
		Registry:      reg,
		Authenticator: tokenSvc,
		Auth:          tokens.MiddlewareOptions{Limiter: tokens.NewFailureLimiter(tokens.DefaultFailureBurst, tokens.DefaultFailureWindow)},
		BaseURL:       "http://localhost:18080",
		Accounts:      f.Accounts(),
		RateLimiter:   mcp.NewRateLimiter(mcp.RateLimitConfig{}),
		Audit:         rec,
		Log:           log,
	})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(observability.RequestID(h))
	defer srv.Close()

	cs := connect(t, srv.URL, created.Raw, "2025-11-25")
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.list_accounts"})
	if err != nil || !strings.Contains(text(t, res), `"`+bobAcct.ID+`"`) {
		t.Fatalf("list_accounts: err=%v text=%q", err, text(t, res))
	}
	if res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.create_item", Arguments: map[string]any{"id": "it-1", "name": "first", "body": "SECRET BODY"}}); err != nil || res.IsError {
		t.Fatalf("create_item: err=%v res=%+v", err, res)
	}
	res, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "fake.list_items"})
	if err != nil || res.IsError || !strings.Contains(text(t, res), `"it-1"`) {
		t.Fatalf("list_items: err=%v text=%q", err, text(t, res))
	}

	events, err := rec.ListForUser(ctx, bob, audit.Filter{}, audit.Page{})
	if err != nil {
		t.Fatal(err)
	}
	var calls []audit.Record
	for _, ev := range events {
		if ev.EventType == audit.EventTypeToolCall {
			calls = append(calls, ev)
		}
	}
	if len(calls) != 3 {
		t.Fatalf("tool_call events = %d, want 3: %+v", len(calls), calls)
	}
	for _, ev := range calls {
		if ev.Outcome != "succeeded" || ev.UserID != bob {
			t.Errorf("audit = %+v", ev)
		}
		switch ev.Tool {
		case "fake.list_accounts":
			if ev.AccountID != "" {
				t.Errorf("list_accounts recorded an account: %+v", ev)
			}
		default:
			if ev.AccountID != bobAcct.ID || ev.AccountLabel != "personal" {
				t.Errorf("%s audit account = %q/%q, want %s/personal", ev.Tool, ev.AccountID, ev.AccountLabel, bobAcct.ID)
			}
		}
		raw, _ := json.Marshal(ev)
		if strings.Contains(string(raw), "SECRET") {
			t.Errorf("argument content reached the audit table: %s", raw)
		}
	}
}

// execRetryingConcurrentUpdate runs stmt, retrying when PostgreSQL reports
// "tuple concurrently updated" (SQLSTATE XX000): every package's
// integration bootstrap ALTERs the same cluster-global roles and `go test`
// runs packages in parallel.
func execRetryingConcurrentUpdate(ctx context.Context, conn *pgx.Conn, stmt string) error {
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		if _, err = conn.Exec(ctx, stmt); err == nil || !strings.Contains(err.Error(), "concurrently updated") {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return err
}
