//go:build integration

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/federation/client"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// The federation wired the way run() wires it, against its own database
// (gateway_cmd_federation_test, quirk 01mepmn6): a tunnel agent connects
// through the real mux and middleware (WebSocket upgrade through the
// metrics wrapper), a tunnel-backed server is reviewed and its tool is
// listed and called through /mcp with the official MCP client.

const (
	fedTestDB      = "gateway_cmd_federation_test"
	fedAppPassword = "gateway-app-test"
	fedJobsPass    = "gateway-jobs-test"
)

func openFederationStore(t *testing.T) *store.Store {
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
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, fedTestDB).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		if _, err := admin.Exec(ctx, `CREATE DATABASE `+fedTestDB); err != nil {
			t.Fatalf("create database: %v", err)
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + fedTestDB
	if err := migrations.Up(ctx, u.String()); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	super, err := pgx.Connect(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = super.Close(ctx) }()
	for _, stmt := range []string{
		"ALTER ROLE gateway_app LOGIN PASSWORD '" + fedAppPassword + "'",
		"ALTER ROLE gateway_jobs LOGIN PASSWORD '" + fedJobsPass + "'",
		"TRUNCATE users, roles, role_assignments, policy_versions, tokens, vendor_apps, connections, mcp_servers, mcp_tunnels, netguard_allow_hosts, audit_events CASCADE",
	} {
		var err error
		for attempt := 0; attempt < 20; attempt++ {
			if _, err = super.Exec(ctx, stmt); err == nil || !strings.Contains(err.Error(), "concurrently updated") {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	appURL, jobsURL := *u, *u
	appURL.User = url.UserPassword("gateway_app", fedAppPassword)
	jobsURL.User = url.UserPassword("gateway_jobs", fedJobsPass)
	st, err := store.New(ctx, appURL.String(), store.WithJobsURL(jobsURL.String()))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(st.Close)
	return st
}

// headerLog records the headers of every request the local server gets.
type headerLog struct {
	mu      sync.Mutex
	headers []http.Header
}

func (h *headerLog) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.mu.Lock()
		h.headers = append(h.headers, r.Header.Clone())
		h.mu.Unlock()
		next.ServeHTTP(w, r)
	})
}

func (h *headerLog) all() []http.Header {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]http.Header(nil), h.headers...)
}

type echoArgs struct {
	Text string `json:"text"`
}

func TestIntegrationFederationTunnelThroughMux(t *testing.T) {
	st := openFederationStore(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	log := slog.New(slog.DiscardHandler)
	cfg := config.Default()
	cfg.BaseURL = "http://gateway.test"
	keys, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{3}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	var alice string
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		u := &store.User{DisplayName: "Alice", Status: store.UserActive}
		if err := tx.Users().Create(ctx, u); err != nil {
			return err
		}
		alice = u.ID
		// Tokens work only for users who signed in recently.
		_, err := tx.Exec(ctx, `UPDATE users SET last_company_sign_in_at = now() WHERE id = $1`, u.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}

	metrics := observability.NewMetrics()
	tokenSvc, err := tokens.New(tokens.Config{SignInMaxAge: time.Hour}, tokens.NewPostgresStore(st), metrics, audit.NopRecorder{}, log)
	if err != nil {
		t.Fatal(err)
	}
	policySvc, err := policy.New(policy.NewPostgresStore(st), policy.Options{Log: log})
	if err != nil {
		t.Fatal(err)
	}
	registry := connectors.NewRegistry()
	fed, err := newFederation(ctx, cfg, st, keys, registry, policySvc, metrics, log)
	if err != nil || fed == nil {
		t.Fatalf("newFederation = %v, %v", fed, err)
	}
	mcpHandler, err := newMCP(cfg, registry, federationAccounts(fed, connectors.NewStaticAccountSource()), tokenSvc,
		federationDecider(fed, policySvc), nil, audit.NopRecorder{}, metrics, log)
	if err != nil {
		t.Fatal(err)
	}
	// Exactly the production handler chain.
	srv := httptest.NewServer(observability.RequestID(metrics.HTTPMiddleware(
		newMux(observability.NewReadiness(time.Second), nil, mcpHandler, nil, withFederationRoutes(fed)))))
	defer srv.Close()

	// The client metadata document is public.
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, srv.URL+auth.ClientMetadataPath, nil)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	_ = json.NewDecoder(res.Body).Decode(&doc)
	_ = res.Body.Close()
	if res.StatusCode != http.StatusOK || doc["client_id"] != cfg.BaseURL+auth.ClientMetadataPath {
		t.Errorf("client metadata = %d %v", res.StatusCode, doc)
	}

	// The tunnel agent connects through the real mux.
	tun, token, err := fed.Tunnels.CreateTunnel(ctx, alice, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	local := sdk.NewServer(&sdk.Implementation{Name: "local", Version: "1"}, nil)
	sdk.AddTool(local, &sdk.Tool{Name: "echo", Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}},
		func(_ context.Context, _ *sdk.CallToolRequest, in echoArgs) (*sdk.CallToolResult, any, error) {
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "echo: " + in.Text}}}, nil, nil
		})
	seen := &headerLog{}
	agent, err := tunnel.NewAgent(tunnel.AgentOptions{
		GatewayURL: srv.URL, Token: token, Log: log,
		Handler: seen.wrap(sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return local }, &sdk.StreamableHTTPOptions{Stateless: true, JSONResponse: true})),
	})
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = agent.Run(ctx) }()
	deadline := time.Now().Add(10 * time.Second)
	for !fed.Tunnels.Online(tun.ID) {
		if time.Now().After(deadline) {
			t.Fatal("tunnel agent never came online through the mux (WebSocket upgrade failed?)")
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Alice adds the tunnel-backed server and reviews its snapshot.
	server := &store.MCPServer{Name: "laptop", URL: tunnel.URL(tun.ID, "/"), OwnerUserID: alice,
		CredentialMode: store.MCPCredentialPerUser, AuthKind: store.MCPAuthNone}
	if err := fed.Manager.CreateServer(ctx, server); err != nil {
		t.Fatal(err)
	}
	c, err := client.New(client.Options{HTTPClient: fed.Tunnels.HTTPClient(fed.Guard.Client())})
	if err != nil {
		t.Fatal(err)
	}
	cu, _ := tunnel.ClientURL(server.URL)
	sess, err := c.Connect(ctx, client.Endpoint{URL: cu})
	if err != nil {
		t.Fatalf("connect through the tunnel: %v", err)
	}
	rec, err := fed.Snapshots.Create(ctx, snapshot.Actor{UserID: alice}, server.ID, sess)
	_ = sess.Close()
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	if _, err := fed.Snapshots.Approve(ctx, snapshot.Actor{UserID: alice}, server.ID, rec.Version,
		snapshot.ReviewDecisions{Tools: map[string]snapshot.Decision{"echo": {Enabled: &enabled}}}); err != nil {
		t.Fatal(err)
	}
	if err := fed.Manager.ServerChanged(ctx, server.ID); err != nil {
		t.Fatal(err)
	}

	// Alice's harness lists and calls laptop.echo through /mcp.
	created, err := tokenSvc.Create(ctx, alice, tokens.CreateRequest{Name: "harness"})
	if err != nil {
		t.Fatal(err)
	}
	transport := &sdk.StreamableClientTransport{Endpoint: srv.URL + "/mcp", HTTPClient: &http.Client{Transport: bearer{created.Raw}}}
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "harness", Version: "0"}, nil).Connect(ctx, transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()
	list, err := cs.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, tool := range list.Tools {
		found = found || tool.Name == "laptop.echo"
	}
	if !found {
		t.Fatalf("tools/list lacks laptop.echo: %v", list.Tools)
	}
	out, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "laptop.echo", Arguments: map[string]any{"text": "hi"}})
	if err != nil {
		t.Fatalf("call: %v", err)
	}
	if out.IsError || len(out.Content) != 1 || out.Content[0].(*sdk.TextContent).Text != "echo: hi" {
		t.Fatalf("result = %+v", out)
	}
	for _, h := range seen.all() {
		for name, vals := range h {
			for _, v := range vals {
				if strings.Contains(v, created.Raw) || strings.Contains(v, token) {
					t.Errorf("the local server received a gateway credential in %s", name)
				}
			}
		}
	}
}

// bearer adds the harness token.
type bearer struct{ token string }

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}
