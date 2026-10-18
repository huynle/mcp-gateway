//go:build integration

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/federation/client"
	"github.com/huynle/mcp-gateway/internal/federation/connector"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// Two gateway replicas wired the way run() wires them share one database
// (decision efq0ncag item 5): the tunnel client connects to A, the
// harness's tool call goes through B, and B forwards it to A over the
// internal relay listener. Then the client reconnects to B (handover) and
// calls through A work; a revocation on one replica stops both.

const testRelaySecret = "integration-relay-secret-0123456789abcdef"

// replicaGW is one in-process gateway replica.
type replicaGW struct {
	fed    *connector.Federation
	public *httptest.Server // production handler chain (newMux)
	relay  *httptest.Server // the internal relay listener
}

func newReplicaGW(t *testing.T, ctx context.Context, st *store.Store, keys crypto.KeyProvider, tokenSvc *tokens.Service, relayOn bool) *replicaGW {
	t.Helper()
	log := slog.New(slog.DiscardHandler)
	var relayHandler atomic.Value
	relaySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		relayHandler.Load().(http.Handler).ServeHTTP(w, r)
	}))
	t.Cleanup(relaySrv.Close)
	cfg := config.Default()
	cfg.BaseURL = "http://gateway.test"
	if relayOn {
		cfg.RelayListenAddr, cfg.RelayAdvertiseAddr, cfg.RelaySecret = "127.0.0.1:0", relaySrv.URL, testRelaySecret
	}
	metrics := observability.NewMetrics()
	policySvc, err := policy.New(policy.NewPostgresStore(st), policy.Options{Log: log})
	if err != nil {
		t.Fatal(err)
	}
	registry := connectors.NewRegistry()
	fed, err := newFederation(ctx, cfg, st, keys, registry, policySvc, nil, metrics, log)
	if err != nil || fed == nil {
		t.Fatalf("newFederation = %v, %v", fed, err)
	}
	if fed.Tunnels.RelayEnabled() != relayOn {
		t.Fatalf("RelayEnabled = %v, want %v", fed.Tunnels.RelayEnabled(), relayOn)
	}
	relayHandler.Store(newRelayHandler(fed))
	mcpHandler, err := newMCP(cfg, registry, federationAccounts(fed, connectors.NewStaticAccountSource()), tokenSvc,
		federationDecider(fed, policySvc), nil, audit.NopRecorder{}, metrics, log, withFederationPrecheck(fed, log))
	if err != nil {
		t.Fatal(err)
	}
	public := httptest.NewServer(observability.RequestID(metrics.HTTPMiddleware(
		newMux(observability.NewReadiness(time.Second), nil, mcpHandler, nil, withFederationRoutes(fed)))))
	t.Cleanup(public.Close)
	return &replicaGW{fed: fed, public: public, relay: relaySrv}
}

func (g *replicaGW) harness(t *testing.T, ctx context.Context, token string) *sdk.ClientSession {
	t.Helper()
	transport := &sdk.StreamableClientTransport{Endpoint: g.public.URL + "/mcp", HTTPClient: &http.Client{Transport: bearer{token}}}
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "harness", Version: "0"}, nil).Connect(ctx, transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func callEcho(ctx context.Context, cs *sdk.ClientSession, text string) (string, error) {
	out, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: "laptop.echo", Arguments: map[string]any{"text": text}})
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, c := range out.Content {
		if tc, ok := c.(*sdk.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	if out.IsError {
		return "error: " + b.String(), nil
	}
	return b.String(), nil
}

func startEchoAgent(t *testing.T, ctx context.Context, gatewayURL, token string) (stop func()) {
	t.Helper()
	local := sdk.NewServer(&sdk.Implementation{Name: "local", Version: "1"}, nil)
	sdk.AddTool(local, &sdk.Tool{Name: "echo", Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}},
		func(_ context.Context, _ *sdk.CallToolRequest, in echoArgs) (*sdk.CallToolResult, any, error) {
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "echo: " + in.Text}}}, nil, nil
		})
	agent, err := tunnel.NewAgent(tunnel.AgentOptions{
		GatewayURL: gatewayURL, Token: token, Log: slog.New(slog.DiscardHandler),
		Handler: sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return local }, &sdk.StreamableHTTPOptions{Stateless: true, JSONResponse: true}),
	})
	if err != nil {
		t.Fatal(err)
	}
	actx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { _ = agent.Run(actx); close(done) }()
	return func() { cancel(); <-done }
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestIntegrationTunnelRelayAcrossReplicas(t *testing.T) {
	st := openFederationStore(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	keys, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{3}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	alice := newServerBuilder(t, st)
	tokenSvc, err := tokens.New(tokens.Config{SignInMaxAge: time.Hour}, tokens.NewPostgresStore(st), observability.NewMetrics(), audit.NopRecorder{}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	a := newReplicaGW(t, ctx, st, keys, tokenSvc, true)
	b := newReplicaGW(t, ctx, st, keys, tokenSvc, true)

	// The tunnel client connects to A.
	tun, token, err := a.fed.Tunnels.CreateTunnel(ctx, alice, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	stopA := startEchoAgent(t, ctx, a.public.URL, token)
	waitFor(t, "B sees the tunnel held by A", func() bool { return b.fed.Tunnels.Online(tun.ID) })

	// Alice adds and reviews the server on B: the snapshot itself already
	// travels B -> relay -> A -> tunnel.
	server := &store.MCPServer{Name: "laptop", URL: tunnel.URL(tun.ID, "/"), OwnerUserID: alice,
		CredentialMode: store.MCPCredentialPerUser, AuthKind: store.MCPAuthNone}
	if err := b.fed.Manager.CreateServer(ctx, server); err != nil {
		t.Fatal(err)
	}
	c, err := client.New(client.Options{HTTPClient: b.fed.Tunnels.HTTPClient(b.fed.Guard.Client())})
	if err != nil {
		t.Fatal(err)
	}
	cu, _ := tunnel.ClientURL(server.URL)
	sess, err := c.Connect(ctx, client.Endpoint{URL: cu})
	if err != nil {
		t.Fatalf("connect through B to the tunnel held by A: %v", err)
	}
	rec, err := b.fed.Snapshots.Create(ctx, snapshot.Actor{UserID: alice}, server.ID, sess)
	_ = sess.Close()
	if err != nil {
		t.Fatal(err)
	}
	enabled := true
	if _, err := b.fed.Snapshots.Approve(ctx, snapshot.Actor{UserID: alice}, server.ID, rec.Version,
		snapshot.ReviewDecisions{Tools: map[string]snapshot.Decision{"echo": {Enabled: &enabled}}}); err != nil {
		t.Fatal(err)
	}
	for _, g := range []*replicaGW{a, b} {
		if err := g.fed.Manager.ServerChanged(ctx, server.ID); err != nil {
			t.Fatal(err)
		}
	}
	created, err := tokenSvc.Create(ctx, alice, tokens.CreateRequest{Name: "harness"})
	if err != nil {
		t.Fatal(err)
	}

	// The tool call goes through B.
	if got, err := callEcho(ctx, b.harness(t, ctx, created.Raw), "via B"); err != nil || got != "echo: via B" {
		t.Fatalf("call through B = %q, %v", got, err)
	}
	// And through A, which holds the connection, as before.
	if got, err := callEcho(ctx, a.harness(t, ctx, created.Raw), "via A"); err != nil || got != "echo: via A" {
		t.Fatalf("call through A = %q, %v", got, err)
	}

	// Handover: the client reconnects to B; calls through A now relay to B.
	stopA()
	waitFor(t, "A drops the connection", func() bool { return !a.fed.Tunnels.Online(tun.ID) })
	stopB := startEchoAgent(t, ctx, b.public.URL, token)
	defer stopB()
	waitFor(t, "A sees the tunnel held by B", func() bool { return a.fed.Tunnels.Online(tun.ID) })
	if got, err := callEcho(ctx, a.harness(t, ctx, created.Raw), "after handover"); err != nil || got != "echo: after handover" {
		t.Fatalf("call through A after handover = %q, %v", got, err)
	}

	// The relay listener refuses unsigned requests; the public mux does not
	// serve the relay path at all.
	for name, u := range map[string]string{"relay listener": b.relay.URL, "public mux": b.public.URL} {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, u+tunnel.RelayPath, strings.NewReader("x"))
		req.Header.Set("X-Mgw-Relay-Tunnel", tun.ID)
		req.Header.Set("X-Mgw-Relay-Epoch", "1")
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, res.Body)
		_ = res.Body.Close()
		switch name {
		case "relay listener":
			if res.StatusCode != http.StatusUnauthorized {
				t.Errorf("unsigned relay request: %d, want 401", res.StatusCode)
			}
		default:
			if res.Header.Get("X-Mgw-Relay-Error") != "" || res.StatusCode != http.StatusNotFound {
				t.Errorf("public mux answered the relay path: %d %v", res.StatusCode, res.Header)
			}
		}
	}

	// Revocation on A stops calls on both replicas.
	if err := a.fed.Tunnels.Revoke(ctx, alice, tun.ID); err != nil {
		t.Fatal(err)
	}
	for name, g := range map[string]*replicaGW{"A": a, "B": b} {
		got, err := callEcho(ctx, g.harness(t, ctx, created.Raw), "revoked")
		if err == nil && strings.HasPrefix(got, "echo:") {
			t.Errorf("call through %s after revoke succeeded: %q", name, got)
		}
	}
	if a.fed.Tunnels.Online(tun.ID) {
		t.Error("A reports the revoked tunnel online")
	}
}

// A replica without relay settings keeps the single-replica behaviour:
// tunnels held by another replica are offline there.
func TestIntegrationTunnelRelayDisabled(t *testing.T) {
	st := openFederationStore(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	keys, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{3}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	alice := newServerBuilder(t, st)
	tokenSvc, err := tokens.New(tokens.Config{SignInMaxAge: time.Hour}, tokens.NewPostgresStore(st), observability.NewMetrics(), audit.NopRecorder{}, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	a := newReplicaGW(t, ctx, st, keys, tokenSvc, false)
	b := newReplicaGW(t, ctx, st, keys, tokenSvc, false)
	tun, token, err := a.fed.Tunnels.CreateTunnel(ctx, alice, "laptop")
	if err != nil {
		t.Fatal(err)
	}
	stop := startEchoAgent(t, ctx, a.public.URL, token)
	defer stop()
	waitFor(t, "online on A", func() bool { return a.fed.Tunnels.Online(tun.ID) })
	if b.fed.Tunnels.Online(tun.ID) {
		t.Fatal("relay off: B reports A's tunnel online")
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, tunnel.URL(tun.ID, "/"), nil)
	res, err := b.fed.Tunnels.HTTPClient(nil).Do(req)
	if res != nil {
		_ = res.Body.Close()
	}
	if te := (*tunnel.Error)(nil); !errors.As(err, &te) || te.Class != tunnel.ClassOffline {
		t.Fatalf("relay off: through B = %v, want tunnel_offline", err)
	}
	var n int
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM mcp_tunnel_holders`).Scan(&n)
	}); err != nil || n != 0 {
		t.Fatalf("relay off: %d holder rows (%v), want none", n, err)
	}
}

// newServerBuilder creates an active user who may add MCP servers and
// signed in recently.
func newServerBuilder(t *testing.T, st *store.Store) string {
	t.Helper()
	ctx := t.Context()
	var id string
	if err := st.WithJobs(ctx, func(tx store.Tx) error {
		u := &store.User{DisplayName: "Alice", Status: store.UserActive}
		if err := tx.Users().Create(ctx, u); err != nil {
			return err
		}
		id = u.ID
		if err := store.UpsertRole(ctx, tx, "server_builders", "", nil, true); err != nil {
			return err
		}
		role, err := store.FindRoleByName(ctx, tx, "server_builders")
		if err != nil {
			return err
		}
		if err := store.AssignRoleIfMissing(ctx, tx, u.ID, role.ID, nil); err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `UPDATE users SET last_company_sign_in_at = now() WHERE id = $1`, u.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return id
}
