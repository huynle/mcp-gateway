//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/federation/connector"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
	"github.com/huynle/mcp-gateway/internal/machines"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// Two replicas wired like run() share one database: a machine enrolls
// and registers two servers on A, connects its one WebSocket to A, and
// refreshes and serves both servers through B (relay); revoking the
// machine on A closes the connection and stops both servers everywhere.

const machinesBase = "http://gateway.test"

type machineReplica struct {
	fed      *connector.Federation
	machines *machines.Service
	public   *httptest.Server
}

func newMachineReplica(t *testing.T, ctx context.Context, st *store.Store, keys crypto.KeyProvider, tokenSvc *tokens.Service) *machineReplica {
	t.Helper()
	log := slog.New(slog.DiscardHandler)
	var relayHandler atomic.Value
	relaySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		relayHandler.Load().(http.Handler).ServeHTTP(w, r)
	}))
	t.Cleanup(relaySrv.Close)
	cfg := config.Default()
	cfg.BaseURL = machinesBase
	cfg.RelayListenAddr, cfg.RelayAdvertiseAddr, cfg.RelaySecret = "127.0.0.1:0", relaySrv.URL, testRelaySecret
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
	relayHandler.Store(newRelayHandler(fed))
	msvc, err := newMachines(cfg, st, fed, nil, audit.NopRecorder{}, log)
	if err != nil || msvc == nil {
		t.Fatalf("newMachines = %v, %v", msvc, err)
	}
	mcpHandler, err := newMCP(cfg, registry, federationAccounts(fed, connectors.NewStaticAccountSource()), tokenSvc,
		federationDecider(fed, policySvc), nil, audit.NopRecorder{}, metrics, log, withFederationPrecheck(fed, log))
	if err != nil {
		t.Fatal(err)
	}
	public := httptest.NewServer(observability.RequestID(metrics.HTTPMiddleware(
		newMux(observability.NewReadiness(time.Second), nil, mcpHandler, nil, withFederationRoutes(fed), withMachineRoutes(msvc)))))
	t.Cleanup(public.Close)
	return &machineReplica{fed: fed, machines: msvc, public: public}
}

func machineCall(t *testing.T, base, method, path, token, ctype, body string) (int, map[string]any) {
	t.Helper()
	req, _ := http.NewRequestWithContext(t.Context(), method, base+path, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	b, _ := io.ReadAll(res.Body)
	out := map[string]any{}
	_ = json.Unmarshal(b, &out)
	return res.StatusCode, out
}

func machineToken(t *testing.T, base string, priv ed25519.PrivateKey, machineID string) string {
	t.Helper()
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, (&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	raw, err := jwt.Signed(sig).Claims(map[string]any{
		"iss": machineID, "sub": machineID, "aud": machinesBase + machines.TokenPath,
		"iat": now.Unix(), "exp": now.Add(time.Minute).Unix(), "jti": rand.Text(),
	}).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	code, out := machineCall(t, base, http.MethodPost, machines.TokenPath, "", "application/x-www-form-urlencoded",
		url.Values{"grant_type": {machines.GrantJWTBearer}, "assertion": {raw}}.Encode())
	if code != http.StatusOK {
		t.Fatalf("machine token on %s = %d %v", base, code, out)
	}
	return out["access_token"].(string)
}

func echoMCP(name string) http.Handler {
	local := sdk.NewServer(&sdk.Implementation{Name: name, Version: "1"}, nil)
	sdk.AddTool(local, &sdk.Tool{Name: "echo", Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}},
		func(_ context.Context, _ *sdk.CallToolRequest, in echoArgs) (*sdk.CallToolResult, any, error) {
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: name + ": " + in.Text}}}, nil, nil
		})
	return sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return local }, &sdk.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
}

func callTool(ctx context.Context, cs *sdk.ClientSession, tool, text string) (string, error) {
	out, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: tool, Arguments: map[string]any{"text": text}})
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

func TestIntegrationMachineConnectionRelayAcrossReplicas(t *testing.T) {
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
	a := newMachineReplica(t, ctx, st, keys, tokenSvc)
	b := newMachineReplica(t, ctx, st, keys, tokenSvc)

	// Enroll with a one-time code on A.
	code, _, err := a.machines.CreateEnrollmentCode(ctx, alice, "ci", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	jwk := machines.PublicJWK(pub)
	status, out := machineCall(t, a.public.URL, http.MethodPost, machines.EnrollPath, "", "application/json",
		`{"code":"`+code+`","name":"laptop","public_key":`+string(jwk)+`,"client_version":"test"}`)
	if status != http.StatusOK {
		t.Fatalf("enroll = %d %v", status, out)
	}
	machineID := out["machine_id"].(string)

	// Register two servers on A.
	tokA := machineToken(t, a.public.URL, priv, machineID)
	tunnels := map[string]string{}
	for _, name := range []string{"one", "two"} {
		status, out := machineCall(t, a.public.URL, http.MethodPut, "/machine/v1/servers/"+name, tokA, "application/json", `{"kind":"http","path":"/"}`)
		if status != http.StatusOK || out["created"] != true {
			t.Fatalf("PUT %s = %d %v", name, status, out)
		}
		tunnels[name] = out["tunnel_id"].(string)
	}

	// One connection to A for both.
	agent, err := tunnel.NewMachineAgent(tunnel.MachineAgentOptions{
		GatewayURL: a.public.URL, Log: slog.New(slog.DiscardHandler),
		Token:   func(context.Context) (string, error) { return machineToken(t, a.public.URL, priv, machineID), nil },
		Targets: map[string]http.Handler{tunnels["one"]: echoMCP("one"), tunnels["two"]: echoMCP("two")},
	})
	if err != nil {
		t.Fatal(err)
	}
	agentDone := make(chan error, 1)
	go func() { agentDone <- agent.Run(ctx) }()
	waitFor(t, "B sees both tunnels", func() bool { return b.fed.Tunnels.Online(tunnels["one"]) && b.fed.Tunnels.Online(tunnels["two"]) })

	// Refresh both through B (relayed to A) and approve.
	tokB := machineToken(t, b.public.URL, priv, machineID)
	enabled := true
	for _, name := range []string{"one", "two"} {
		status, out := machineCall(t, b.public.URL, http.MethodPost, "/machine/v1/servers/"+name+"/refresh", tokB, "", "")
		if status != http.StatusOK || out["version"] != float64(1) {
			t.Fatalf("refresh %s through B = %d %v", name, status, out)
		}
		var srv *store.MCPServer
		if err := st.WithUser(ctx, alice, func(tx store.Tx) (err error) {
			srv, err = store.GetMCPServerByName(ctx, tx, name)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := b.fed.Snapshots.Approve(ctx, snapshot.Actor{UserID: alice}, srv.ID, 1,
			snapshot.ReviewDecisions{Tools: map[string]snapshot.Decision{"echo": {Enabled: &enabled}}}); err != nil {
			t.Fatal(err)
		}
		for _, g := range []*machineReplica{a, b} {
			if err := g.fed.Manager.ServerChanged(ctx, srv.ID); err != nil {
				t.Fatal(err)
			}
		}
	}
	status, out = machineCall(t, b.public.URL, http.MethodGet, "/machine/v1/self", tokB, "", "")
	if servers, _ := out["servers"].([]any); status != http.StatusOK || len(servers) != 2 {
		t.Fatalf("self through B = %d %v", status, out)
	}

	created, err := tokenSvc.Create(ctx, alice, tokens.CreateRequest{Name: "harness"})
	if err != nil {
		t.Fatal(err)
	}
	transport := &sdk.StreamableClientTransport{Endpoint: b.public.URL + "/mcp", HTTPClient: &http.Client{Transport: bearer{created.Raw}}}
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "harness", Version: "0"}, nil).Connect(ctx, transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()
	for _, name := range []string{"one", "two"} {
		if got, err := callTool(ctx, cs, name+".echo", "via B"); err != nil || got != name+": via B" {
			t.Fatalf("%s.echo through B = %q, %v", name, got, err)
		}
	}

	// The machine token is useless at /mcp.
	mt := &sdk.StreamableClientTransport{Endpoint: b.public.URL + "/mcp", HTTPClient: &http.Client{Transport: bearer{tokB}}}
	if _, err := sdk.NewClient(&sdk.Implementation{Name: "m", Version: "0"}, nil).Connect(ctx, mt, nil); err == nil {
		t.Fatal("a machine token opened an MCP session")
	}

	// Revoke on A: the connection closes as revoked, both servers stop.
	if err := a.machines.Revoke(ctx, machineID, alice, alice, store.MachineRevokedByOwner); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-agentDone:
		if !errors.Is(err, tunnel.ErrRevoked) {
			t.Fatalf("agent ended with %v, want ErrRevoked", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the machine connection survived its revocation")
	}
	for _, name := range []string{"one", "two"} {
		got, err := callTool(ctx, cs, name+".echo", "revoked")
		if err == nil && strings.HasPrefix(got, name+":") {
			t.Errorf("%s.echo after revoke succeeded: %q", name, got)
		}
	}
	if status, out := machineCall(t, b.public.URL, http.MethodGet, "/machine/v1/self", tokB, "", ""); status != http.StatusForbidden {
		t.Fatalf("self after revoke = %d %v", status, out)
	}
}
