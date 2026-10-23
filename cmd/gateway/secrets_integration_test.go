//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
	"github.com/huynle/mcp-gateway/internal/machineclient"
	"github.com/huynle/mcp-gateway/internal/machines"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/secrets"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// TestIntegrationSecretThroughMachineAction: with GATEWAY_SECRETS_ENABLED
// the gateway wired by newSecrets / withSecretStage delivers a secret
// bound to a machine action through the machine connection: the action
// (a fixed `tee <file>` reading the secret on stdin) gets the plaintext,
// the agent's result does not hold it, and the one use is spent.
func TestIntegrationSecretThroughMachineAction(t *testing.T) {
	st := openFederationStore(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	log := slog.New(slog.DiscardHandler)
	keys, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{5}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	alice := newServerBuilder(t, st)
	tokenSvc, err := tokens.New(tokens.Config{SignInMaxAge: time.Hour}, tokens.NewPostgresStore(st), observability.NewMetrics(), audit.NopRecorder{}, log)
	if err != nil {
		t.Fatal(err)
	}

	// The gateway, wired like run() with the feature on.
	cfg := config.Default()
	cfg.BaseURL = machinesBase
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
	msvc, err := newMachines(cfg, st, fed, nil, audit.NopRecorder{}, log)
	if err != nil || msvc == nil {
		t.Fatalf("newMachines = %v, %v", msvc, err)
	}
	decider := federationDecider(fed, policySvc)
	env := map[string]string{secrets.EnvEnabled: "true"}
	feature, err := newSecrets(cfg, st, keys, fed, registry, mcp.PolicyVisibility{Decider: decider, Log: log}, audit.NopRecorder{},
		func(k string) string { return env[k] }, log)
	if err != nil || feature == nil {
		t.Fatalf("newSecrets = %v, %v", feature, err)
	}
	mcpHandler, err := newMCP(cfg, registry, federationAccounts(fed, connectors.NewStaticAccountSource()), tokenSvc,
		decider, nil, audit.NopRecorder{}, metrics, log, withFederationPrecheck(fed, log), withSecretStage(feature))
	if err != nil {
		t.Fatal(err)
	}
	public := httptest.NewServer(observability.RequestID(metrics.HTTPMiddleware(
		newMux(observability.NewReadiness(time.Second), nil, mcpHandler, nil, withFederationRoutes(fed), withMachineRoutes(msvc)))))
	t.Cleanup(public.Close)

	// Enroll a machine and register its actions server.
	code, _, err := msvc.CreateEnrollmentCode(ctx, alice, "ci", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	status, out := machineCall(t, public.URL, http.MethodPost, machines.EnrollPath, "", "application/json",
		`{"code":"`+code+`","name":"laptop","public_key":`+string(machines.PublicJWK(pub))+`,"client_version":"test"}`)
	if status != http.StatusOK {
		t.Fatalf("enroll = %d %v", status, out)
	}
	machineID := out["machine_id"].(string)
	tok := machineToken(t, public.URL, priv, machineID)
	const server = "laptop-actions"
	status, out = machineCall(t, public.URL, http.MethodPut, "/machine/v1/servers/"+server, tok, "application/json", `{"kind":"http","path":"/"}`)
	if status != http.StatusOK {
		t.Fatalf("PUT %s = %d %v", server, status, out)
	}
	tunnelID := out["tunnel_id"].(string)

	stash := filepath.Join(t.TempDir(), "stash.txt")
	mc, err := machineclient.ParseConfig([]byte("actions:\n  stash:\n    run: /usr/bin/tee " + stash + "\n    secret: stdin\n"))
	if err != nil {
		t.Fatal(err)
	}
	agent, err := tunnel.NewMachineAgent(tunnel.MachineAgentOptions{
		GatewayURL: public.URL, Log: log,
		Token:   func(context.Context) (string, error) { return machineToken(t, public.URL, priv, machineID), nil },
		Targets: map[string]http.Handler{tunnelID: machineclient.NewActionsHandler(mc.Actions, machineclient.ActionsOptions{Version: "test"})},
	})
	if err != nil {
		t.Fatal(err)
	}
	agentDone := make(chan error, 1)
	go func() { agentDone <- agent.Run(ctx) }()
	defer func() {
		cancel()
		<-agentDone
	}()
	waitFor(t, "the machine is online", func() bool { return fed.Tunnels.Online(tunnelID) })

	// Discover and approve the action (a write) to run without asking.
	status, out = machineCall(t, public.URL, http.MethodPost, "/machine/v1/servers/"+server+"/refresh", tok, "", "")
	if status != http.StatusOK {
		t.Fatalf("refresh = %d %v", status, out)
	}
	var srv *store.MCPServer
	if err := st.WithUser(ctx, alice, func(tx store.Tx) (err error) {
		srv, err = store.GetMCPServerByName(ctx, tx, server)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	on, auto := true, snapshot.ApprovalAuto
	if _, err := fed.Snapshots.Approve(ctx, snapshot.Actor{UserID: alice}, srv.ID, 1,
		snapshot.ReviewDecisions{Tools: map[string]snapshot.Decision{"stash": {Enabled: &on, Approval: &auto}}}); err != nil {
		t.Fatal(err)
	}
	if err := fed.Manager.ServerChanged(ctx, srv.ID); err != nil {
		t.Fatal(err)
	}

	created, err := tokenSvc.Create(ctx, alice, tokens.CreateRequest{Name: "harness"})
	if err != nil {
		t.Fatal(err)
	}
	transport := &sdk.StreamableClientTransport{Endpoint: public.URL + "/mcp", HTTPClient: &http.Client{Transport: bearer{created.Raw}}}
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "harness", Version: "0"}, nil).Connect(ctx, transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()

	// Request, provide (the entry page's Provide), use.
	tool := server + ".stash"
	_, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: "secrets.request",
		Arguments: map[string]any{"label": "sudo password", "tool": tool, "arg": machineclient.SecretArg}})
	var je *jsonrpc.Error
	if !errors.As(err, &je) || je.Code != mcp.CodeSecretRequired {
		t.Fatalf("secrets.request = %v, want -32042", err)
	}
	var ask struct{ URL, Handle string }
	if err := json.Unmarshal(je.Data, &ask); err != nil {
		t.Fatal(err)
	}
	const value = "machine sudo p@ss/word+1"
	if _, err := feature.svc.Provide(ctx, alice, strings.TrimPrefix(ask.URL, machinesBase+"/s/"), []byte(value)); err != nil {
		t.Fatalf("provide: %v", err)
	}
	args := map[string]any{machineclient.SecretArg: map[string]any{"$secret": ask.Handle}}
	res, err := cs.CallTool(ctx, &sdk.CallToolParams{Name: tool, Arguments: args})
	if err != nil || res.IsError {
		t.Fatalf("%s with the handle = %+v, %v", tool, res, err)
	}
	wire, _ := json.Marshal(res)
	if strings.Contains(string(wire), "p@ss") || !strings.Contains(string(wire), "[secret]") {
		t.Errorf("agent result = %s, want the value scrubbed", wire)
	}
	got, err := os.ReadFile(stash) //nolint:gosec // the test's own temp file
	if err != nil || string(got) != value+"\n" {
		t.Fatalf("the action received %q (%v), want the value on stdin", got, err)
	}

	// One use: the second call is refused before reaching the machine.
	if err := os.Remove(stash); err != nil {
		t.Fatal(err)
	}
	_, err = cs.CallTool(ctx, &sdk.CallToolParams{Name: tool, Arguments: args})
	if !errors.As(err, &je) || je.Code != mcp.CodeSecretUnavailable {
		t.Fatalf("second use = %v, want -32037", err)
	}
	if _, err := os.Stat(stash); !os.IsNotExist(err) {
		t.Error("the action ran again for a used-up secret")
	}
}
