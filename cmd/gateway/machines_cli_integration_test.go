//go:build integration

package main

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/machineclient"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// syncBuf is a goroutine-safe output buffer for Up.
type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// The real CLI against a real gateway: `mcp-gateway login --enroll-code`
// (machineclient.Login) and `mcp-gateway up` (machineclient.Up with the
// real tunnel connector) register two local HTTP servers, connect one
// machine connection, refresh them; after approval a harness calls both
// tools through /mcp. Contract drift between the two halves fails here.
func TestIntegrationMachineCLIEndToEnd(t *testing.T) {
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

	var handler atomic.Value
	public := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.Load().(http.Handler).ServeHTTP(w, r) }))
	defer public.Close()
	cfg := config.Default()
	cfg.BaseURL = public.URL
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
	if err != nil {
		t.Fatal(err)
	}
	mcpHandler, err := newMCP(cfg, registry, federationAccounts(fed, connectors.NewStaticAccountSource()), tokenSvc,
		federationDecider(fed, policySvc), nil, audit.NopRecorder{}, metrics, log, withFederationPrecheck(fed, log))
	if err != nil {
		t.Fatal(err)
	}
	handler.Store(observability.RequestID(metrics.HTTPMiddleware(
		newMux(observability.NewReadiness(time.Second), nil, mcpHandler, nil, withFederationRoutes(fed), withMachineRoutes(msvc)))))

	// Two local HTTP MCP servers on "the machine".
	one, two := httptest.NewServer(echoMCP("one")), httptest.NewServer(echoMCP("two"))
	defer one.Close()
	defer two.Close()

	home := t.TempDir()
	stateDir := filepath.Join(home, "mcp-gateway")
	code, _, err := msvc.CreateEnrollmentCode(ctx, alice, "cli", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var loginOut bytes.Buffer
	stateRes, err := machineclient.Login(ctx, machineclient.LoginOptions{
		Gateway: public.URL, Name: "ci-box", EnrollCode: code, KeyStore: machineclient.KeyStoreFile,
		StateDir: stateDir, Version: "test", Out: &loginOut, Log: log,
	})
	if err != nil {
		t.Fatalf("login: %v\n%s", err, loginOut.String())
	}
	if strings.Contains(loginOut.String(), code) {
		t.Error("login output shows the enrollment code")
	}
	if stateRes.MachineID == "" || stateRes.Name != "ci-box" {
		t.Fatalf("state = %+v", stateRes)
	}

	cfgPath := filepath.Join(home, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte("gateway: "+public.URL+"\nservers:\n  one:\n    http: "+one.URL+"\n  two:\n    http: "+two.URL+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	upCtx, stopUp := context.WithCancel(ctx)
	out, errOut := &syncBuf{}, &syncBuf{}
	upDone := make(chan error, 1)
	go func() {
		upDone <- machineclient.Up(upCtx, machineclient.UpOptions{
			ConfigPath: cfgPath, StateDir: stateDir, Version: "test", Out: out, Stderr: errOut, Log: log,
			Connector: machineclient.NewTunnelConnector(log), Environ: func() []string { return nil },
			MinBackoff: 50 * time.Millisecond, MaxBackoff: 200 * time.Millisecond,
		})
	}()

	servers := map[string]*store.MCPServer{}
	// up registers, connects and refreshes in the background (with its own
	// retries); allow for a loaded CI machine.
	waitForWithin(t, 90*time.Second, "up registers, connects and refreshes both servers", func() bool {
		for _, name := range []string{"one", "two"} {
			var srv *store.MCPServer
			if err := st.WithUser(ctx, alice, func(tx store.Tx) (err error) {
				srv, err = store.GetMCPServerByName(ctx, tx, name)
				return err
			}); err != nil || srv == nil {
				return false
			}
			servers[name] = srv
			if _, err := fed.Snapshots.Latest(ctx, snapshot.Actor{UserID: alice}, srv.ID); err != nil {
				return false
			}
		}
		return true
	})
	enabled := true
	for name, srv := range servers {
		if _, err := fed.Snapshots.Approve(ctx, snapshot.Actor{UserID: alice}, srv.ID, 1,
			snapshot.ReviewDecisions{Tools: map[string]snapshot.Decision{"echo": {Enabled: &enabled}}}); err != nil {
			t.Fatalf("approve %s: %v", name, err)
		}
		if err := fed.Manager.ServerChanged(ctx, srv.ID); err != nil {
			t.Fatal(err)
		}
	}
	if s := out.String() + errOut.String(); !strings.Contains(s, "/review") {
		t.Errorf("up printed no review link:\n%q", s)
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
	for _, name := range []string{"one", "two"} {
		if got, err := callTool(ctx, cs, name+".echo", "via the CLI"); err != nil || got != name+": via the CLI" {
			t.Fatalf("%s.echo = %q, %v\nup out:\n%s\n%s", name, got, err, out.String(), errOut.String())
		}
	}

	stopUp()
	select {
	case <-upDone:
	case <-time.After(10 * time.Second):
		t.Fatal("up did not stop")
	}
	for _, s := range []string{loginOut.String(), out.String(), errOut.String()} {
		if strings.Contains(s, "mgm_") || strings.Contains(s, "eyJ") {
			t.Errorf("CLI output leaks a token or assertion:\n%s", s)
		}
	}
}

func waitForWithin(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", d, what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
