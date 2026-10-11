package main

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/policy/policytest"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// oneToken authenticates the bearer "t" as user-1.
type oneToken struct{}

func (oneToken) Authenticate(_ context.Context, bearer string) (*tokens.Principal, error) {
	if bearer == "t" {
		return &tokens.Principal{UserID: "user-1", TokenID: "token-1"}, nil
	}
	return nil, &tokens.Error{Reason: tokens.ReasonUnknown}
}

// oneResource serves mem://x.
type oneResource struct{}

func (oneResource) ListResources(context.Context, *tokens.Principal) ([]*sdk.Resource, error) {
	return []*sdk.Resource{{URI: "mem://x", Name: "mem.x"}}, nil
}
func (oneResource) ListResourceTemplates(context.Context, *tokens.Principal) ([]*sdk.ResourceTemplate, error) {
	return nil, nil
}
func (oneResource) ListPrompts(context.Context, *tokens.Principal) ([]*sdk.Prompt, error) {
	return nil, nil
}
func (oneResource) ReadResource(ctx context.Context, _ *tokens.Principal, uri string, admit mcp.Admit) (*sdk.ReadResourceResult, error) {
	if err := admit(ctx, mcp.Access{Name: "mem.resources/read", ResourceIdentity: map[string]string{"server": "mem"}}); err != nil {
		return nil, err
	}
	return &sdk.ReadResourceResult{Contents: []*sdk.ResourceContents{{URI: uri, Text: "x"}}}, nil
}
func (oneResource) GetPrompt(context.Context, *tokens.Principal, string, map[string]string, mcp.Admit) (*sdk.GetPromptResult, error) {
	return nil, mcp.ErrPromptNotFound("")
}

type lockedRecorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *lockedRecorder) Record(_ context.Context, ev audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
	return nil
}

func bearerHTTP(token string) *http.Client {
	return &http.Client{Transport: resRoundTrip(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		r.Header.Set("Authorization", "Bearer "+token)
		return http.DefaultTransport.RoundTrip(r)
	})}
}

type resRoundTrip func(*http.Request) (*http.Response, error)

func (f resRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// Without a federation there is no provider (and /mcp advertises no
// resources); with one, newMCPWithResources serves it on /mcp with the
// audit recorder of tool calls.
func TestNewMCPServesFederationResources(t *testing.T) {
	if federationResources(nil) != nil {
		t.Error("a provider without a federation")
	}
	log := slog.New(slog.DiscardHandler)
	cfg := config.Default()
	policySvc, err := policy.New(policytest.NewMemStore(), policy.Options{Log: log})
	if err != nil {
		t.Fatal(err)
	}
	rec := &lockedRecorder{}
	h, err := newMCPWithResources(cfg, connectors.NewRegistry(), connectors.NewStaticAccountSource(), oneToken{}, policySvc, nil, rec,
		observability.NewMetrics(), log, oneResource{})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h)
	defer srv.Close()
	cs, err := sdk.NewClient(&sdk.Implementation{Name: "t", Version: "0"}, nil).Connect(t.Context(),
		&sdk.StreamableClientTransport{Endpoint: srv.URL, HTTPClient: bearerHTTP("t"), MaxRetries: -1}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cs.Close() }()
	if caps := cs.InitializeResult().Capabilities; caps.Resources == nil || caps.Prompts == nil {
		t.Fatalf("capabilities = %+v", caps)
	}
	res, err := cs.ReadResource(t.Context(), &sdk.ReadResourceParams{URI: "mem://x"})
	if err != nil || res.Contents[0].Text != "x" {
		t.Fatalf("read = %+v, %v", res, err)
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.events) != 1 || rec.events[0].Tool != "mem.resources/read" || rec.events[0].UserID != "user-1" {
		t.Errorf("audit = %+v", rec.events)
	}
}
