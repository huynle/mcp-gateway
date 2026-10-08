package mcp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

const baseURL = "http://gw.test"

// fakeAuth maps bearer strings to principals.
type fakeAuth map[string]*tokens.Principal

func (f fakeAuth) Authenticate(_ context.Context, bearer string) (*tokens.Principal, error) {
	if p, ok := f[bearer]; ok {
		return p, nil
	}
	return nil, &tokens.Error{Reason: tokens.ReasonUnknown}
}

var (
	fullToken     = "mgw_full_token"
	readOnlyToken = "mgw_readonly_token"
	auth          = fakeAuth{
		fullToken:     {UserID: "user-1", TokenID: "token-1", PublicID: "fulltokn"},
		readOnlyToken: {UserID: "user-2", TokenID: "token-2", PublicID: "readonly", Scope: tokens.Scope{ReadOnly: true}},
	}
)

// httpTools is the registry every handler test shares: an echo read, an
// echo write, an unavailable read and a failing read.
func httpTools(t *testing.T) *connectors.Registry {
	t.Helper()
	echo := func(_ context.Context, call connectors.Call) (connectors.Result, error) {
		return connectors.Result{Content: map[string]any{
			"user":        call.Principal.UserID,
			"account":     call.Account,
			"approval_id": call.ApprovalID,
			"args":        call.Args,
		}}, nil
	}
	list := stubTool("github", "list_issues", connectors.KindRead)
	list.Handler = echo
	create := stubTool("github", "create_issue", connectors.KindWrite)
	create.Handler = echo
	unavailable := stubTool("github", "list_prs", connectors.KindRead)
	unavailable.Handler = func(context.Context, connectors.Call) (connectors.Result, error) {
		return connectors.Result{Content: "nothing yet", Unavailable: true, Empty: true}, nil
	}
	failing := stubTool("github", "list_runs", connectors.KindRead)
	failing.Handler = func(context.Context, connectors.Call) (connectors.Result, error) {
		return connectors.Result{}, errors.New("vendor refused: Authorization: Bearer ghp_secret123")
	}
	return newRegistry(t, list, create, unavailable, failing)
}

func newHandler(t *testing.T, reg *connectors.Registry, mutate func(*mcp.Options)) http.Handler {
	t.Helper()
	opts := mcp.Options{
		Registry:      reg,
		Authenticator: auth,
		BaseURL:       baseURL,
		Log:           slog.New(slog.DiscardHandler),
	}
	if mutate != nil {
		mutate(&opts)
	}
	h, err := mcp.Handler(opts)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// bearerClient adds Authorization to every request.
func bearerClient(token string) *http.Client {
	return &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		r = r.Clone(r.Context())
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		return http.DefaultTransport.RoundTrip(r)
	})}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// protocolVersions are the handshakes real harnesses use today (initialize)
// and the SDK's newest (server/discover).
var protocolVersions = []string{"2025-11-25", "2026-07-28"}

func connect(t *testing.T, endpoint, token, protocol string) *sdk.ClientSession {
	t.Helper()
	client := sdk.NewClient(&sdk.Implementation{Name: "test-harness", Version: "0"}, nil)
	cs, err := client.Connect(t.Context(), &sdk.StreamableClientTransport{
		Endpoint:   endpoint,
		HTTPClient: bearerClient(token),
		MaxRetries: -1,
	}, &sdk.ClientSessionOptions{ProtocolVersion: protocol})
	if err != nil {
		t.Fatalf("Connect (%s): %v", protocol, err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func text(t *testing.T, res *sdk.CallToolResult) string {
	t.Helper()
	if len(res.Content) == 0 {
		t.Fatalf("no content in %+v", res)
	}
	tc, ok := res.Content[0].(*sdk.TextContent)
	if !ok {
		t.Fatalf("content[0] is %T", res.Content[0])
	}
	return tc.Text
}

func TestConformanceListAndCall(t *testing.T) {
	srv := httptest.NewServer(newHandler(t, httpTools(t), nil))
	defer srv.Close()
	for _, pv := range protocolVersions {
		t.Run(pv, func(t *testing.T) {
			cs := connect(t, srv.URL, fullToken, pv)

			list, err := cs.ListTools(t.Context(), nil)
			if err != nil {
				t.Fatalf("ListTools: %v", err)
			}
			byName := map[string]*sdk.Tool{}
			for _, tool := range list.Tools {
				byName[tool.Name] = tool
			}
			for _, name := range []string{"github.list_issues", "github.create_issue", "github.list_prs", "github.list_runs"} {
				if byName[name] == nil {
					t.Errorf("tools/list lacks %s: %v", name, list.Tools)
				}
			}
			schema, _ := byName["github.list_issues"].InputSchema.(map[string]any)
			props, _ := schema["properties"].(map[string]any)
			for _, inj := range []string{"account", "approval_id"} {
				p, _ := props[inj].(map[string]any)
				if p["type"] != "string" || p["description"] == "" {
					t.Errorf("injected property %s = %v, want string with a description", inj, props[inj])
				}
			}
			if _, ok := props["repo"]; !ok {
				t.Errorf("tool's own property lost: %v", props)
			}
			if req, _ := schema["required"].([]any); len(req) != 0 {
				t.Errorf("injected properties must stay optional, required = %v", req)
			}
			if byName["github.list_issues"].Description != "github list_issues" {
				t.Errorf("Description = %q", byName["github.list_issues"].Description)
			}

			res, err := cs.CallTool(t.Context(), &sdk.CallToolParams{
				Name:      "github.list_issues",
				Arguments: map[string]any{"repo": "acme/web", "account": "acct-1", "approval_id": "appr-2"},
			})
			if err != nil {
				t.Fatalf("CallTool: %v", err)
			}
			if res.IsError {
				t.Fatalf("IsError: %s", text(t, res))
			}
			var echo struct {
				User       string         `json:"user"`
				Account    string         `json:"account"`
				ApprovalID string         `json:"approval_id"`
				Args       map[string]any `json:"args"`
			}
			if err := json.Unmarshal([]byte(text(t, res)), &echo); err != nil {
				t.Fatalf("content %q: %v", text(t, res), err)
			}
			if echo.User != "user-1" || echo.Account != "acct-1" || echo.ApprovalID != "appr-2" {
				t.Errorf("echo = %+v", echo)
			}
			if _, ok := echo.Args["account"]; ok {
				t.Error("account reached the handler")
			}
			if echo.Args["repo"] != "acme/web" {
				t.Errorf("args = %v", echo.Args)
			}
			if res.StructuredContent == nil {
				t.Error("StructuredContent missing for a JSON result")
			}

			// Unavailable/empty reads carry the flags in _meta.
			res, err = cs.CallTool(t.Context(), &sdk.CallToolParams{Name: "github.list_prs", Arguments: map[string]any{}})
			if err != nil {
				t.Fatalf("CallTool unavailable: %v", err)
			}
			flags, _ := res.Meta[mcp.MetaReadKey].(map[string]any)
			if flags["unavailable"] != true || flags["empty"] != true || flags["partial"] != nil {
				t.Errorf("_meta[%s] = %v", mcp.MetaReadKey, res.Meta)
			}
			if text(t, res) != "nothing yet" {
				t.Errorf("text = %q", text(t, res))
			}

			// A handler error is a tool error (IsError), redacted.
			res, err = cs.CallTool(t.Context(), &sdk.CallToolParams{Name: "github.list_runs", Arguments: map[string]any{}})
			if err != nil {
				t.Fatalf("CallTool failing: %v", err)
			}
			if !res.IsError {
				t.Error("handler error must set IsError")
			}
			if msg := text(t, res); !strings.Contains(msg, "vendor refused") || strings.Contains(msg, "ghp_secret123") {
				t.Errorf("error text = %q (must keep the message, redact the secret)", msg)
			}

			// Unknown tool is a protocol error.
			_, err = cs.CallTool(t.Context(), &sdk.CallToolParams{Name: "github.nope", Arguments: map[string]any{}})
			if err == nil || !strings.Contains(err.Error(), `unknown tool "github.nope"`) {
				t.Errorf("unknown tool err = %v", err)
			}
		})
	}
}

func TestReadOnlyTokenSeesNoWriteTools(t *testing.T) {
	srv := httptest.NewServer(newHandler(t, httpTools(t), nil))
	defer srv.Close()
	cs := connect(t, srv.URL, readOnlyToken, protocolVersions[0])
	list, err := cs.ListTools(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range list.Tools {
		if tool.Name == "github.create_issue" {
			t.Error("read-only token lists a write tool")
		}
	}
	if len(list.Tools) != 3 {
		t.Errorf("tools = %d, want 3", len(list.Tools))
	}
	_, err = cs.CallTool(t.Context(), &sdk.CallToolParams{Name: "github.create_issue", Arguments: map[string]any{}})
	if err == nil || !strings.Contains(err.Error(), `unknown tool "github.create_issue"`) {
		t.Errorf("hidden tool err = %v", err)
	}
}

// reply is what post returns: the response without its (already read and
// closed) body, plus the body.
type reply struct {
	StatusCode int
	Header     http.Header
	Body       []byte
}

// post sends one raw JSON-RPC message and returns status, headers and body.
func post(t *testing.T, endpoint, token, body string) reply {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	return reply{StatusCode: resp.StatusCode, Header: resp.Header, Body: b}
}

const callCreateIssue = `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"github.create_issue","arguments":{}}}`

func TestHiddenAndUnknownToolsAreByteIdentical(t *testing.T) {
	hidden := httptest.NewServer(newHandler(t, httpTools(t), nil)) // has create_issue, read-only token cannot see it
	defer hidden.Close()
	absent := httptest.NewServer(newHandler(t, newRegistry(t, stubTool("github", "list_issues", connectors.KindRead)), nil))
	defer absent.Close()

	r1 := post(t, hidden.URL, readOnlyToken, callCreateIssue)
	r2 := post(t, absent.URL, readOnlyToken, callCreateIssue)
	if r1.StatusCode != r2.StatusCode {
		t.Errorf("status %d vs %d", r1.StatusCode, r2.StatusCode)
	}
	if !bytes.Equal(r1.Body, r2.Body) {
		t.Errorf("payloads differ:\n%s\n%s", r1.Body, r2.Body)
	}
	b1 := r1.Body
	var rpc struct {
		Error *struct {
			Code    int64  `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(b1, &rpc); err != nil || rpc.Error == nil {
		t.Fatalf("not a JSON-RPC error: %s (%v)", b1, err)
	}
	if rpc.Error.Code != mcp.CodeToolNotFound || rpc.Error.Message != `unknown tool "github.create_issue"` {
		t.Errorf("error = %+v", rpc.Error)
	}
}

func TestUnauthenticatedGets401WithResourceMetadata(t *testing.T) {
	srv := httptest.NewServer(newHandler(t, httpTools(t), nil))
	defer srv.Close()

	resp := post(t, srv.URL, "", callCreateIssue)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, body %s", resp.StatusCode, resp.Body)
	}
	want := `Bearer realm="mcp-gateway", resource_metadata="` + baseURL + `/.well-known/oauth-protected-resource"`
	if got := resp.Header.Get("WWW-Authenticate"); got != want {
		t.Errorf("WWW-Authenticate = %q, want %q", got, want)
	}

	resp = post(t, srv.URL, "mgw_wrong", callCreateIssue)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("bad token status = %d", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); !strings.HasPrefix(got, want+`, error="invalid_token"`) {
		t.Errorf("bad token WWW-Authenticate = %q", got)
	}

	client := sdk.NewClient(&sdk.Implementation{Name: "t", Version: "0"}, nil)
	_, err := client.Connect(t.Context(), &sdk.StreamableClientTransport{Endpoint: srv.URL, HTTPClient: bearerClient(""), MaxRetries: -1}, nil)
	if err == nil || !strings.Contains(err.Error(), "Unauthorized") {
		t.Errorf("SDK client without token: err = %v, want Unauthorized", err)
	}
}

func TestFailureBudgetGives429(t *testing.T) {
	limiter := tokens.NewFailureLimiter(2, time.Minute)
	srv := httptest.NewServer(newHandler(t, httpTools(t), func(o *mcp.Options) { o.Auth.Limiter = limiter }))
	defer srv.Close()
	for i := range 2 {
		if resp := post(t, srv.URL, "mgw_wrong", callCreateIssue); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("attempt %d status = %d", i, resp.StatusCode)
		}
	}
	resp := post(t, srv.URL, "mgw_wrong", callCreateIssue)
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") == "" {
		t.Errorf("status = %d, Retry-After = %q", resp.StatusCode, resp.Header.Get("Retry-After"))
	}
	// The budget is per client, not per token: a valid token from the same
	// address is refused too, until the window passes.
	if resp := post(t, srv.URL, fullToken, callCreateIssue); resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("valid token from a limited client: status = %d", resp.StatusCode)
	}
}

func TestBodyLimitGives413(t *testing.T) {
	srv := httptest.NewServer(newHandler(t, httpTools(t), func(o *mcp.Options) { o.MaxBody = 512 }))
	defer srv.Close()
	big := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"github.list_issues","arguments":{"repo":"` + strings.Repeat("x", 1024) + `"}}}`
	resp := post(t, srv.URL, fullToken, big)
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Errorf("status = %d, want 413", resp.StatusCode)
	}
	if resp := post(t, srv.URL, fullToken, callCreateIssue); resp.StatusCode != http.StatusOK {
		t.Errorf("small body status = %d", resp.StatusCode)
	}
}

func TestStatelessRejectsGetAndDelete(t *testing.T) {
	srv := httptest.NewServer(newHandler(t, httpTools(t), nil))
	defer srv.Close()
	for _, method := range []string{http.MethodGet, http.MethodDelete} {
		req, _ := http.NewRequestWithContext(t.Context(), method, srv.URL, nil)
		req.Header.Set("Authorization", "Bearer "+fullToken)
		req.Header.Set("Accept", "text/event-stream")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("%s status = %d, want 405 (stateless: no sessions, no server stream)", method, resp.StatusCode)
		}
		if resp.Header.Get("Mcp-Session-Id") != "" {
			t.Errorf("%s issued a session id", method)
		}
	}
	resp := post(t, srv.URL, fullToken, callCreateIssue)
	if resp.Header.Get("Mcp-Session-Id") != "" {
		t.Error("POST issued a session id; the transport must be stateless")
	}
}

// TestRoundRobinAcrossReplicas runs one SDK session through two independent
// handler instances behind an alternating proxy: with no session state,
// every request may land anywhere.
func TestRoundRobinAcrossReplicas(t *testing.T) {
	reg := httpTools(t)
	var backends []*httptest.Server
	var hits [2]atomic.Int64
	for i := range 2 {
		b := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits[i].Add(1)
			newHandler(t, reg, nil).ServeHTTP(w, r)
		}))
		defer b.Close()
		backends = append(backends, b)
	}
	var next atomic.Int64
	var mu sync.Mutex
	proxies := make([]*httputil.ReverseProxy, 2)
	for i, b := range backends {
		u, _ := url.Parse(b.URL)
		proxies[i] = httputil.NewSingleHostReverseProxy(u)
	}
	lb := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		p := proxies[next.Add(1)%2]
		mu.Unlock()
		p.ServeHTTP(w, r)
	}))
	defer lb.Close()

	for _, pv := range protocolVersions {
		t.Run(pv, func(t *testing.T) {
			cs := connect(t, lb.URL, fullToken, pv)
			for range 3 {
				list, err := cs.ListTools(t.Context(), nil)
				if err != nil {
					t.Fatalf("ListTools: %v", err)
				}
				if len(list.Tools) != 4 {
					t.Errorf("tools = %d", len(list.Tools))
				}
				res, err := cs.CallTool(t.Context(), &sdk.CallToolParams{Name: "github.list_issues", Arguments: map[string]any{"repo": "r"}})
				if err != nil {
					t.Fatalf("CallTool: %v", err)
				}
				if res.IsError {
					t.Errorf("IsError: %s", text(t, res))
				}
			}
		})
	}
	if hits[0].Load() == 0 || hits[1].Load() == 0 {
		t.Errorf("both replicas must have served requests: %d / %d", hits[0].Load(), hits[1].Load())
	}
}

func TestHandlerOptionsValidation(t *testing.T) {
	reg := newRegistry(t)
	cases := map[string]mcp.Options{
		"no registry":      {Authenticator: auth, BaseURL: baseURL},
		"no authenticator": {Registry: reg, BaseURL: baseURL},
		"no base url":      {Registry: reg, Authenticator: auth},
		"negative body":    {Registry: reg, Authenticator: auth, BaseURL: baseURL, MaxBody: -1},
	}
	for name, opts := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := mcp.Handler(opts); err == nil {
				t.Error("want an error")
			}
		})
	}
}

func TestHandlerUsesSuppliedPipeline(t *testing.T) {
	reg := httpTools(t)
	p, err := mcp.DefaultPipeline(mcp.PipelineDeps{Registry: reg})
	if err != nil {
		t.Fatal(err)
	}
	// A stage inserted before dispatch answers for every call: the handler
	// must run the supplied pipeline, not build its own.
	err = p.Insert(mcp.Before, mcp.StageDispatch, newStageFunc("short", func(context.Context, *mcp.CallContext, mcp.Next) (connectors.Result, error) {
		return connectors.Result{Content: "short-circuited"}, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(newHandler(t, reg, func(o *mcp.Options) { o.Pipeline = p }))
	defer srv.Close()
	cs := connect(t, srv.URL, fullToken, protocolVersions[0])
	res, err := cs.CallTool(t.Context(), &sdk.CallToolParams{Name: "github.list_issues", Arguments: map[string]any{}})
	if err != nil {
		t.Fatal(err)
	}
	if text(t, res) != "short-circuited" {
		t.Errorf("text = %q", text(t, res))
	}
}
