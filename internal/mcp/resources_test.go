package mcp_test

import (
	"context"
	"errors"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// syncRecorder keeps audit events; safe across the HTTP handler goroutine.
type syncRecorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *syncRecorder) Record(_ context.Context, ev audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
	return nil
}

func (r *syncRecorder) all() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]audit.Event(nil), r.events...)
}

// upstreamFailure is an upstream failure with a class (like the connector's).
type upstreamFailure struct{ class, msg string }

func (c upstreamFailure) Error() string      { return c.msg }
func (c upstreamFailure) ErrorClass() string { return c.class }

// fakeResources serves a fixed set per user; "mem://*" URIs are readable,
// anything else is not found. A read of "mem://fail" fails upstream after
// admission.
type fakeResources struct {
	mu        sync.Mutex
	resources map[string][]*sdk.Resource // by user
	templates []*sdk.ResourceTemplate
	prompts   []*sdk.Prompt
	gotArgs   map[string]string
	users     []string
}

func (f *fakeResources) seen(p *tokens.Principal) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users = append(f.users, p.UserID)
}

func (f *fakeResources) ListResources(_ context.Context, p *tokens.Principal) ([]*sdk.Resource, error) {
	f.seen(p)
	return f.resources[p.UserID], nil
}

func (f *fakeResources) ListResourceTemplates(_ context.Context, p *tokens.Principal) ([]*sdk.ResourceTemplate, error) {
	f.seen(p)
	return f.templates, nil
}

func (f *fakeResources) ListPrompts(_ context.Context, p *tokens.Principal) ([]*sdk.Prompt, error) {
	f.seen(p)
	return f.prompts, nil
}

func (f *fakeResources) ReadResource(ctx context.Context, p *tokens.Principal, uri string, admit mcp.Admit) (*sdk.ReadResourceResult, error) {
	f.seen(p)
	if !strings.HasPrefix(uri, "mem://") {
		return nil, mcp.ErrResourceNotFound(uri)
	}
	if err := admit(ctx, mcp.Access{Name: "mem.resources/read", ResourceIdentity: map[string]string{"server": "mem", "uri": uri}}); err != nil {
		return nil, err
	}
	switch uri {
	case "mem://fail":
		return nil, upstreamFailure{"upstream_timeout", "mem: the server did not answer in time"}
	case "mem://boom":
		return nil, errors.New("raw failure with https://internal.example/secret")
	}
	return &sdk.ReadResourceResult{Contents: []*sdk.ResourceContents{
		{URI: uri, MIMEType: "text/plain", Text: "hello"},
		{URI: uri + "#bin", MIMEType: "application/octet-stream", Blob: []byte{0, 1, 2}},
	}}, nil
}

func (f *fakeResources) GetPrompt(ctx context.Context, p *tokens.Principal, name string, args map[string]string, admit mcp.Admit) (*sdk.GetPromptResult, error) {
	f.seen(p)
	if name != "mem.greet" {
		return nil, mcp.ErrPromptNotFound(name)
	}
	if err := admit(ctx, mcp.Access{Name: "mem.prompts/get", ResourceIdentity: map[string]string{"server": "mem", "prompt": "greet"}}); err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.gotArgs = args
	f.mu.Unlock()
	return &sdk.GetPromptResult{Description: "greeting", Messages: []*sdk.PromptMessage{
		{Role: "user", Content: &sdk.TextContent{Text: "hello " + args["who"]}},
	}}, nil
}

func newFakeResources() *fakeResources {
	var many []*sdk.Resource
	for _, u := range []string{"mem://e", "mem://a", "mem://d", "mem://c", "mem://b"} {
		many = append(many, &sdk.Resource{URI: u, Name: "mem." + u[6:], MIMEType: "text/plain"})
	}
	return &fakeResources{
		resources: map[string][]*sdk.Resource{"user-1": many},
		templates: []*sdk.ResourceTemplate{{URITemplate: "mem://t/{id}", Name: "mem.t"}},
		prompts:   []*sdk.Prompt{{Name: "mem.greet", Arguments: []*sdk.PromptArgument{{Name: "who", Required: true}}}},
	}
}

type namedDenyLimiter struct {
	mu    sync.Mutex
	names []string
}

func (d *namedDenyLimiter) Allow(_ context.Context, _, tool string) (bool, time.Duration) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.names = append(d.names, tool)
	return false, 3 * time.Second
}

func resourcesServer(t *testing.T, f *fakeResources, mutate func(*mcp.Options)) string {
	t.Helper()
	srv := httptest.NewServer(newHandler(t, httpTools(t), func(o *mcp.Options) {
		o.Resources = f
		o.ListPageSize = 2
		if mutate != nil {
			mutate(o)
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func wantRPCCode(t *testing.T, err error, code int64) *jsonrpc.Error {
	t.Helper()
	var we *jsonrpc.Error
	if !errors.As(err, &we) {
		t.Fatalf("error = %v (%T), want a JSON-RPC error %d", err, err, code)
	}
	if we.Code != code {
		t.Fatalf("code = %d (%s), want %d", we.Code, we.Message, code)
	}
	return we
}

func TestResourcesCapabilitiesAdvertisedOnlyWithAProvider(t *testing.T) {
	for _, protocol := range protocolVersions {
		cs := connect(t, resourcesServer(t, newFakeResources(), nil), fullToken, protocol)
		caps := cs.InitializeResult().Capabilities
		if caps.Resources == nil || caps.Resources.Subscribe || caps.Resources.ListChanged {
			t.Errorf("%s: resources capability = %+v, want present without subscribe/listChanged", protocol, caps.Resources)
		}
		if caps.Prompts == nil || caps.Prompts.ListChanged {
			t.Errorf("%s: prompts capability = %+v", protocol, caps.Prompts)
		}
		if caps.Tools == nil {
			t.Errorf("%s: tools capability lost", protocol)
		}
	}
	srv := httptest.NewServer(newHandler(t, httpTools(t), nil))
	defer srv.Close()
	caps := connect(t, srv.URL, fullToken, protocolVersions[0]).InitializeResult().Capabilities
	if caps.Resources != nil || caps.Prompts != nil {
		t.Errorf("without a provider: resources %+v prompts %+v, want none", caps.Resources, caps.Prompts)
	}
}

func TestResourcesListPagesTheSortedUnion(t *testing.T) {
	f := newFakeResources()
	cs := connect(t, resourcesServer(t, f, nil), fullToken, protocolVersions[0])
	first, err := cs.ListResources(t.Context(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Resources) != 2 || first.Resources[0].URI != "mem://a" || first.Resources[1].URI != "mem://b" || first.NextCursor == "" {
		t.Fatalf("first page = %+v next %q", first.Resources, first.NextCursor)
	}
	var uris []string
	for r, err := range cs.Resources(t.Context(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		uris = append(uris, r.URI)
	}
	if strings.Join(uris, ",") != "mem://a,mem://b,mem://c,mem://d,mem://e" {
		t.Errorf("all pages = %v", uris)
	}
	_, err = cs.ListResources(t.Context(), &sdk.ListResourcesParams{Cursor: "not a cursor!"})
	_ = wantRPCCode(t, err, mcp.CodeInvalidParams)

	// Another user's list is theirs alone (here: empty).
	other := connect(t, resourcesServer(t, f, nil), readOnlyToken, protocolVersions[0])
	res, err := other.ListResources(t.Context(), nil)
	if err != nil || len(res.Resources) != 0 || res.NextCursor != "" {
		t.Errorf("user-2 list = %+v, %v", res, err)
	}
	if res.CacheScope != "private" {
		t.Errorf("cacheScope = %q, want private", res.CacheScope)
	}
}

func TestResourceTemplatesAndPromptsList(t *testing.T) {
	cs := connect(t, resourcesServer(t, newFakeResources(), nil), fullToken, protocolVersions[1])
	tl, err := cs.ListResourceTemplates(t.Context(), nil)
	if err != nil || len(tl.ResourceTemplates) != 1 || tl.ResourceTemplates[0].URITemplate != "mem://t/{id}" {
		t.Fatalf("templates = %+v, %v", tl, err)
	}
	pl, err := cs.ListPrompts(t.Context(), nil)
	if err != nil || len(pl.Prompts) != 1 || pl.Prompts[0].Name != "mem.greet" {
		t.Fatalf("prompts = %+v, %v", pl, err)
	}
}

func TestResourceReadPassesContentThroughAndAudits(t *testing.T) {
	rec := &syncRecorder{}
	cs := connect(t, resourcesServer(t, newFakeResources(), func(o *mcp.Options) { o.Audit = rec }), fullToken, protocolVersions[0])
	res, err := cs.ReadResource(t.Context(), &sdk.ReadResourceParams{URI: "mem://x"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Contents) != 2 || res.Contents[0].Text != "hello" || res.Contents[0].MIMEType != "text/plain" ||
		string(res.Contents[1].Blob) != "\x00\x01\x02" || res.Contents[1].MIMEType != "application/octet-stream" {
		t.Fatalf("contents = %+v", res.Contents)
	}
	evs := rec.all()
	if len(evs) != 1 {
		t.Fatalf("events = %+v", evs)
	}
	ev := evs[0]
	if ev.Tool != "mem.resources/read" || ev.UserID != "user-1" || ev.TokenID != "token-1" || ev.Outcome != "succeeded" ||
		ev.Decision != "allow" || ev.ResourceIdentity["uri"] != "mem://x" {
		t.Errorf("event = %+v", ev)
	}
}

func TestResourceReadErrors(t *testing.T) {
	rec := &syncRecorder{}
	limiter := &namedDenyLimiter{}
	f := newFakeResources()
	url := resourcesServer(t, f, func(o *mcp.Options) { o.Audit = rec })
	cs := connect(t, url, fullToken, protocolVersions[0])

	// Unknown (or hidden): the SDK's resource-not-found shape.
	_, err := cs.ReadResource(t.Context(), &sdk.ReadResourceParams{URI: "other://x"})
	we := wantRPCCode(t, err, mcp.CodeInvalidParams)
	if we.Message != "Resource not found" || !strings.Contains(string(we.Data), `"uri":"other://x"`) {
		t.Errorf("not found = %+v data %s", we, we.Data)
	}
	// Upstream failure: class-level message, gateway upstream code.
	_, err = cs.ReadResource(t.Context(), &sdk.ReadResourceParams{URI: "mem://fail"})
	we = wantRPCCode(t, err, mcp.CodeUpstream)
	if we.Message != "mem: the server did not answer in time" {
		t.Errorf("upstream failure message = %q", we.Message)
	}
	// An unclassified failure never shows its text.
	_, err = cs.ReadResource(t.Context(), &sdk.ReadResourceParams{URI: "mem://boom"})
	we = wantRPCCode(t, err, mcp.CodeInternal)
	if strings.Contains(we.Message, "internal.example") {
		t.Errorf("internal failure leaked: %q", we.Message)
	}
	evs := rec.all()
	if len(evs) != 3 {
		t.Fatalf("events = %+v", evs)
	}
	if evs[0].Tool != "resources/read" || evs[0].Outcome != "denied" || evs[0].ErrorClass != "resource_not_found" {
		t.Errorf("not found event = %+v", evs[0])
	}
	if evs[1].Tool != "mem.resources/read" || evs[1].Outcome != "failed" || evs[1].ErrorClass != "upstream_timeout" {
		t.Errorf("upstream event = %+v", evs[1])
	}
	if evs[2].Outcome != "failed" || evs[2].ErrorClass != "upstream_error" {
		t.Errorf("unclassified event = %+v", evs[2])
	}

	// The rate limiter is asked with the access name once the provider
	// admits the read.
	limited := connect(t, resourcesServer(t, f, func(o *mcp.Options) { o.RateLimiter = limiter }), fullToken, protocolVersions[0])
	_, err = limited.ReadResource(t.Context(), &sdk.ReadResourceParams{URI: "mem://x"})
	we = wantRPCCode(t, err, mcp.CodeRateLimited)
	if !strings.Contains(string(we.Data), `"retry_after":3`) {
		t.Errorf("rate limited data = %s", we.Data)
	}
	limiter.mu.Lock()
	defer limiter.mu.Unlock()
	if len(limiter.names) != 1 || limiter.names[0] != "mem.resources/read" {
		t.Errorf("limiter asked for %v", limiter.names)
	}
}

func TestPromptGetPassesArgumentsAndAudits(t *testing.T) {
	rec := &syncRecorder{}
	f := newFakeResources()
	cs := connect(t, resourcesServer(t, f, func(o *mcp.Options) { o.Audit = rec }), fullToken, protocolVersions[1])
	res, err := cs.GetPrompt(t.Context(), &sdk.GetPromptParams{Name: "mem.greet", Arguments: map[string]string{"who": "alice"}})
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	got := f.gotArgs
	f.mu.Unlock()
	if len(res.Messages) != 1 || res.Messages[0].Content.(*sdk.TextContent).Text != "hello alice" || got["who"] != "alice" {
		t.Fatalf("prompt = %+v args %v", res, got)
	}
	_, err = cs.GetPrompt(t.Context(), &sdk.GetPromptParams{Name: "mem.nope"})
	we := wantRPCCode(t, err, mcp.CodeInvalidParams)
	if we.Message != `unknown prompt "mem.nope"` {
		t.Errorf("unknown prompt message = %q", we.Message)
	}
	evs := rec.all()
	sort.SliceStable(evs, func(i, j int) bool { return evs[i].Outcome > evs[j].Outcome })
	if len(evs) != 2 || evs[0].Tool != "mem.prompts/get" || evs[0].Outcome != "succeeded" || evs[0].ResourceIdentity["prompt"] != "greet" {
		t.Fatalf("events = %+v", evs)
	}
	if evs[1].Tool != "prompts/get" || evs[1].ErrorClass != "prompt_not_found" || evs[1].Outcome != "denied" {
		t.Errorf("unknown prompt event = %+v", evs[1])
	}
}

func TestResourcesRequireAuthentication(t *testing.T) {
	srv := httptest.NewServer(newHandler(t, httpTools(t), func(o *mcp.Options) { o.Resources = newFakeResources() }))
	defer srv.Close()
	client := sdk.NewClient(&sdk.Implementation{Name: "anon", Version: "0"}, nil)
	_, err := client.Connect(t.Context(), &sdk.StreamableClientTransport{Endpoint: srv.URL, HTTPClient: bearerClient(""), MaxRetries: -1}, nil)
	if err == nil {
		t.Fatal("connected without a token")
	}
}
