package client

import (
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestNewRequiresHTTPClient(t *testing.T) {
	if _, err := New(Options{}); err == nil {
		t.Fatal("New without HTTPClient succeeded")
	}
	hc := guardClient(t)
	hc.Transport = nil // would fall back to http.DefaultTransport
	if _, err := New(Options{HTTPClient: hc}); err == nil {
		t.Fatal("New with a nil Transport succeeded")
	}
}

func TestStreamableEndToEnd(t *testing.T) {
	ts := streamableServer(t, fullServer(0, 0), nil)
	c := newTestClient(t, nil)
	s := connect(t, c, Endpoint{URL: ts.URL + "/mcp", Transport: TransportStreamableHTTP})

	if got := s.Transport(); got != TransportStreamableHTTP {
		t.Errorf("Transport() = %q, want streamable_http", got)
	}
	if info := s.ServerInfo(); info == nil || info.Name != "upstream" || info.Version != "1.2.3" {
		t.Errorf("ServerInfo() = %+v", info)
	}
	if s.ProtocolVersion() == "" {
		t.Error("ProtocolVersion() is empty")
	}
	if s.Instructions() != "use echo" {
		t.Errorf("Instructions() = %q", s.Instructions())
	}
	if caps := s.Capabilities(); caps == nil || caps.Tools == nil || caps.Resources == nil || caps.Prompts == nil {
		t.Errorf("Capabilities() = %+v", caps)
	}

	ctx := ctxT(t)
	tools, err := s.ListTools(ctx)
	if err != nil {
		t.Fatalf("ListTools: %v", err)
	}
	if len(tools) != 2 || tools[0].Name != "echo" || tools[1].Name != "fail" {
		t.Fatalf("tools = %v", names(tools, func(x *mcp.Tool) string { return x.Name }))
	}

	res, err := s.CallTool(ctx, "echo", map[string]any{"text": "ping"})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if res.IsError {
		t.Fatalf("CallTool IsError: %+v", res)
	}
	sc, _ := json.Marshal(res.StructuredContent)
	if string(sc) != `{"echo":"ping"}` {
		t.Errorf("structuredContent = %s", sc)
	}
	if len(res.Content) == 0 {
		t.Error("content is empty")
	}

	// A tool-level failure is a result with IsError, not a Go error.
	res, err = s.CallTool(ctx, "fail", map[string]any{"text": "x"})
	if err != nil {
		t.Fatalf("CallTool(fail): %v", err)
	}
	if !res.IsError {
		t.Errorf("CallTool(fail).IsError = false")
	}

	resources, err := s.ListResources(ctx)
	if err != nil || len(resources) != 1 || resources[0].URI != "file:///readme" {
		t.Fatalf("ListResources = %v, %v", resources, err)
	}
	templates, err := s.ListResourceTemplates(ctx)
	if err != nil || len(templates) != 1 || templates[0].URITemplate != "file:///docs/{name}" {
		t.Fatalf("ListResourceTemplates = %v, %v", templates, err)
	}
	rr, err := s.ReadResource(ctx, "file:///readme")
	if err != nil || len(rr.Contents) != 1 || rr.Contents[0].Text != "hello" {
		t.Fatalf("ReadResource = %+v, %v", rr, err)
	}
	prompts, err := s.ListPrompts(ctx)
	if err != nil || len(prompts) != 1 || prompts[0].Name != "greet" {
		t.Fatalf("ListPrompts = %v, %v", prompts, err)
	}
	gp, err := s.GetPrompt(ctx, "greet", map[string]string{"who": "bob"})
	if err != nil || len(gp.Messages) != 1 {
		t.Fatalf("GetPrompt = %+v, %v", gp, err)
	}
	if tc, ok := gp.Messages[0].Content.(*mcp.TextContent); !ok || tc.Text != "hi bob" {
		t.Errorf("GetPrompt message = %+v", gp.Messages[0].Content)
	}
	if err := s.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

func names[T any](xs []T, f func(T) string) []string {
	out := make([]string, len(xs))
	for i, x := range xs {
		out[i] = f(x)
	}
	return out
}
