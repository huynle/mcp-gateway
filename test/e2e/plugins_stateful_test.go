//go:build integration || e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestE2EPluginsStatefulUpstream (task 36hcuxk2, quirk 91d7smmg): most
// real servers run the go-sdk's default, stateful Streamable HTTP handler,
// which only accepts protocol versions up to 2025-11-25. Review (the first
// connection, from the portal) used to work while every tools/call through
// /mcp failed: the gateway's client inherited the downstream client's
// Mcp-Protocol-Version (2026-07-28) from the /mcp request context and sent
// it on its initialize, and the upstream answered 400 -32022.
func TestE2EPluginsStatefulUpstream(t *testing.T) {
	w := newWorld(t, options{federation: true})
	w.allowLoopback()
	s := sdk.NewServer(&sdk.Implementation{Name: "stateful", Version: "1"}, nil)
	sdk.AddTool(s, &sdk.Tool{Name: "status", Description: "Status.", Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}},
		func(_ context.Context, _ *sdk.CallToolRequest, in echoIn) (*sdk.CallToolResult, any, error) {
			return textResult("ok stateful: " + in.Text), nil, nil
		})
	h := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return s }, nil) // default options: stateful

	// initialize records one initialize POST: its Mcp-Protocol-Version
	// header and the version its body asks for.
	type initialize struct{ header, body string }
	var mu sync.Mutex
	var inits []initialize
	gets := 0
	srv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			mu.Lock()
			gets++
			mu.Unlock()
		case http.MethodPost:
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
			var m struct {
				Method string `json:"method"`
				Params struct {
					ProtocolVersion string `json:"protocolVersion"`
				} `json:"params"`
			}
			if json.Unmarshal(body, &m) == nil && m.Method == "initialize" {
				mu.Lock()
				inits = append(inits, initialize{r.Header.Get("Mcp-Protocol-Version"), m.Params.ProtocolVersion})
				mu.Unlock()
			}
		}
		h.ServeHTTP(rw, r)
	}))
	t.Cleanup(srv.Close)

	id := w.addServer(w.alice, url.Values{"name": {"stateful"}, "url_mode": {"https"}, "url": {srv.URL + "/mcp"},
		"auth_kind": {"none"}, "credential_mode": {"per_user"}})
	w.approve(w.alice, id, w.refresh(w.alice, id), "status")
	alice := w.client(w.alice)
	for _, text := range []string{"one", "two"} {
		if got := w.toolText(alice, "stateful.status", map[string]any{"text": text}); got != "ok stateful: "+text {
			t.Errorf("stateful.status(%s) = %q", text, got)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if len(inits) < 3 { // review + one per call
		t.Errorf("upstream saw %d initialize requests, want >= 3", len(inits))
	}
	for i, in := range inits {
		if in.header != "" && in.header != in.body {
			t.Errorf("initialize %d: Mcp-Protocol-Version header %q, body asks %q", i, in.header, in.body)
		}
	}
	if gets != 0 {
		t.Errorf("upstream saw %d GET requests: the gateway fell back to legacy SSE", gets)
	}
}
