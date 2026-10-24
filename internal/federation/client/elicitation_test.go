package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func withURLElicitation(o *Options) { o.URLElicitation = true }

// urlParams is a URL-mode elicitation request.
func urlParams(id, url, msg string) *mcp.ElicitParams {
	return &mcp.ElicitParams{Mode: "url", ElicitationID: id, URL: url, Message: msg}
}

func TestRecorderDedupAndCap(t *testing.T) {
	var r Recorder
	if !r.Add(Elicitation{ElicitationID: "a", URL: "https://x.example/a", Message: "m"}) {
		t.Fatal("first entry not kept")
	}
	if r.Add(Elicitation{ElicitationID: "a", URL: "https://x.example/other"}) {
		t.Error("duplicate id kept")
	}
	for _, bad := range []Elicitation{
		{URL: "https://x.example/no-id"},
		{ElicitationID: "no-url"},
		{ElicitationID: strings.Repeat("i", MaxElicitationIDBytes+1), URL: "https://x.example/"},
	} {
		if r.Add(bad) {
			t.Errorf("kept invalid entry %+v", bad)
		}
	}
	for i := range 10 {
		r.Add(Elicitation{ElicitationID: fmt.Sprintf("id-%d", i), URL: "https://x.example/"})
	}
	got := r.List()
	if len(got) != MaxElicitations {
		t.Fatalf("len = %d, want %d", len(got), MaxElicitations)
	}
	if got[0].ElicitationID != "a" || got[0].URL != "https://x.example/a" || got[1].ElicitationID != "id-0" {
		t.Errorf("order or content = %+v", got)
	}
	got[0].URL = "mutated"
	if r.List()[0].URL == "mutated" {
		t.Error("List shares its backing array")
	}
	r.Clear()
	if l := r.List(); l != nil {
		t.Errorf("after Clear = %+v", l)
	}
	if !r.Add(Elicitation{ElicitationID: "a", URL: "https://x.example/a"}) {
		t.Error("id not accepted again after Clear")
	}
}

func TestRecorderCapsFields(t *testing.T) {
	var r Recorder
	msg := strings.Repeat("é", MaxElicitationMessageRunes+20)
	url := "https://x.example/" + strings.Repeat("p", MaxElicitationURLBytes)
	r.Add(Elicitation{ElicitationID: "a", URL: url, Message: msg})
	l := r.List()
	if len(l) != 1 {
		t.Fatalf("List = %+v, want one entry", l)
	}
	e := l[0]
	if n := len([]rune(e.Message)); n != MaxElicitationMessageRunes {
		t.Errorf("message runes = %d, want %d", n, MaxElicitationMessageRunes)
	}
	if len(e.URL) != MaxElicitationURLBytes || !strings.HasPrefix(url, e.URL) {
		t.Errorf("url bytes = %d, want a %d-byte prefix", len(e.URL), MaxElicitationURLBytes)
	}
}

func TestRecorderConcurrent(t *testing.T) {
	var r Recorder
	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() { r.Add(Elicitation{ElicitationID: fmt.Sprint(i % 7), URL: "https://x.example/"}) })
	}
	wg.Wait()
	if n := len(r.List()); n != MaxElicitations {
		t.Errorf("len = %d, want %d", n, MaxElicitations)
	}
}

func rpc32042(t *testing.T, entries ...any) *jsonrpc.Error {
	t.Helper()
	data, err := json.Marshal(map[string]any{"elicitations": entries})
	if err != nil {
		t.Fatal(err)
	}
	return &jsonrpc.Error{Code: mcp.CodeURLElicitationRequired, Message: "URL elicitation required", Data: data}
}

func TestURLElicitationsExtract(t *testing.T) {
	good := map[string]any{"mode": "url", "elicitationId": "e1", "url": "https://x.example/c", "message": "connect"}
	tests := []struct {
		name string
		err  error
		want []Elicitation
	}{
		{"nil", nil, nil},
		{"plain error", errors.New("x"), nil},
		{"other code", &jsonrpc.Error{Code: -32602, Data: json.RawMessage(`{"elicitations":[]}`)}, nil},
		{"no data", &jsonrpc.Error{Code: mcp.CodeURLElicitationRequired}, nil},
		{"bad data", &jsonrpc.Error{Code: mcp.CodeURLElicitationRequired, Data: json.RawMessage(`[1]`)}, nil},
		{"empty list", rpc32042(t), nil},
		{"bare", rpc32042(t, good), []Elicitation{{"e1", "https://x.example/c", "connect"}}},
		{"wrapped twice", fmt.Errorf("outer: %w", &Error{Class: ClassToolError, RPCCode: -32042, err: fmt.Errorf("inner: %w", rpc32042(t, good))}),
			[]Elicitation{{"e1", "https://x.example/c", "connect"}}},
		{"non-url and id-less ignored", rpc32042(t,
			map[string]any{"mode": "form", "elicitationId": "f", "url": "https://x.example/f"},
			map[string]any{"elicitationId": "nomode", "url": "https://x.example/n"},
			map[string]any{"mode": "url", "url": "https://x.example/noid"},
			good, good,
		), []Elicitation{{"e1", "https://x.example/c", "connect"}}},
		{"only non-url", rpc32042(t, map[string]any{"mode": "form", "elicitationId": "f"}), nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := URLElicitations(tc.err)
			if ok != (tc.want != nil) {
				t.Fatalf("ok = %v, want %v (got %+v)", ok, tc.want != nil, got)
			}
			if fmt.Sprint(got) != fmt.Sprint(tc.want) {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
	var many []any
	for i := range 9 {
		many = append(many, map[string]any{"mode": "url", "elicitationId": fmt.Sprint(i), "url": "https://x.example/"})
	}
	if got, _ := URLElicitations(rpc32042(t, many...)); len(got) != MaxElicitations {
		t.Errorf("cap: len = %d, want %d", len(got), MaxElicitations)
	}
}

// elicitServer has tools that elicit mid-call (stateful: elicitation/create;
// stateless 2026-07-28: multi round-trip input requests) or answer -32042.
// seen receives the action each elicitation got (or the error text).
func elicitServer(seen chan<- string) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "elicit-upstream", Version: "1"}, nil)
	report := func(res *mcp.ElicitResult, err error) {
		switch {
		case err != nil:
			seen <- "error: " + err.Error()
		default:
			seen <- res.Action
		}
	}
	mcp.AddTool(s, &mcp.Tool{Name: "create_url"}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		for range 2 { // the same id twice: recorded once
			report(req.Session.Elicit(ctx, urlParams("up-1", "https://auth.example.com/connect?x=1", "Sign in to Example")))
		}
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "not connected"}}}, nil, nil
	})
	mcp.AddTool(s, &mcp.Tool{Name: "create_many"}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		for i := range 8 {
			report(req.Session.Elicit(ctx, urlParams(fmt.Sprintf("id-%d", i), "https://auth.example.com/", "m")))
		}
		return &mcp.CallToolResult{}, nil, nil
	})
	// Multi round-trip (SEP-2322): the request comes back in the result.
	mrtr := func(p *mcp.ElicitParams) mcp.ToolHandlerFor[struct{}, any] {
		return func(_ context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
			if len(req.Params.InputResponses) == 0 {
				return &mcp.CallToolResult{InputRequests: mcp.InputRequestMap{"in": p}}, nil, nil
			}
			res, _ := req.Params.InputResponses["in"].(*mcp.ElicitResult)
			if res == nil {
				seen <- "no response"
			} else {
				seen <- res.Action
			}
			return &mcp.CallToolResult{IsError: true}, nil, nil
		}
	}
	mcp.AddTool(s, &mcp.Tool{Name: "mrtr_url"}, mrtr(urlParams("up-2", "https://auth.example.com/mrtr", "Approve")))
	mcp.AddTool(s, &mcp.Tool{Name: "mrtr_form"}, mrtr(&mcp.ElicitParams{Mode: "form", Message: "password?",
		RequestedSchema: map[string]any{"type": "object", "properties": map[string]any{"p": map[string]any{"type": "string"}}}}))
	mcp.AddTool(s, &mcp.Tool{Name: "mrtr_nomode"}, mrtr(&mcp.ElicitParams{Message: "anything?"}))
	mcp.AddTool(s, &mcp.Tool{Name: "required"}, func(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
		return nil, nil, mcp.URLElicitationRequiredError([]*mcp.ElicitParams{
			urlParams("up-3", "https://auth.example.com/req", "Connect your account"),
			urlParams("up-3", "https://auth.example.com/dup", "dup"),
		})
	})
	return s
}

// A stateful upstream sends elicitation/create {mode:"url"} mid-call: the
// handler records it once and answers cancel, which the tool sees.
func TestURLElicitationMidCallRecorded(t *testing.T) {
	seen := make(chan string, 16)
	up := streamableServer(t, elicitServer(seen), nil)
	s := connect(t, newTestClient(t, withURLElicitation), Endpoint{URL: up.URL + "/mcp"})
	if s.ProtocolVersion() != pvLegacy {
		t.Fatalf("version = %s, want %s (stateful)", s.ProtocolVersion(), pvLegacy)
	}
	res, err := s.CallTool(ctxT(t), "create_url", nil)
	if err != nil || !res.IsError {
		t.Fatalf("call = %+v, %v; want an isError result", res, err)
	}
	for range 2 {
		if a := <-seen; a != "cancel" {
			t.Errorf("tool saw %q, want cancel", a)
		}
	}
	want := []Elicitation{{"up-1", "https://auth.example.com/connect?x=1", "Sign in to Example"}}
	if got := s.Elicitations(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("Elicitations = %+v, want %+v", got, want)
	}
	s.ClearElicitations()
	if got := s.Elicitations(); got != nil {
		t.Errorf("after ClearElicitations = %+v", got)
	}

	if _, err := s.CallTool(ctxT(t), "create_many", nil); err != nil {
		t.Fatal(err)
	}
	for range 8 {
		if a := <-seen; a != "cancel" {
			t.Errorf("tool saw %q, want cancel", a)
		}
	}
	if n := len(s.Elicitations()); n != MaxElicitations {
		t.Errorf("recorded %d, want cap %d", n, MaxElicitations)
	}
}

// A stateless 2026-07-28 upstream asks through multi round-trip input
// requests: URL mode is recorded and answered cancel; form and mode-less
// requests get -32602 (the call fails client-side).
func TestURLElicitationMultiRoundTrip(t *testing.T) {
	seen := make(chan string, 16)
	up := statelessServer(t, elicitServer(seen))
	s := connect(t, newTestClient(t, withURLElicitation), Endpoint{URL: up.URL + "/mcp"})
	if s.ProtocolVersion() != pvModern {
		t.Fatalf("version = %s, want %s", s.ProtocolVersion(), pvModern)
	}
	if _, err := s.CallTool(ctxT(t), "mrtr_url", nil); err != nil {
		t.Fatal(err)
	}
	if a := <-seen; a != "cancel" {
		t.Errorf("tool saw %q, want cancel", a)
	}
	want := []Elicitation{{"up-2", "https://auth.example.com/mrtr", "Approve"}}
	if got := s.Elicitations(); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("Elicitations = %+v, want %+v", got, want)
	}
	for _, tool := range []string{"mrtr_form", "mrtr_nomode"} {
		_, err := s.CallTool(ctxT(t), tool, nil)
		var we *jsonrpc.Error
		if !errors.As(err, &we) || we.Code != jsonrpc.CodeInvalidParams || we.Message != "form elicitation not supported" {
			t.Errorf("%s: err = %v, want -32602 form elicitation not supported", tool, err)
		}
	}
	if n := len(s.Elicitations()); n != 1 {
		t.Errorf("form requests recorded: %+v", s.Elicitations())
	}
}

// answer400 serves a stateless go-sdk server but answers tools/call of
// "required" itself with HTTP 400 and a -32042 body, as servers that map
// JSON-RPC errors to 400 do (go-sdk v1.8.0 itself answers -32042 with 200
// and uses 400 only for -32602, -32022 and -32021 on 2026-07-28).
func answer400(t *testing.T, s *mcp.Server) *httptest.Server {
	t.Helper()
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return s },
		&mcp.StreamableHTTPOptions{Stateless: true})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Params struct {
				Name string `json:"name"`
			} `json:"params"`
		}
		_ = json.Unmarshal(body, &req)
		if req.Method == "tools/call" && req.Params.Name == "required" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32042,"message":"URL elicitation required",`+
				`"data":{"elicitations":[{"mode":"url","elicitationId":"up-3","url":"https://auth.example.com/req","message":"Connect your account"}]}}}`, req.ID)
			return
		}
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	return ts
}

// -32042 from a tool reaches the client as ClassToolError (HTTP 200: any
// go-sdk server) or ClassProtocol with Status 400 (servers answering
// JSON-RPC errors with 400): both carry RPCCode -32042 and are extracted.
func TestURLElicitationRequiredExtracted(t *testing.T) {
	for _, tc := range []struct {
		name   string
		up     func(*testing.T, *mcp.Server) *httptest.Server
		class  Class
		status int
	}{
		{"stateful 200", func(t *testing.T, s *mcp.Server) *httptest.Server { return streamableServer(t, s, nil) }, ClassToolError, 0},
		{"stateless 200", statelessServer, ClassToolError, 0},
		{"stateless 400", answer400, ClassProtocol, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			up := tc.up(t, elicitServer(make(chan string, 4)))
			s := connect(t, newTestClient(t, withURLElicitation), Endpoint{URL: up.URL + "/mcp"})
			_, err := s.CallTool(ctxT(t), "required", nil)
			e := wantClass(t, err, tc.class)
			if e.Status != tc.status || e.RPCCode != mcp.CodeURLElicitationRequired || !e.IsURLElicitationRequired() {
				t.Errorf("err = %v (status %d, code %d), want status %d code -32042", err, e.Status, e.RPCCode, tc.status)
			}
			got, ok := URLElicitations(fmt.Errorf("connector: %w", err))
			want := []Elicitation{{"up-3", "https://auth.example.com/req", "Connect your account"}}
			if !ok || fmt.Sprint(got) != fmt.Sprint(want) {
				t.Errorf("URLElicitations = %+v, %v; want %+v", got, ok, want)
			}
			assertNoLeak(t, err, "auth.example.com", "Connect your account")
		})
	}
	// Any other error is not an elicitation.
	up := streamableServer(t, fullServer(0, 0), nil)
	s := connect(t, newTestClient(t, withURLElicitation), Endpoint{URL: up.URL + "/mcp"})
	_, err := s.CallTool(ctxT(t), "no_such_tool", nil)
	var e *Error
	if !errors.As(err, &e) || e.IsURLElicitationRequired() {
		t.Fatalf("unknown tool err = %v", err)
	}
	if _, ok := URLElicitations(err); ok {
		t.Error("URLElicitations ok for an unknown-tool error")
	}
}

// initCapabilities connects c to a stateful upstream and returns the
// capabilities object of its initialize request.
func initCapabilities(t *testing.T, c *Client, srv *mcp.Server) map[string]json.RawMessage {
	t.Helper()
	var mu sync.Mutex
	var initBody []byte
	ts := streamableServer(t, srv, func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			body, _ := io.ReadAll(r.Body)
			if strings.Contains(string(body), `"initialize"`) {
				mu.Lock()
				initBody = body
				mu.Unlock()
			}
			r.Body = io.NopCloser(strings.NewReader(string(body)))
			h.ServeHTTP(w, r)
		})
	})
	connect(t, c, Endpoint{URL: ts.URL + "/mcp"})
	mu.Lock()
	defer mu.Unlock()
	var init struct {
		Params struct {
			Capabilities map[string]json.RawMessage `json:"capabilities"`
		} `json:"params"`
	}
	if err := json.Unmarshal(initBody, &init); err != nil {
		t.Fatalf("initialize body %q: %v", initBody, err)
	}
	return init.Params.Capabilities
}

func TestURLElicitationCapability(t *testing.T) {
	on := initCapabilities(t, newTestClient(t, withURLElicitation), elicitServer(make(chan string, 4)))
	if len(on) != 1 || string(on["elicitation"]) != `{"url":{}}` {
		t.Errorf("URLElicitation capabilities = %s, want only elicitation {\"url\":{}}", fmt.Sprint(on))
	}
	off := initCapabilities(t, newTestClient(t, nil), elicitServer(make(chan string, 4)))
	if len(off) != 0 {
		t.Errorf("default capabilities = %v, want none", off)
	}
}

// Without the option the client declares nothing and records nothing: a
// stateful upstream's Elicit fails server-side, and an input request
// (which bypasses the capability check) gets the go-sdk's own -32602
// "client does not support elicitation".
func TestURLElicitationOff(t *testing.T) {
	seen := make(chan string, 16)
	up := streamableServer(t, elicitServer(seen), nil)
	s := connect(t, newTestClient(t, nil), Endpoint{URL: up.URL + "/mcp"})
	if _, err := s.CallTool(ctxT(t), "create_url", nil); err != nil {
		t.Fatal(err)
	}
	if a := <-seen; !strings.Contains(a, "client does not support elicitation") {
		t.Errorf("stateful Elicit = %q, want refused for missing capability", a)
	}
	<-seen
	if got := s.Elicitations(); got != nil {
		t.Errorf("recorded without the option: %+v", got)
	}
	s.ClearElicitations() // no-op, no panic

	sl := connect(t, newTestClient(t, nil), Endpoint{URL: statelessServer(t, elicitServer(seen)).URL + "/mcp"})
	_, err := sl.CallTool(ctxT(t), "mrtr_url", nil)
	var we *jsonrpc.Error
	if !errors.As(err, &we) || we.Code != jsonrpc.CodeInvalidParams || !strings.Contains(we.Message, "does not support elicitation") {
		t.Errorf("input request without the option: err = %v, want SDK -32602", err)
	}
	if got := sl.Elicitations(); got != nil {
		t.Errorf("recorded without the option: %+v", got)
	}
}
