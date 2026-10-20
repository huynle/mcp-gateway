package tunnel

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// The client-side targets (NewHTTPForwarder, NewStdioBridge, StartStdio)
// are shared by the legacy tunnel client and the machine agent.

func TestHTTPForwarderStaysOnTarget(t *testing.T) {
	type seen struct{ host, uri, hdr string }
	got := make(chan seen, 4)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- seen{r.Host, r.URL.RequestURI(), r.Header.Get("X-Test")}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: x\n\n")
	}))
	defer target.Close()
	tu, _ := url.Parse(target.URL + "/mcp")
	fw := NewHTTPForwarder(tu, target.Client())

	for _, tc := range []struct{ in, want string }{
		{"/", "/mcp"},
		{"/messages?sessionId=1", "/messages?sessionId=1"},
		{"//evil.example/x", "//evil.example/x"},
	} {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "http://tunnel"+tc.in, strings.NewReader("{}"))
		req.RequestURI = tc.in
		req.URL, _ = url.ParseRequestURI(tc.in)
		req.Header.Set("X-Test", "v")
		req.Header.Set("Connection", "X-Drop")
		req.Header.Set("X-Drop", "secret")
		rec := httptest.NewRecorder()
		fw.ServeHTTP(rec, req)
		s := <-got
		wantHost := strings.TrimPrefix(target.URL, "http://")
		if s.host != wantHost || s.uri != tc.want || s.hdr != "v" {
			t.Errorf("%s: target saw host %q uri %q hdr %q; want %q %q", tc.in, s.host, s.uri, s.hdr, wantHost, tc.want)
		}
		if rec.Code != http.StatusOK || rec.Body.String() != "data: x\n\n" || rec.Header().Get("Content-Type") != "text/event-stream" {
			t.Errorf("%s: response %d %q %v", tc.in, rec.Code, rec.Body.String(), rec.Header())
		}
	}
	dead, _ := url.Parse("http://127.0.0.1:1/mcp")
	rec := httptest.NewRecorder()
	NewHTTPForwarder(dead, target.Client()).ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", nil))
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("dead target: %d, want 502", rec.Code)
	}
}

func TestStdioBridgeAnswersDiscoverLocallyAndRewritesIDs(t *testing.T) {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	t.Cleanup(func() { _ = outW.Close(); _ = inW.Close() })
	b := NewStdioBridge(outR, inW, slog.New(slog.DiscardHandler))

	post := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", strings.NewReader(body))
		rec := httptest.NewRecorder()
		b.ServeHTTP(rec, req)
		return rec
	}
	rec := post(`{"jsonrpc":"2.0","id":"d1","method":"server/discover"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"id":"d1"`) || !strings.Contains(rec.Body.String(), "-32601") {
		t.Fatalf("server/discover = %d %s", rec.Code, rec.Body.String())
	}
	// A call is forwarded with the bridge's own id and answered with the
	// caller's.
	go func() {
		sc := bufio.NewScanner(inR)
		for sc.Scan() {
			var m map[string]any
			_ = json.Unmarshal(sc.Bytes(), &m)
			out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m["id"], "result": map[string]any{"ok": true}})
			_, _ = outW.Write(append(out, '\n'))
		}
	}()
	rec = post(`{"jsonrpc":"2.0","id":"x-7","method":"tools/list"}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"id":"x-7"`) || !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("tools/list = %d %s", rec.Code, rec.Body.String())
	}
	_ = outW.Close()
	select {
	case <-b.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("bridge not done after stdout closed")
	}
}

// TestStdioHelperProcess is the child StartStdio runs in the test below:
// it prints its environment and directory as one JSON-RPC result line per
// request.
func TestStdioHelperProcess(t *testing.T) {
	if os.Getenv("TUNNEL_STDIO_HELPER") != "1" {
		t.Skip("helper process")
	}
	dir, _ := os.Getwd()
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		var m map[string]any
		if json.Unmarshal(sc.Bytes(), &m) != nil || m["id"] == nil {
			continue
		}
		out, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": m["id"], "result": map[string]any{"env": os.Environ(), "dir": dir}})
		_, _ = os.Stdout.Write(append(out, '\n'))
	}
	os.Exit(0)
}

func TestStartStdioUsesExactlyTheGivenEnvironmentAndDirectory(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("MCP_GATEWAY_SECRET_THAT_MUST_NOT_LEAK", "x")
	p, err := StartStdio(t.Context(), StdioOptions{
		Command: []string{os.Args[0], "-test.run=^TestStdioHelperProcess$"},
		Env:     []string{"TUNNEL_STDIO_HELPER=1", "ONLY=this"},
		Dir:     dir,
		Log:     slog.New(slog.DiscardHandler),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Stop()
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	rec := httptest.NewRecorder()
	p.Handler().ServeHTTP(rec, req)
	var resp struct {
		Result struct {
			Env []string `json:"env"`
			Dir string   `json:"dir"`
		} `json:"result"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	for _, kv := range resp.Result.Env {
		if strings.HasPrefix(kv, "MCP_GATEWAY_SECRET_THAT_MUST_NOT_LEAK=") {
			t.Fatalf("the parent's environment leaked into the child: %v", resp.Result.Env)
		}
	}
	if !slices.Contains(resp.Result.Env, "ONLY=this") {
		t.Fatalf("child env = %v", resp.Result.Env)
	}
	wantDir, _ := filepath.EvalSymlinks(dir)
	gotDir, _ := filepath.EvalSymlinks(resp.Result.Dir)
	if gotDir != wantDir {
		t.Fatalf("child dir = %q, want %q", gotDir, wantDir)
	}
	p.Stop()
	select {
	case <-p.Done():
	case <-time.After(10 * time.Second):
		t.Fatal("process not done after Stop")
	}
}
