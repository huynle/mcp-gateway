package tunnel

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// fakeChild is the other end of a bridge: it reads what the bridge writes
// and lets the test answer by hand.
type fakeChild struct {
	lines  chan map[string]any
	stdout *io.PipeWriter
}

func newFakeChild(t *testing.T) (*StdioBridge, *fakeChild) {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	fc := &fakeChild{lines: make(chan map[string]any, 16), stdout: outW}
	go func() {
		sc := bufio.NewScanner(inR)
		for sc.Scan() {
			var m map[string]any
			if json.Unmarshal(sc.Bytes(), &m) == nil {
				fc.lines <- m
			}
		}
	}()
	b := NewStdioBridge(outR, inW, slog.New(slog.DiscardHandler))
	t.Cleanup(func() { _ = outW.Close(); _ = inW.Close() })
	return b, fc
}

func (fc *fakeChild) next(t *testing.T) map[string]any {
	t.Helper()
	select {
	case m := <-fc.lines:
		return m
	case <-time.After(5 * time.Second):
		t.Fatal("bridge wrote nothing to the child")
		return nil
	}
}

func (fc *fakeChild) send(t *testing.T, v any) {
	t.Helper()
	b, _ := json.Marshal(v)
	if _, err := fc.stdout.Write(append(b, '\n')); err != nil {
		t.Fatal(err)
	}
}

func postRPC(b http.Handler, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	b.ServeHTTP(rec, req)
	return rec
}

func TestStdioBridgeProtocol(t *testing.T) {
	b, fc := newFakeChild(t)

	// server/discover is answered locally with "method not found", so the
	// gateway's client falls back to the classic initialize handshake.
	rec := postRPC(b, `{"jsonrpc":"2.0","id":"d1","method":"server/discover","params":{}}`)
	var resp map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if rec.Code != http.StatusOK || resp["id"] != "d1" || resp["error"] == nil {
		t.Fatalf("discover: %d %s", rec.Code, rec.Body.String())
	}

	// A request is forwarded with the bridge's own id and answered with the
	// caller's id.
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- postRPC(b, `{"jsonrpc":"2.0","id":"abc","method":"tools/list","params":{}}`) }()
	m := fc.next(t)
	if m["method"] != "tools/list" || m["id"] == "abc" {
		t.Fatalf("child got %v", m)
	}
	// Meanwhile the child asks the client something: refused, not hung.
	fc.send(t, map[string]any{"jsonrpc": "2.0", "id": 77, "method": "roots/list"})
	refusal := fc.next(t)
	if refusal["id"] != float64(77) || refusal["error"] == nil {
		t.Fatalf("server->client request answered with %v", refusal)
	}
	fc.send(t, map[string]any{"jsonrpc": "2.0", "id": m["id"], "result": map[string]any{"tools": []any{}}})
	rec = <-done
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if rec.Code != http.StatusOK || resp["id"] != "abc" || resp["result"] == nil ||
		!strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("tools/list: %d %s", rec.Code, rec.Body.String())
	}

	// Notifications are accepted (202) and forwarded.
	rec = postRPC(b, `{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":1}}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("notification: %d", rec.Code)
	}
	if m := fc.next(t); m["method"] != "notifications/cancelled" {
		t.Fatalf("child got %v", m)
	}

	// Malformed input.
	for name, body := range map[string]string{"batch": `[{"jsonrpc":"2.0","id":1,"method":"ping"}]`, "not json": `nope`} {
		if rec := postRPC(b, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: %d, want 400", name, rec.Code)
		}
	}
	if rec := postRPC(b, `{"jsonrpc":"2.0","id":1,"method":"x","params":{"p":"`+strings.Repeat("a", maxBridgeBody)+`"}}`); rec.Code != http.StatusRequestEntityTooLarge {
		t.Errorf("oversized: %d, want 413", rec.Code)
	}
	rec = httptest.NewRecorder()
	b.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d, want 405", rec.Code)
	}

	// The child exits: pending and later requests fail with 502.
	go func() { done <- postRPC(b, `{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{}}`) }()
	fc.next(t)
	_ = fc.stdout.Close()
	if rec := <-done; rec.Code != http.StatusBadGateway {
		t.Fatalf("pending after exit: %d, want 502", rec.Code)
	}
	if rec := postRPC(b, `{"jsonrpc":"2.0","id":6,"method":"tools/list"}`); rec.Code != http.StatusBadGateway {
		t.Fatalf("after exit: %d, want 502", rec.Code)
	}
	select {
	case <-b.Done():
	default:
		t.Fatal("Done not closed after the child exited")
	}
}
