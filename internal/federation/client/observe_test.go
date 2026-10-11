package client

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
)

type callLog struct {
	mu    sync.Mutex
	calls []CallInfo
}

func (l *callLog) record(ci CallInfo) {
	l.mu.Lock()
	l.calls = append(l.calls, ci)
	l.mu.Unlock()
}

func (l *callLog) all() []CallInfo {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]CallInfo(nil), l.calls...)
}

func TestOnCallReportsEveryOperation(t *testing.T) {
	ts := streamableServer(t, fullServer(0, 0), nil)
	var log callLog
	c := newTestClient(t, func(o *Options) { o.OnCall = log.record })
	s := connect(t, c, Endpoint{URL: ts.URL + "/mcp", Label: "srv-1"})
	ctx := ctxT(t)
	if _, err := s.ListTools(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := s.CallTool(ctx, "echo", map[string]any{"text": "x"}); err != nil {
		t.Fatal(err)
	}
	_, _ = s.CallTool(ctx, "no_such_tool", nil)

	got := log.all()
	want := []struct {
		op    string
		class Class
	}{{"connect", ""}, {"tools/list", ""}, {"tools/call", ""}, {"tools/call", ClassToolError}}
	if len(got) != len(want) {
		t.Fatalf("OnCall got %d calls: %+v", len(got), got)
	}
	for i, w := range want {
		g := got[i]
		if g.Label != "srv-1" || g.Op != w.op || g.Class != w.class || g.Duration <= 0 {
			t.Errorf("call %d = %+v, want op %s class %q label srv-1", i, g, w.op, w.class)
		}
		if g.Transport != TransportStreamableHTTP {
			t.Errorf("call %d transport = %q", i, g.Transport)
		}
	}
}

func TestOnCallReportsConnectFailure(t *testing.T) {
	rk := &requireKey{}
	ts := streamableServer(t, fullServer(0, 0), rk.wrap)
	var log callLog
	c := newTestClient(t, func(o *Options) { o.OnCall = log.record })
	_, _ = c.Connect(ctxT(t), Endpoint{URL: ts.URL + "/mcp", Label: "srv-2"})
	got := log.all()
	if len(got) != 1 || got[0].Op != "connect" || got[0].Class != ClassAuthRequired || got[0].Label != "srv-2" {
		t.Fatalf("OnCall = %+v", got)
	}
}

func TestProtocolVersionNegotiation(t *testing.T) {
	ts := streamableServer(t, fullServer(0, 0), nil)
	s := connect(t, newTestClient(t, nil), Endpoint{URL: ts.URL + "/mcp"})
	if v := s.ProtocolVersion(); v < "2025-06-18" {
		t.Errorf("go-sdk server negotiated %q", v)
	}
	// An older server that only knows initialize (server/discover is
	// "method not found") gets the version it answered with.
	url := rawServer(t, nil)
	old := connect(t, newTestClient(t, nil), Endpoint{URL: url, Transport: TransportStreamableHTTP})
	if v := old.ProtocolVersion(); v != "2025-06-18" {
		t.Errorf("raw server negotiated %q, want 2025-06-18", v)
	}
	if old.ServerInfo().Name != "raw" {
		t.Errorf("ServerInfo = %+v", old.ServerInfo())
	}
}

func TestEventLimitBody(t *testing.T) {
	ev := func(n int) string { return "data: " + strings.Repeat("x", n) }
	for _, tc := range []struct {
		name    string
		body    string
		max     int64
		tooBig  bool
		readAll string
	}{
		{"LF events under the cap", ev(10) + "\n\n" + ev(10) + "\n\n", 20, false, ""},
		{"CRLF events under the cap", ev(10) + "\r\n\r\n" + ev(10) + "\r\n\r\n", 20, false, ""},
		{"CR events under the cap", ev(10) + "\r\r" + ev(10) + "\r\r", 20, false, ""},
		{"one event over the cap", ev(30) + "\n\n", 20, true, ""},
		{"multi-line event over the cap", ev(8) + "\n" + ev(8) + "\n" + ev(8) + "\n\n", 20, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			obs := &observer{}
			b := &eventLimitBody{rc: io.NopCloser(strings.NewReader(tc.body)), max: tc.max, obs: obs}
			_, err := io.ReadAll(b)
			if tc.tooBig != errors.Is(err, errTooLarge) {
				t.Fatalf("err = %v, tooBig want %v", err, tc.tooBig)
			}
			if tc.tooBig != obs.tooLarge {
				t.Errorf("observer tooLarge = %v", obs.tooLarge)
			}
		})
	}
}

func TestJSONResultBoundOnPlainJSONServer(t *testing.T) {
	url := rawServer(t, func(w http.ResponseWriter, method string, id, _ json.RawMessage) bool {
		if method != "tools/call" {
			return false
		}
		writeResult(w, id, map[string]any{"content": []any{map[string]any{"type": "text", "text": strings.Repeat("y", 64<<10)}}})
		return true
	})
	c := newTestClient(t, func(o *Options) { o.MaxResultBytes = 16 << 10 })
	s := connect(t, c, Endpoint{URL: url, Transport: TransportStreamableHTTP})
	_, err := s.CallTool(ctxT(t), "any", nil)
	_ = wantClass(t, err, ClassTooLarge)
}
