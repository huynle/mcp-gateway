package machineclient

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	gwtunnel "github.com/huynle/mcp-gateway/internal/federation/tunnel"
)

// wireFrame mirrors the tunnel wire frame (internal/federation/tunnel).
type wireFrame struct {
	Type   string      `json:"t"`
	ID     uint64      `json:"id,omitempty"`
	Tunnel string      `json:"tid,omitempty"`
	Method string      `json:"m,omitempty"`
	Path   string      `json:"p,omitempty"`
	Header http.Header `json:"h,omitempty"`
	Status int         `json:"s,omitempty"`
	Data   []byte      `json:"d,omitempty"`
	Error  string      `json:"e,omitempty"`
}

// fakeMachineGateway accepts one machine connection, checks the bearer
// token and subprotocol, sends one request per tunnel id and collects the
// responses, then closes with closeCode.
func fakeMachineGateway(t *testing.T, tunnelIDs []string, closeCode websocket.StatusCode, got chan<- map[string]string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != gwtunnel.MachineConnectPath || r.Header.Get("Authorization") != "Bearer mgm_test" {
			http.Error(w, "nope", http.StatusUnauthorized)
			return
		}
		ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{gwtunnel.MachineSubprotocol}})
		if err != nil {
			return
		}
		ctx := r.Context()
		bodies := map[string]string{}
		byID := map[uint64]string{}
		for i, tid := range tunnelIDs {
			id := uint64(i + 1)
			byID[id] = tid
			b, _ := json.Marshal(wireFrame{Type: "req", ID: id, Tunnel: tid, Method: http.MethodPost, Path: "/mcp", Data: []byte("ping-" + tid)})
			if err := ws.Write(ctx, websocket.MessageText, b); err != nil {
				return
			}
		}
		for done := 0; done < len(tunnelIDs); {
			_, b, err := ws.Read(ctx)
			if err != nil {
				return
			}
			var f wireFrame
			_ = json.Unmarshal(b, &f)
			switch f.Type {
			case "data":
				bodies[byID[f.ID]] += string(f.Data)
			case "end":
				done++
			}
		}
		got <- bodies
		_ = ws.Close(closeCode, "bye")
	}))
}

func echoHandler(prefix string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_, _ = w.Write([]byte(prefix + string(b)))
	})
}

// The real connector routes each request to its tunnel's handler over one
// connection, reports the connection, and maps 4003 to ErrRevoked.
func TestMachineConnectorRoutesByTunnelAndMapsRevoked(t *testing.T) {
	got := make(chan map[string]string, 1)
	srv := fakeMachineGateway(t, []string{"t-a", "t-b"}, 4003, got)
	defer srv.Close()
	var connected atomic.Int32
	targets := map[string]Target{
		"t-a": {Kind: KindHTTP, Handler: echoHandler("A:")},
		"t-b": {Kind: KindStdio, Handler: echoHandler("B:")},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := tunnelConnector{}.Run(ctx, srv.URL, func(context.Context) (string, error) { return "mgm_test", nil }, targets, func() { connected.Add(1) })
	if !errors.Is(err, ErrRevoked) {
		t.Fatalf("Run = %v, want ErrRevoked", err)
	}
	if connected.Load() == 0 {
		t.Error("onConnected never called")
	}
	select {
	case b := <-got:
		if b["t-a"] != "A:ping-t-a" || b["t-b"] != "B:ping-t-b" {
			t.Errorf("responses = %v", b)
		}
	default:
		t.Fatal("gateway saw no responses")
	}
}

// 4001 (replaced by a newer connection) maps to ErrReplaced.
func TestMachineConnectorMapsReplaced(t *testing.T) {
	got := make(chan map[string]string, 1)
	srv := fakeMachineGateway(t, []string{"t-a"}, 4001, got)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := tunnelConnector{}.Run(ctx, srv.URL, func(context.Context) (string, error) { return "mgm_test", nil },
		map[string]Target{"t-a": {Handler: echoHandler("")}}, nil)
	if !errors.Is(err, ErrReplaced) {
		t.Fatalf("Run = %v, want ErrReplaced", err)
	}
}

// Any other end of the connection is handed back to `up` (it reconnects),
// never silently retried inside the connector.
func TestMachineConnectorReturnsOnDisconnect(t *testing.T) {
	got := make(chan map[string]string, 1)
	srv := fakeMachineGateway(t, []string{"t-a"}, websocket.StatusGoingAway, got)
	defer srv.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	start := time.Now()
	err := tunnelConnector{}.Run(ctx, srv.URL, func(context.Context) (string, error) { return "mgm_test", nil },
		map[string]Target{"t-a": {Handler: echoHandler("")}}, nil)
	if err == nil || errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 10*time.Second {
		t.Fatalf("Run = %v after %v, want a prompt disconnect error", err, time.Since(start))
	}
	if strings.Contains(err.Error(), "mgm_test") {
		t.Error("error leaks the token")
	}
}
