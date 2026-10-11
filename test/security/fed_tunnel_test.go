//go:build integration || e2e || security

package security

// Tunnel attacks (decision dzjepj6k: per-tunnel mgt_ token hashed whole,
// one live connection per tunnel, revocation closes it, bounded frames,
// 32 concurrent streams), driven by a raw WebSocket client playing a
// hostile tunnel agent.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/huynle/mcp-gateway/internal/federation/tunnel"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// rawFrame is the tunnel wire frame (internal/federation/tunnel/wire.go).
type rawFrame struct {
	Type   string      `json:"t"`
	ID     uint64      `json:"id,omitempty"`
	Method string      `json:"m,omitempty"`
	Path   string      `json:"p,omitempty"`
	Header http.Header `json:"h,omitempty"`
	Status int         `json:"s,omitempty"`
	Data   []byte      `json:"d,omitempty"`
	Error  string      `json:"e,omitempty"`
}

// dialTunnel opens the tunnel endpoint like a tunnel client and returns
// the connection, or the HTTP status of the refused handshake.
func (w *world) dialTunnel(ctx context.Context, header http.Header) (*websocket.Conn, int, error) {
	return dialWS(ctx, "ws"+strings.TrimPrefix(w.srv.URL, "http")+tunnel.ConnectPath, header)
}

func dialWS(ctx context.Context, u string, header http.Header) (*websocket.Conn, int, error) {
	c, res, err := websocket.Dial(ctx, u, &websocket.DialOptions{Subprotocols: []string{tunnel.Subprotocol}, HTTPHeader: header})
	status := 0
	if res != nil {
		status = res.StatusCode
		if res.Body != nil {
			_ = res.Body.Close()
		}
	}
	return c, status, err
}

func bearer(tok string) http.Header { return http.Header{"Authorization": {"Bearer " + tok}} }

// TestSecurityFedTunnelTokens: the tunnel endpoint admits only a live
// tunnel's exact token in the Authorization header. Missing, malformed,
// unknown, id-swapped, revoked, query-string and Basic credentials are
// 401 without a reason; a revoked tunnel's live connection is closed at
// once and cannot come back; a second connection with the same token
// replaces the first.
func TestSecurityFedTunnelTokens(t *testing.T) {
	w := newWorld(t, options{federation: true})
	ctx := t.Context()
	a, aRaw, err := w.fed.Tunnels.CreateTunnel(ctx, w.alice.id, "alice-a")
	if err != nil {
		t.Fatal(err)
	}
	_, bRaw, err := w.fed.Tunnels.CreateTunnel(ctx, w.bob.id, "bob-b")
	if err != nil {
		t.Fatal(err)
	}
	w.forbid(aRaw, "tunnel token")
	w.forbid(bRaw, "tunnel token")
	swapped := aRaw[:strings.LastIndex(aRaw, "_")] + bRaw[strings.LastIndex(bRaw, "_"):] // alice's id, bob's secret
	for name, h := range map[string]http.Header{
		"none":            nil,
		"garbage":         bearer("garbage"),
		"well-formed":     bearer("mgt_AAAAAAAA_" + strings.Repeat("a", 43)),
		"id-swapped":      bearer(swapped),
		"basic":           {"Authorization": {"Basic " + aRaw}},
		"bearer lower":    {"Authorization": {"bearer"}},
		"token with crlf": bearer(aRaw + "\r\nX-Evil: 1"),
	} {
		c, status, err := w.dialTunnel(ctx, h)
		if err == nil {
			_ = c.CloseNow()
			t.Errorf("%s: tunnel connected", name)
			continue
		}
		if status != 0 && status != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, status)
		}
	}
	u := "ws" + strings.TrimPrefix(w.srv.URL, "http") + tunnel.ConnectPath + "?token=" + url.QueryEscape(aRaw) + "&access_token=" + url.QueryEscape(aRaw)
	if c, _, err := dialWS(ctx, u, nil); err == nil {
		_ = c.CloseNow()
		t.Error("a token in the query string was accepted")
	}

	// Replacement: a second connection with the same token wins.
	first, _, err := w.dialTunnel(ctx, bearer(aRaw))
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := w.dialTunnel(ctx, bearer(aRaw))
	if err != nil {
		t.Fatal(err)
	}
	rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	_, _, err = first.Read(rctx)
	cancel()
	if websocket.CloseStatus(err) != 4001 {
		t.Errorf("first connection after replacement: %v, want close 4001", err)
	}
	// Revocation by the owner closes the live connection (4003) and the
	// token is refused afterwards.
	if code, _, _ := w.post(w.alice, "/servers/tunnels/revoke", url.Values{"id": {a.ID}}); code >= 400 {
		t.Fatalf("revoke = %d", code)
	}
	rctx, cancel = context.WithTimeout(ctx, 5*time.Second)
	_, _, err = second.Read(rctx)
	cancel()
	if websocket.CloseStatus(err) != 4003 {
		t.Errorf("live connection after revocation: %v, want close 4003", err)
	}
	if c, status, err := w.dialTunnel(ctx, bearer(aRaw)); err == nil {
		_ = c.CloseNow()
		t.Error("a revoked token reconnected")
	} else if status != http.StatusUnauthorized {
		t.Errorf("revoked token: %d %v", status, err)
	}
	if w.fed.Tunnels.Online(a.ID) {
		t.Error("the revoked tunnel is still online")
	}
}

// TestSecurityFedTunnelHostileClient: a tunnel client sending an oversized
// frame, a binary or malformed frame is disconnected; frames for unknown
// streams are ignored; a client that never answers can hold at most the
// stream bound (32) open, further calls are refused at once (busy), and
// everything is released when it disconnects. The gateway keeps serving.
func TestSecurityFedTunnelHostileClient(t *testing.T) {
	w := newWorld(t, options{federation: true, fedTimeout: 20 * time.Second})
	ctx := t.Context()
	tun, raw, err := w.fed.Tunnels.CreateTunnel(ctx, w.alice.id, "alice-hostile")
	if err != nil {
		t.Fatal(err)
	}
	w.forbid(raw, "tunnel token")
	s := w.addServer(w.alice, "hostiletun", tunnel.URL(tun.ID, "/mcp"), nil)
	w.exec(`INSERT INTO mcp_server_snapshots (server_id, version, status, tools, review) VALUES ($1, 1, 'approved', $2::jsonb, $3::jsonb)`,
		s.ID, `[{"name":"search","inputSchema":{"type":"object"}}]`, `{"search":{"enabled":true,"kind":"read"}}`)
	if err := w.fed.Manager.ServerChanged(ctx, s.ID); err != nil {
		t.Fatal(err)
	}

	for name, send := range map[string]func(c *websocket.Conn) error{
		"oversized frame": func(c *websocket.Conn) error {
			return c.Write(ctx, websocket.MessageText, []byte(`{"t":"data","id":1,"d":"`+strings.Repeat("A", 2<<20)+`"}`))
		},
		"binary frame":    func(c *websocket.Conn) error { return c.Write(ctx, websocket.MessageBinary, []byte{1, 2, 3}) },
		"malformed frame": func(c *websocket.Conn) error { return c.Write(ctx, websocket.MessageText, []byte(`{"t":`)) },
	} {
		c, _, err := w.dialTunnel(ctx, bearer(raw))
		if err != nil {
			t.Fatal(err)
		}
		_ = send(c)
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		for {
			if _, _, err = c.Read(rctx); err != nil {
				break
			}
		}
		cancel()
		if websocket.CloseStatus(err) == -1 && rctx.Err() != nil {
			t.Errorf("%s: the connection stayed open", name)
		}
		_ = c.CloseNow()
		waitFor(t, func() bool { return !w.fed.Tunnels.Online(tun.ID) })
	}

	// A client that never answers.
	c, _, err := w.dialTunnel(ctx, bearer(raw))
	if err != nil {
		t.Fatal(err)
	}
	c.SetReadLimit(64 << 20)
	waitFor(t, func() bool { return w.fed.Tunnels.Online(tun.ID) })
	var reqs atomic.Int64
	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		for {
			_, b, err := c.Read(ctx)
			if err != nil {
				return
			}
			var f rawFrame
			if json.Unmarshal(b, &f) == nil && f.Type == "req" {
				reqs.Add(1)
				// Frames for streams that do not exist are ignored.
				for _, junk := range []rawFrame{{Type: "head", ID: f.ID + 1000, Status: 200}, {Type: "data", ID: 999999, Data: []byte("x")}, {Type: "end", ID: 424242}} {
					jb, _ := json.Marshal(junk)
					_ = c.Write(ctx, websocket.MessageText, jb)
				}
			}
		}
	}()
	const calls = 40
	var wg sync.WaitGroup
	var fastFail atomic.Int64
	var outMu sync.Mutex
	var outcomes []string
	tok := w.token(w.alice, tokens.CreateRequest{})
	for range calls {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			code, _, body := w.rawCall(tok, "hostiletun.search", map[string]any{})
			took := time.Since(start)
			// Refused for lack of a free stream, while the 32 streams are
			// still held (the hostile client is released only after this
			// count is reached, so these did not wait for it).
			if code == http.StatusOK && strings.Contains(string(body), "could not be reached") {
				fastFail.Add(1)
			}
			outMu.Lock()
			outcomes = append(outcomes, fmt.Sprintf("%d after %s: %.120s", code, took.Round(100*time.Millisecond), body))
			outMu.Unlock()
		}()
	}
	deadline := time.Now().Add(30 * time.Second)
	for (reqs.Load() < 32 || fastFail.Load() < calls-32) && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if fastFail.Load() < calls-32 {
		outMu.Lock()
		t.Errorf("%d calls refused for lack of a stream while the others were held, want %d; finished so far:\n%s", fastFail.Load(), calls-32, strings.Join(outcomes, "\n"))
		outMu.Unlock()
	}
	time.Sleep(300 * time.Millisecond)
	if n := reqs.Load(); n > 32 {
		t.Errorf("%d concurrent requests reached the tunnel client, want at most 32", n)
	}
	// Unrelated traffic is unaffected while the streams are held.
	start := time.Now()
	code, _, body := w.rawCall(w.token(w.bob, tokens.CreateRequest{}), "fake.list_items", map[string]any{"account": w.bobAcc})
	if code != http.StatusOK || strings.Contains(string(body), `"error"`) || time.Since(start) > 3*time.Second {
		t.Errorf("unrelated call during the flood: %d in %s: %.200s", code, time.Since(start), body)
	}
	_ = c.Close(websocket.StatusNormalClosure, "bye")
	wg.Wait()
	<-readDone
	waitFor(t, func() bool { return !w.fed.Tunnels.Online(tun.ID) })
	if res, err := w.call(w.client(w.alice), "fake.list_items", map[string]any{"account": w.aliceAcc}); err != nil || res.IsError {
		t.Errorf("the gateway stopped serving: %v %+v", err, res)
	}
}
