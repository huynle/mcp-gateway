package tunnel

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Cross-replica relay (decision efq0ncag item 5): two Services share one
// store, each with its own relay listener; a tunnel connected to one is
// usable through the other.

var (
	secretOne = []byte("relay-secret-one-0123456789abcdef-xyz")
	secretTwo = []byte("relay-secret-two-0123456789abcdef-xyz")
)

// replica is one gateway replica: its public tunnel endpoint (g.srv) and
// its relay listener (relaySrv).
type replica struct {
	*gw
	relaySrv *httptest.Server
}

// newReplica builds a replica over ms. secret nil disables the relay.
func newReplica(t *testing.T, ms *memStore, l Limits, secret []byte) *replica {
	t.Helper()
	var relayHandler atomic.Value // http.Handler, set once the Service exists
	relaySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		relayHandler.Load().(http.Handler).ServeHTTP(w, r)
	}))
	t.Cleanup(relaySrv.Close)
	buf := &syncBuffer{}
	opts := Options{Store: ms, Limits: l, Log: slog.New(slog.NewTextHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug}))}
	if secret != nil {
		opts.Relay = &RelayOptions{Holders: ms, Advertise: relaySrv.URL, Secret: secret, HTTPClient: &http.Client{}}
	}
	svc, err := NewService(opts)
	if err != nil {
		t.Fatal(err)
	}
	relayHandler.Store(svc.RelayHandler())
	mux := http.NewServeMux()
	mux.Handle(ConnectPath, svc.Handler())
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return &replica{gw: &gw{svc: svc, ms: ms, srv: srv, log: buf}, relaySrv: relaySrv}
}

func newPair(t *testing.T, l Limits) (a, b *replica) {
	t.Helper()
	ms := newMemStore()
	return newReplica(t, ms, l, secretOne), newReplica(t, ms, l, secretOne)
}

func readAll(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(b)
}

func TestRelayForwardsToTheHolder(t *testing.T) {
	a, b := newPair(t, Limits{})
	id, raw := a.newTunnel(t)
	a.startAgent(t, raw, echoHandler())
	eventually(t, "online on A", func() bool { return a.svc.Online(id) })
	eventually(t, "holder recorded", func() bool { h, ok := a.ms.holder(id); return ok && h.Holder == a.relaySrv.URL })
	if !b.svc.Online(id) {
		t.Error("B does not report the tunnel online although A holds it")
	}

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, "tunnel://"+id+"/mcp/x?q=1", strings.NewReader("hello"))
	req.Header.Set("X-Test", "v")
	resp, err := b.client().Do(req)
	if err != nil {
		t.Fatalf("through B: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body := readAll(t, resp)
	if resp.StatusCode != http.StatusCreated || body != "hello" || resp.Header.Get("X-Echo-Method") != "POST" ||
		resp.Header.Get("X-Echo-Path") != "/mcp/x?q=1" || resp.Header.Get("X-Echo-Header") != "v" {
		t.Fatalf("status %d body %q headers %v", resp.StatusCode, body, resp.Header)
	}
	for k := range resp.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-mgw-relay") {
			t.Errorf("relay header %s leaked to the caller", k)
		}
	}
}

func TestRelayStreamsEventsBeforeTheHandlerEnds(t *testing.T) {
	a, b := newPair(t, Limits{})
	id, raw := a.newTunnel(t)
	release := make(chan struct{})
	a.startAgent(t, raw, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: one\n\n")
		w.(http.Flusher).Flush()
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, "data: two\n\n")
	}))
	eventually(t, "online", func() bool { return a.svc.Online(id) })
	resp, err := b.do(http.MethodGet, "tunnel://"+id+"/sse", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	br := bufio.NewReader(resp.Body)
	line, err := br.ReadString('\n')
	if err != nil || line != "data: one\n" {
		t.Fatalf("first event %q, %v", line, err)
	}
	close(release)
	rest, err := io.ReadAll(br)
	if err != nil || string(rest) != "\ndata: two\n\n" {
		t.Fatalf("rest %q, %v", rest, err)
	}
}

func TestRelayDisabledKeepsOldBehaviour(t *testing.T) {
	ms := newMemStore()
	a := newReplica(t, ms, Limits{}, secretOne)
	plain := newReplica(t, ms, Limits{}, nil)
	id, raw := a.newTunnel(t)
	a.startAgent(t, raw, echoHandler())
	eventually(t, "online", func() bool { return a.svc.Online(id) })
	if err := plain.doErr(http.MethodGet, "tunnel://"+id+"/mcp", nil); classOf(err) != ClassOffline {
		t.Fatalf("relay off: err %v, want %s", err, ClassOffline)
	}
	if plain.svc.Online(id) {
		t.Error("relay off: Online must only report this replica's connections")
	}
	if plain.svc.RelayEnabled() || !a.svc.RelayEnabled() {
		t.Error("RelayEnabled wrong")
	}

	// A relay-less replica never writes holder rows.
	ms2 := newMemStore()
	solo := newReplica(t, ms2, Limits{}, nil)
	id2, raw2 := solo.newTunnel(t)
	solo.startAgent(t, raw2, echoHandler())
	eventually(t, "online", func() bool { return solo.svc.Online(id2) })
	if _, ok := ms2.holder(id2); ok {
		t.Error("relay off: holder row written")
	}
	resp, err := solo.do(http.MethodGet, "tunnel://"+id2+"/x", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	_ = readAll(t, resp)
}

func TestRelayHandover(t *testing.T) {
	l := Limits{HeartbeatInterval: 50 * time.Millisecond}
	a, b := newPair(t, l)
	id, raw := a.newTunnel(t)

	// The client connects to A, then reconnects to B.
	first := a.startAgent(t, raw, echoHandler())
	eventually(t, "online on A", func() bool { return a.svc.Online(id) })
	first.cancel()
	<-waitOr(first.done)
	eventually(t, "A forgets", func() bool { return !a.svc.Online(id) })
	eventually(t, "A releases its row", func() bool { _, ok := a.ms.holder(id); return !ok })
	b.startAgent(t, raw, echoHandler())
	eventually(t, "online on B", func() bool { return b.svc.Online(id) })
	eventually(t, "B holds", func() bool { h, ok := b.ms.holder(id); return ok && h.Holder == b.relaySrv.URL })
	resp, err := a.do(http.MethodPost, "tunnel://"+id+"/x", strings.NewReader("via A"))
	if err != nil {
		t.Fatalf("through A after handover: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := readAll(t, resp); got != "via A" {
		t.Fatalf("body %q", got)
	}
}

func TestRelayNewerConnectionElsewhereReplacesTheOld(t *testing.T) {
	l := Limits{HeartbeatInterval: 50 * time.Millisecond}
	a, b := newPair(t, l)
	id, raw := a.newTunnel(t)
	old := a.startAgent(t, raw, echoHandler())
	eventually(t, "online on A", func() bool { return a.svc.Online(id) })
	b.startAgent(t, raw, echoHandler())
	eventually(t, "online on B", func() bool { return b.svc.Online(id) })
	// A notices at its next heartbeat that B holds a newer connection.
	if err := <-waitOr(old.done); !errors.Is(err, ErrReplaced) {
		t.Fatalf("old agent: %v, want ErrReplaced", err)
	}
	eventually(t, "A dropped its connection", func() bool { return !a.svc.Online(id) || a.svc.reg.get(id) == nil })
	resp, err := a.do(http.MethodPost, "tunnel://"+id+"/x", strings.NewReader("ok"))
	if err != nil {
		t.Fatalf("through A: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if got := readAll(t, resp); got != "ok" {
		t.Fatalf("body %q", got)
	}
	h, _ := a.ms.holder(id)
	if h.Holder != b.relaySrv.URL {
		t.Fatalf("holder = %s, want B", h.Holder)
	}
}

func TestRelayRevocationAcrossReplicas(t *testing.T) {
	l := Limits{HeartbeatInterval: 50 * time.Millisecond}
	a, b := newPair(t, l)
	id, raw := a.newTunnel(t)
	r := a.startAgent(t, raw, echoHandler())
	eventually(t, "online", func() bool { return a.svc.Online(id) })
	if err := b.svc.Revoke(context.Background(), ownerA, id); err != nil {
		t.Fatal(err)
	}
	// B refuses at once (the holder row is of a revoked tunnel) ...
	if err := b.doErr(http.MethodGet, "tunnel://"+id+"/x", nil); classOf(err) != ClassOffline {
		t.Fatalf("through B after revoke: %v, want %s", err, ClassOffline)
	}
	// ... and A drops the connection within a heartbeat.
	if err := <-waitOr(r.done); !errors.Is(err, ErrRevoked) && !errors.Is(err, ErrRejected) {
		t.Fatalf("agent after revoke: %v", err)
	}
}

func TestRelayStaleSelfAndWrongEpochAreOffline(t *testing.T) {
	a, b := newPair(t, Limits{})
	id, raw := a.newTunnel(t)
	a.startAgent(t, raw, echoHandler())
	eventually(t, "holder", func() bool { _, ok := a.ms.holder(id); return ok })
	h, _ := a.ms.holder(id)

	// Not seen for longer than the staleness bound.
	b.ms.setLastSeen(id, time.Now().Add(-time.Hour))
	if err := b.doErr(http.MethodGet, "tunnel://"+id+"/x", nil); classOf(err) != ClassOffline {
		t.Fatalf("stale: %v", err)
	}
	b.ms.setLastSeen(id, time.Now())

	// The row names B itself, but B has no connection.
	b.ms.setHolder(id, b.relaySrv.URL, h.Epoch)
	if err := b.doErr(http.MethodGet, "tunnel://"+id+"/x", nil); classOf(err) != ClassOffline {
		t.Fatalf("self: %v", err)
	}

	// The row names A with an epoch A does not hold: A refuses (not holder).
	b.ms.setHolder(id, a.relaySrv.URL, h.Epoch+100)
	err := b.doErr(http.MethodGet, "tunnel://"+id+"/x", nil)
	if classOf(err) != ClassOffline {
		t.Fatalf("wrong epoch: %v", err)
	}
	if strings.Contains(err.Error(), "127.0.0.1") || strings.Contains(err.Error(), a.relaySrv.URL) {
		t.Fatalf("error leaks the holder address: %v", err)
	}

	// An unusable holder address is never dialled.
	b.ms.setHolder(id, "file:///etc/passwd", h.Epoch)
	if err := b.doErr(http.MethodGet, "tunnel://"+id+"/x", nil); classOf(err) != ClassOffline {
		t.Fatalf("bad holder url: %v", err)
	}
}

func TestRelayUnreachableHolderIsOffline(t *testing.T) {
	a, b := newPair(t, Limits{})
	id, raw := a.newTunnel(t)
	a.startAgent(t, raw, echoHandler())
	eventually(t, "holder", func() bool { _, ok := a.ms.holder(id); return ok })
	a.relaySrv.Close()
	err := b.doErr(http.MethodGet, "tunnel://"+id+"/x", nil)
	if classOf(err) != ClassOffline {
		t.Fatalf("holder down: %v", err)
	}
}

func TestRelayMismatchedSecretIsRejected(t *testing.T) {
	ms := newMemStore()
	a := newReplica(t, ms, Limits{}, secretOne)
	b := newReplica(t, ms, Limits{}, secretTwo)
	id, raw := a.newTunnel(t)
	a.startAgent(t, raw, echoHandler())
	eventually(t, "holder", func() bool { _, ok := a.ms.holder(id); return ok })
	if err := b.doErr(http.MethodGet, "tunnel://"+id+"/x", nil); classOf(err) != ClassOffline {
		t.Fatalf("wrong secret: %v, want %s", err, ClassOffline)
	}
	for _, r := range []*replica{a, b} {
		for _, s := range [][]byte{secretOne, secretTwo} {
			if strings.Contains(r.log.String(), string(s)) {
				t.Fatal("a relay secret reached the log")
			}
		}
	}
}

func TestRelayErrorClassesCrossReplicas(t *testing.T) {
	l := Limits{ResponseHeaderTimeout: 150 * time.Millisecond, MaxResponseBytes: 1 << 10, MaxRequestBytes: 1 << 10}
	a, b := newPair(t, l)
	id, raw := a.newTunnel(t)
	a.startAgent(t, raw, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/slow":
			select {
			case <-time.After(2 * time.Second):
			case <-r.Context().Done():
			}
		case "/big":
			_, _ = w.Write(bytes.Repeat([]byte("x"), 4<<10))
		case "/status":
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	eventually(t, "online", func() bool { return a.svc.Online(id) })

	err := b.doErr(http.MethodGet, "tunnel://"+id+"/slow", nil)
	var te *Error
	if !errors.As(err, &te) || te.Class != ClassTimeout || !te.Timeout() {
		t.Fatalf("slow: %v, want %s", err, ClassTimeout)
	}

	resp, err := b.do(http.MethodGet, "tunnel://"+id+"/big", nil)
	if err != nil {
		t.Fatalf("big: %v", err)
	}
	_, err = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if classOf(err) != ClassTooLarge {
		t.Fatalf("big body: %v, want %s", err, ClassTooLarge)
	}

	if err := b.doErr(http.MethodPost, "tunnel://"+id+"/x", bytes.NewReader(make([]byte, 2<<10))); classOf(err) != ClassTooLarge {
		t.Fatalf("big request: %v, want %s", err, ClassTooLarge)
	}

	resp, err = b.do(http.MethodGet, "tunnel://"+id+"/status", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	_ = readAll(t, resp)
	if resp.StatusCode != http.StatusTeapot {
		t.Fatalf("status %d, want 418 passed through", resp.StatusCode)
	}
}

// --- the relay endpoint's own checks ---------------------------------------

// relayReq builds a request to r's relay endpoint signed with secret.
func relayReq(t *testing.T, r *replica, secret []byte, id string, epoch int64, body []byte, at time.Time, nonce string) *http.Request {
	t.Helper()
	req, err := signedRelayRequest(context.Background(), r.relaySrv.URL, secret, id, epoch, http.MethodPost, "/x", http.Header{"X-Test": {"v"}}, body, at, nonce)
	if err != nil {
		t.Fatal(err)
	}
	return req
}

func send(t *testing.T, req *http.Request) (int, string) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode, resp.Header.Get(relayHeaderError)
}

func TestRelayEndpointAuthenticates(t *testing.T) {
	a, _ := newPair(t, Limits{MaxRequestBytes: 1 << 10})
	id, raw := a.newTunnel(t)
	a.startAgent(t, raw, echoHandler())
	eventually(t, "holder", func() bool { _, ok := a.ms.holder(id); return ok })
	h, _ := a.ms.holder(id)
	now := time.Now()

	// Sanity: a correctly signed request is served.
	if code, _ := send(t, relayReq(t, a, secretOne, id, h.Epoch, []byte("hi"), now, "n-ok")); code != http.StatusOK {
		t.Fatalf("valid: %d", code)
	}

	// Replaying the same request (same nonce) is refused.
	if code, cls := send(t, relayReq(t, a, secretOne, id, h.Epoch, []byte("hi"), now, "n-ok")); code != http.StatusUnauthorized || cls != relayErrUnauthorized {
		t.Fatalf("replay: %d %s", code, cls)
	}

	missing := relayReq(t, a, secretOne, id, h.Epoch, []byte("hi"), now, "n-missing")
	missing.Header.Del(relayHeaderSignature)
	tampered := relayReq(t, a, secretOne, id, h.Epoch, []byte("hi"), now, "n-tampered")
	tampered.Body = io.NopCloser(strings.NewReader("ho"))
	retarget := relayReq(t, a, secretOne, id, h.Epoch, []byte("hi"), now, "n-retarget")
	retarget.Header.Set(relayHeaderEpoch, strconv.FormatInt(h.Epoch+7, 10))
	for name, req := range map[string]*http.Request{
		"missing signature": missing,
		"wrong secret":      relayReq(t, a, secretTwo, id, h.Epoch, []byte("hi"), now, "n-wrong"),
		"tampered body":     tampered,
		"changed epoch":     retarget,
		"too old":           relayReq(t, a, secretOne, id, h.Epoch, []byte("hi"), now.Add(-10*time.Minute), "n-old"),
		"from the future":   relayReq(t, a, secretOne, id, h.Epoch, []byte("hi"), now.Add(10*time.Minute), "n-future"),
	} {
		if code, cls := send(t, req); code != http.StatusUnauthorized || cls != relayErrUnauthorized {
			t.Errorf("%s: %d %s, want 401 %s", name, code, cls, relayErrUnauthorized)
		}
	}

	// Signed, but this replica does not hold that epoch (or that tunnel).
	if code, cls := send(t, relayReq(t, a, secretOne, id, h.Epoch+1, []byte("hi"), now, "n-epoch")); code != http.StatusConflict || cls != relayErrNotHolder {
		t.Errorf("wrong epoch: %d %s", code, cls)
	}
	other, _ := a.newTunnel(t)
	if code, cls := send(t, relayReq(t, a, secretOne, other, h.Epoch, []byte("hi"), now, "n-other")); code != http.StatusConflict || cls != relayErrNotHolder {
		t.Errorf("other tunnel: %d %s", code, cls)
	}

	// Body bound identical to the tunnel transport's.
	if code, cls := send(t, relayReq(t, a, secretOne, id, h.Epoch, make([]byte, 2<<10), now, "n-big")); code != http.StatusRequestEntityTooLarge || cls != string(ClassTooLarge) {
		t.Errorf("big body: %d %s", code, cls)
	}

	// Only POST on the exact path.
	get, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, a.relaySrv.URL+RelayPath, nil)
	if code, _ := send(t, get); code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", code)
	}
	elsewhere, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, a.relaySrv.URL+"/other", nil)
	if code, _ := send(t, elsewhere); code != http.StatusNotFound {
		t.Errorf("other path: %d", code)
	}
}

func TestRelayOptionsValidated(t *testing.T) {
	ms := newMemStore()
	good := RelayOptions{Holders: ms, Advertise: "http://10.1.2.3:18081", Secret: secretOne, HTTPClient: &http.Client{}}
	if _, err := NewService(Options{Store: ms, Relay: &good}); err != nil {
		t.Fatalf("good options: %v", err)
	}
	for name, mut := range map[string]func(o *RelayOptions){
		"short secret":       func(o *RelayOptions) { o.Secret = []byte("short") },
		"no holders":         func(o *RelayOptions) { o.Holders = nil },
		"no client":          func(o *RelayOptions) { o.HTTPClient = nil },
		"advertise empty":    func(o *RelayOptions) { o.Advertise = "" },
		"advertise path":     func(o *RelayOptions) { o.Advertise = "http://10.1.2.3:18081/x" },
		"advertise scheme":   func(o *RelayOptions) { o.Advertise = "ftp://10.1.2.3:18081" },
		"advertise userinfo": func(o *RelayOptions) { o.Advertise = "http://u:p@10.1.2.3:18081" },
	} {
		o := good
		mut(&o)
		_, err := NewService(Options{Store: ms, Relay: &o})
		if err == nil {
			t.Errorf("%s: accepted", name)
			continue
		}
		if strings.Contains(err.Error(), string(secretOne)) {
			t.Errorf("%s: error echoes the secret", name)
		}
	}
}
