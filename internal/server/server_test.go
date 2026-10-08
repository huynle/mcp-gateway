package server_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/server"
)

// slowHandler blocks until released or until the request context is
// cancelled, and records which of the two happened.
type slowHandler struct {
	entered   chan struct{}
	release   chan struct{}
	cancelled atomic.Bool
}

func newSlowHandler() *slowHandler {
	return &slowHandler{entered: make(chan struct{}, 8), release: make(chan struct{})}
}

// waitEntered blocks until a request reaches the handler or fails the test.
func (h *slowHandler) waitEntered(t *testing.T) {
	t.Helper()
	select {
	case <-h.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no request reached the handler within 5s")
	}
}

func (h *slowHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.entered <- struct{}{}
	select {
	case <-h.release:
		_, _ = io.WriteString(w, "done")
	case <-r.Context().Done():
		h.cancelled.Store(true)
	}
}

type started struct {
	addr   string
	cancel context.CancelFunc
	errc   chan error
}

// listen opens a loopback listener on a free port and closes it on cleanup.
func listen(t *testing.T) net.Listener {
	t.Helper()
	var lc net.ListenConfig
	l, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return l
}

func start(t *testing.T, h http.Handler, drain time.Duration) started {
	t.Helper()
	l := listen(t)
	ctx, cancel := context.WithCancel(t.Context())
	srv := server.New(h, drain, slog.New(slog.DiscardHandler))
	errc := make(chan error, 1)
	go func() { errc <- srv.Serve(ctx, l) }()
	t.Cleanup(cancel)
	return started{addr: l.Addr().String(), cancel: cancel, errc: errc}
}

func get(addr string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+addr+"/", nil)
	if err != nil {
		return nil, err
	}
	// A fresh transport per call so keep-alive pools do not blur "new connection".
	c := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 5 * time.Second}
	return c.Do(req)
}

// waitRefused polls until a new TCP connection to addr is refused.
func waitRefused(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		d := net.Dialer{Timeout: 100 * time.Millisecond}
		c, err := d.DialContext(t.Context(), "tcp", addr)
		if err != nil {
			return
		}
		_ = c.Close()
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("server kept accepting new connections after shutdown began")
}

func waitErr(t *testing.T, errc chan error, within time.Duration) error {
	t.Helper()
	select {
	case err := <-errc:
		return err
	case <-time.After(within):
		t.Fatalf("Serve did not return within %v", within)
		return nil
	}
}

func TestServesRequestsUntilCancelled(t *testing.T) {
	s := start(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "hello")
	}), time.Second)
	resp, err := get(s.addr)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "hello" {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
	s.cancel()
	if err := waitErr(t, s.errc, 2*time.Second); err != nil {
		t.Fatalf("clean shutdown should return nil, got %v", err)
	}
}

func TestShutdownRefusesNewConnectionsAndDrainsInFlight(t *testing.T) {
	h := newSlowHandler()
	s := start(t, h, 5*time.Second)

	type result struct {
		body string
		err  error
	}
	resc := make(chan result, 1)
	go func() {
		resp, err := get(s.addr)
		if err != nil {
			resc <- result{err: err}
			return
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		resc <- result{body: string(b)}
	}()
	h.waitEntered(t) // the request is in flight

	s.cancel()
	waitRefused(t, s.addr)

	// Still draining: Serve must not have returned while a request is in flight.
	select {
	case err := <-s.errc:
		t.Fatalf("Serve returned (%v) while a request was still in flight", err)
	case <-time.After(100 * time.Millisecond):
	}

	close(h.release)
	r := <-resc
	if r.err != nil || r.body != "done" {
		t.Fatalf("in-flight request should complete during drain, got body=%q err=%v", r.body, r.err)
	}
	if err := waitErr(t, s.errc, 2*time.Second); err != nil {
		t.Fatalf("drained shutdown should return nil, got %v", err)
	}
	if h.cancelled.Load() {
		t.Fatal("handler context must not be cancelled when the request finishes within the drain period")
	}
}

func TestShutdownCutsOffRequestsExceedingDrain(t *testing.T) {
	const drain = 150 * time.Millisecond
	h := newSlowHandler() // never released: the request outlives the drain period
	s := start(t, h, drain)

	errc := make(chan error, 1)
	go func() {
		resp, err := get(s.addr)
		if err == nil {
			_, err = io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if err == nil {
				err = errors.New("unexpected complete response")
			}
		}
		errc <- err
	}()
	h.waitEntered(t)

	began := time.Now()
	s.cancel()

	err := waitErr(t, s.errc, drain+2*time.Second)
	if !errors.Is(err, server.ErrDrainTimeout) {
		t.Fatalf("Serve should report the drain timeout, got %v", err)
	}
	if took := time.Since(began); took < drain || took > drain+time.Second {
		t.Fatalf("Serve returned after %v, want about the %v drain period", took, drain)
	}
	if cerr := <-errc; cerr == nil {
		t.Fatal("client should see its request cut off")
	}
	deadline := time.Now().Add(time.Second)
	for !h.cancelled.Load() && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if !h.cancelled.Load() {
		t.Fatal("handler context should be cancelled once the drain period elapses")
	}
}

func TestListenAndServeReturnsListenErrors(t *testing.T) {
	l := listen(t)
	srv := server.New(http.NotFoundHandler(), time.Second, slog.New(slog.DiscardHandler))
	if err := srv.ListenAndServe(t.Context(), l.Addr().String()); err == nil {
		t.Fatal("expected an error binding an address that is already in use")
	}
}
