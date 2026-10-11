package tunnel

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// AgentOptions configure the user-side tunnel client.
type AgentOptions struct {
	// GatewayURL is the gateway's base URL (https://gateway.example.com);
	// the agent connects to GatewayURL + ConnectPath.
	GatewayURL string
	// Token is the tunnel token (mgt_...). It is sent only in the
	// Authorization header of the upgrade request and never logged.
	Token string
	// Handler serves the requests arriving through the tunnel: the local
	// stdio bridge or a reverse proxy to a private HTTP server.
	Handler http.Handler
	// HTTPClient performs the WebSocket handshake. Default: the websocket
	// library's default client.
	HTTPClient *http.Client
	// Log receives connection events. Default: discard.
	Log *slog.Logger
	// MinBackoff and MaxBackoff bound the reconnect delay (exponential with
	// jitter). Defaults 1s and 1m.
	MinBackoff, MaxBackoff time.Duration
	// MaxStreams bounds concurrent requests handled locally (default 64);
	// excess requests are answered 503.
	MaxStreams int
	// OnStatus, when set, is called on every state change (for a status
	// line).
	OnStatus func(Status)
}

// State is the agent's connection state.
type State string

// States.
const (
	StateConnecting   State = "connecting"
	StateConnected    State = "connected"
	StateDisconnected State = "disconnected"
)

// Status is reported to AgentOptions.OnStatus.
type Status struct {
	State   State
	Err     error         // why the connection ended (disconnected)
	RetryIn time.Duration // delay before the next attempt (disconnected)
}

// Agent is the tunnel client: it keeps an outbound WebSocket to the
// gateway open and replays the requests it receives against Handler.
type Agent struct {
	o       AgentOptions
	connect string
}

// NewAgent validates o and builds an Agent.
func NewAgent(o AgentOptions) (*Agent, error) {
	if o.Handler == nil {
		return nil, errors.New("tunnel: AgentOptions.Handler is required")
	}
	if ParseToken(o.Token) != nil {
		return nil, errors.New("tunnel: the token is not a tunnel token (mgt_...)")
	}
	u, err := url.Parse(o.GatewayURL)
	if err != nil || u.Host == "" || u.User != nil {
		return nil, errors.New("tunnel: invalid gateway URL")
	}
	switch u.Scheme {
	case "https", "wss", "http", "ws":
	default:
		return nil, errors.New("tunnel: gateway URL must be https (or http for local testing)")
	}
	if o.Log == nil {
		o.Log = slog.New(slog.DiscardHandler)
	}
	if o.MinBackoff <= 0 {
		o.MinBackoff = time.Second
	}
	if o.MaxBackoff < o.MinBackoff {
		o.MaxBackoff = max(time.Minute, o.MinBackoff)
	}
	if o.MaxStreams <= 0 {
		o.MaxStreams = 64
	}
	u.Path = strings.TrimSuffix(u.Path, "/") + ConnectPath
	u.RawQuery, u.Fragment = "", ""
	return &Agent{o: o, connect: u.String()}, nil
}

// Run connects and serves until ctx is cancelled (returns ctx.Err()) or
// the gateway ends the tunnel for good (ErrRejected, ErrReplaced,
// ErrRevoked). Other failures reconnect with exponential backoff.
func (a *Agent) Run(ctx context.Context) error {
	backoff := a.o.MinBackoff
	for {
		a.status(Status{State: StateConnecting})
		connected, err := a.runOnce(ctx)
		if ctx.Err() != nil {
			a.status(Status{State: StateDisconnected, Err: ctx.Err()})
			return ctx.Err()
		}
		if errors.Is(err, ErrRejected) || errors.Is(err, ErrReplaced) || errors.Is(err, ErrRevoked) {
			a.status(Status{State: StateDisconnected, Err: err})
			return err
		}
		if connected {
			backoff = a.o.MinBackoff
		}
		// Full jitter in [backoff/2, backoff].
		delay := backoff/2 + rand.N(backoff/2+1)
		a.o.Log.Info("tunnel: disconnected, retrying", "error", err, "retry_in", delay.Round(time.Millisecond))
		a.status(Status{State: StateDisconnected, Err: err, RetryIn: delay})
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(delay):
		}
		backoff = min(backoff*2, a.o.MaxBackoff)
	}
}

func (a *Agent) status(s Status) {
	if a.o.OnStatus != nil {
		a.o.OnStatus(s)
	}
}

// runOnce makes one connection and serves it until it ends.
func (a *Agent) runOnce(ctx context.Context) (connected bool, err error) {
	h := http.Header{}
	h.Set("Authorization", "Bearer "+a.o.Token)
	ws, resp, err := websocket.Dial(ctx, a.connect, &websocket.DialOptions{
		HTTPClient: a.o.HTTPClient, HTTPHeader: h, Subprotocols: []string{Subprotocol},
	})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		if resp != nil && resp.StatusCode == http.StatusUnauthorized {
			return false, ErrRejected
		}
		if resp != nil {
			return false, fmt.Errorf("tunnel: gateway answered HTTP %d", resp.StatusCode)
		}
		return false, fmt.Errorf("tunnel: connect: %w", err)
	}
	if ws.Subprotocol() != Subprotocol {
		_ = ws.Close(websocket.StatusProtocolError, "unsupported protocol version")
		return false, errors.New("tunnel: gateway does not speak protocol " + Subprotocol)
	}
	ws.SetReadLimit(agentReadLimit)
	a.o.Log.Info("tunnel: connected", "gateway", hostOf(a.connect))
	a.status(Status{State: StateConnected})
	return true, a.serve(ctx, ws)
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// serve reads gateway frames and runs requests until the connection ends.
func (a *Agent) serve(ctx context.Context, ws *websocket.Conn) error {
	life, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer func() {
		cancel()
		wg.Wait()
		_ = ws.CloseNow()
	}()
	var mu sync.Mutex
	running := map[uint64]context.CancelFunc{}
	sem := make(chan struct{}, a.o.MaxStreams)

	for {
		f, err := readFrame(life, ws)
		if err != nil {
			switch websocket.CloseStatus(err) {
			case closeReplaced:
				return ErrReplaced
			case closeRevoked:
				return ErrRevoked
			}
			if ctx.Err() != nil {
				_ = ws.Close(websocket.StatusGoingAway, "client shutting down")
				return ctx.Err()
			}
			return err
		}
		switch f.Type {
		case frameCancel:
			mu.Lock()
			if c := running[f.ID]; c != nil {
				c()
			}
			mu.Unlock()
		case frameRequest:
			rctx, rcancel := context.WithCancel(life)
			mu.Lock()
			if old := running[f.ID]; old != nil {
				old()
			}
			running[f.ID] = rcancel
			mu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() {
					mu.Lock()
					delete(running, f.ID)
					mu.Unlock()
					rcancel()
				}()
				select {
				case sem <- struct{}{}:
					defer func() { <-sem }()
					a.handle(rctx, life, ws, f)
				default:
					a.reply(life, ws, f.ID, http.StatusServiceUnavailable, "tunnel client busy\n")
				}
			}()
		}
	}
}

// reply sends a complete small response. ctx must be the connection's
// life context: cancelling a write's context closes the whole WebSocket.
func (a *Agent) reply(ctx context.Context, ws *websocket.Conn, id uint64, status int, msg string) {
	h := http.Header{"Content-Type": {"text/plain; charset=utf-8"}}
	_ = writeFrame(ctx, ws, &frame{Type: frameHead, ID: id, Status: status, Header: h})
	_ = writeFrame(ctx, ws, &frame{Type: frameData, ID: id, Data: []byte(msg)})
	_ = writeFrame(ctx, ws, &frame{Type: frameEnd, ID: id})
}

// handle replays one request against the local handler. ctx is the
// request's context (cancelled by a cancel frame); frames are written with
// life, the connection's context.
func (a *Agent) handle(ctx, life context.Context, ws *websocket.Conn, f *frame) {
	if !strings.HasPrefix(f.Path, "/") || f.Method == "" {
		a.reply(life, ws, f.ID, http.StatusBadRequest, "bad tunnel request\n")
		return
	}
	u, err := url.ParseRequestURI(f.Path)
	if err != nil {
		a.reply(life, ws, f.ID, http.StatusBadRequest, "bad tunnel request\n")
		return
	}
	req, err := http.NewRequestWithContext(ctx, f.Method, "http://tunnel"+f.Path, bytes.NewReader(f.Data))
	if err != nil {
		a.reply(life, ws, f.ID, http.StatusBadRequest, "bad tunnel request\n")
		return
	}
	req.URL = u
	req.RequestURI = f.Path
	req.Host = "tunnel"
	req.RemoteAddr = "tunnel"
	req.Header = cleanHeader(f.Header)
	req.ContentLength = int64(len(f.Data))

	w := &responseWriter{req: ctx, life: life, ws: ws, id: f.ID, header: http.Header{}}
	defer func() {
		if p := recover(); p != nil {
			a.o.Log.Error("tunnel: local handler panicked", "panic", fmt.Sprint(p))
			w.abort("handler_panic")
			return
		}
		w.finish()
	}()
	a.o.Handler.ServeHTTP(w, req)
}

// responseWriter streams a local response back as head, data*, end.
type responseWriter struct {
	req      context.Context // the request; once cancelled nothing more is sent
	life     context.Context // the connection; used for writes
	ws       *websocket.Conn
	id       uint64
	header   http.Header
	status   int
	headSent bool
	buf      bytes.Buffer
	err      error
}

func (w *responseWriter) Header() http.Header { return w.header }

func (w *responseWriter) WriteHeader(code int) {
	if w.status != 0 || code < 200 { // informational responses are not relayed
		return
	}
	w.status = code
}

func (w *responseWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	w.buf.Write(p)
	if w.buf.Len() >= maxChunk {
		w.flushData()
	}
	return len(p), w.err
}

// Flush sends the head and any buffered data now (SSE).
func (w *responseWriter) Flush() {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	w.flushData()
}

func (w *responseWriter) send(f *frame) {
	if w.err == nil && w.req.Err() != nil {
		w.err = w.req.Err() // the gateway abandoned the stream
	}
	if w.err != nil {
		return
	}
	if err := writeFrame(w.life, w.ws, f); err != nil {
		w.err = err
	}
}

func (w *responseWriter) sendHead() {
	if w.headSent {
		return
	}
	w.headSent = true
	w.send(&frame{Type: frameHead, ID: w.id, Status: w.status, Header: cleanHeader(w.header)})
}

func (w *responseWriter) flushData() {
	w.sendHead()
	for w.buf.Len() > 0 && w.err == nil {
		w.send(&frame{Type: frameData, ID: w.id, Data: w.buf.Next(maxChunk)})
	}
}

func (w *responseWriter) finish() {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	w.flushData()
	w.send(&frame{Type: frameEnd, ID: w.id})
}

func (w *responseWriter) abort(reason string) {
	if w.status == 0 {
		w.status = http.StatusBadGateway
	}
	w.sendHead()
	w.send(&frame{Type: frameEnd, ID: w.id, Error: reason})
}
