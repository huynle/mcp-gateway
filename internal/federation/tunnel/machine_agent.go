package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// MachineAgentOptions configure the machine agent: the client side of a
// machine connection (`mcp-gateway up`), one WebSocket carrying every
// tunnel of an enrolled machine.
type MachineAgentOptions struct {
	// GatewayURL is the gateway's base URL; the agent connects to
	// GatewayURL + MachineConnectPath.
	GatewayURL string
	// Token returns a current machine access token (mgm_...) and is called
	// before every connection attempt; it is sent only in the
	// Authorization header and never logged. Return an error wrapping
	// ErrRejected or ErrRevoked to stop the agent for good (the machine
	// was revoked); other errors are retried with backoff.
	Token func(ctx context.Context) (string, error)
	// Targets maps a tunnel id to the local handler serving it
	// (NewHTTPForwarder, or a StdioProcess's Handler). A request for a
	// tunnel without a target is answered 502. SetTargets replaces them.
	Targets map[string]http.Handler
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
	// OnStatus, when set, is called on every state change.
	OnStatus func(Status)
	// OnTunnels, when set, receives the gateway's list of the machine's
	// tunnel ids on connect and whenever it changes.
	OnTunnels func(ids []string)
}

// MachineAgent keeps a machine connection open and replays the requests it
// receives against the target of each request's tunnel.
type MachineAgent struct {
	o       MachineAgentOptions
	connect string

	mu      sync.RWMutex
	targets map[string]http.Handler
}

// NewMachineAgent validates o and builds a MachineAgent.
func NewMachineAgent(o MachineAgentOptions) (*MachineAgent, error) {
	if o.Token == nil {
		return nil, errors.New("tunnel: MachineAgentOptions.Token is required")
	}
	connect, err := connectURL(o.GatewayURL, MachineConnectPath)
	if err != nil {
		return nil, err
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
	a := &MachineAgent{o: o, connect: connect}
	a.SetTargets(o.Targets)
	return a, nil
}

// SetTargets replaces the tunnel targets; requests already running keep
// their handler.
func (a *MachineAgent) SetTargets(targets map[string]http.Handler) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.targets = maps.Clone(targets)
}

func (a *MachineAgent) target(id string) http.Handler {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.targets[id]
}

// Run connects and serves until ctx is cancelled (returns ctx.Err()) or
// the gateway ends the machine connection for good: ErrRevoked (refused
// with 403 or closed with 4003) or ErrReplaced (4001, another connection
// of the same machine). A rejected token (401) is retried with a new one.
func (a *MachineAgent) Run(ctx context.Context) error {
	return reconnectLoop(ctx, reconnect{
		once: a.runOnce, status: a.status, log: a.o.Log, min: a.o.MinBackoff, max: a.o.MaxBackoff,
	})
}

func (a *MachineAgent) status(s Status) {
	if a.o.OnStatus != nil {
		a.o.OnStatus(s)
	}
}

func (a *MachineAgent) runOnce(ctx context.Context) (bool, error) {
	token, err := a.o.Token(ctx)
	if err != nil {
		if final(err) {
			return false, err
		}
		return false, fmt.Errorf("tunnel: machine token: %w", err)
	}
	h := http.Header{}
	h.Set("Authorization", "Bearer "+token)
	ws, resp, err := websocket.Dial(ctx, a.connect, &websocket.DialOptions{
		HTTPClient: a.o.HTTPClient, HTTPHeader: h, Subprotocols: []string{MachineSubprotocol},
	})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		switch {
		case resp != nil && resp.StatusCode == http.StatusForbidden:
			return false, ErrRevoked
		case resp != nil && resp.StatusCode == http.StatusUnauthorized:
			return false, errors.New("tunnel: the gateway rejected the machine token")
		case resp != nil:
			return false, fmt.Errorf("tunnel: gateway answered HTTP %d", resp.StatusCode)
		}
		return false, fmt.Errorf("tunnel: connect: %w", err)
	}
	if ws.Subprotocol() != MachineSubprotocol {
		_ = ws.Close(websocket.StatusProtocolError, "unsupported protocol version")
		return false, errors.New("tunnel: gateway does not speak protocol " + MachineSubprotocol)
	}
	ws.SetReadLimit(agentReadLimit)
	a.o.Log.Info("tunnel: machine connected", "gateway", hostOf(a.connect))
	a.status(Status{State: StateConnected})
	return true, serveFrames(ctx, ws, frameServer{
		resolve:   func(f *frame) http.Handler { return a.target(f.Tunnel) },
		onTunnels: a.o.OnTunnels,
		log:       a.o.Log, maxStreams: a.o.MaxStreams,
	})
}
