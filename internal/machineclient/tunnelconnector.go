package machineclient

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"

	gwtunnel "github.com/huynle/mcp-gateway/internal/federation/tunnel"
)

// tunnelConnector is the real Connector: one machine
// connection (tunnel.MachineAgent) serving every target by tunnel id. It
// returns on the first disconnect so `up` owns reconnecting, backoff and
// the status lines; revocation and replacement map to machineclient's
// errors.
type tunnelConnector struct{ log *slog.Logger }

// NewTunnelConnector builds the real Connector; log receives connection
// events (nil discards them).
func NewTunnelConnector(log *slog.Logger) Connector { return tunnelConnector{log: log} }

func (c tunnelConnector) Run(ctx context.Context, gateway string, token func(ctx context.Context) (string, error),
	targets map[string]Target, onConnected func(),
) error {
	handlers := make(map[string]http.Handler, len(targets))
	for id, t := range targets {
		if t.Handler != nil {
			handlers[id] = t.Handler
		}
	}
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	var (
		mu   sync.Mutex
		lost error
	)
	agent, err := gwtunnel.NewMachineAgent(gwtunnel.MachineAgentOptions{
		GatewayURL: gateway,
		Token:      token,
		Targets:    handlers,
		Log:        c.log,
		OnStatus: func(s gwtunnel.Status) {
			mu.Lock()
			defer mu.Unlock()
			switch s.State {
			case gwtunnel.StateConnected:
				if onConnected != nil {
					onConnected()
				}
			case gwtunnel.StateDisconnected:
				// Hand the disconnect to up (it reconnects with its own
				// backoff); before the first connection the agent's own
				// retry error is reported the same way.
				lost = s.Err
				if lost == nil {
					lost = errors.New("connection closed")
				}
				cancel()
			}
		},
	})
	if err != nil {
		return err
	}
	runErr := agent.Run(runCtx)
	switch {
	case errors.Is(runErr, gwtunnel.ErrRevoked):
		return ErrRevoked
	case errors.Is(runErr, gwtunnel.ErrReplaced):
		return ErrReplaced
	case ctx.Err() != nil:
		return ctx.Err()
	}
	mu.Lock()
	defer mu.Unlock()
	if lost != nil {
		switch {
		case errors.Is(lost, gwtunnel.ErrRevoked):
			return ErrRevoked
		case errors.Is(lost, gwtunnel.ErrReplaced):
			return ErrReplaced
		}
		return lost
	}
	return runErr
}
