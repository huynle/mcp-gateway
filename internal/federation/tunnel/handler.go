package tunnel

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/coder/websocket"

	"github.com/huynle/mcp-gateway/internal/store"
)

// Handler returns the /tunnel/connect endpoint (mount it at ConnectPath,
// outside the gateway's user authentication: the tunnel token is the
// credential). It authenticates "Authorization: Bearer <tunnel token>"
// (401 otherwise), upgrades to a WebSocket with the v1 subprotocol,
// registers the connection as the tunnel's live one (replacing any
// previous connection), touches last_seen_at, and serves until the
// connection ends. Every HeartbeatInterval it pings the client,
// re-checks that the tunnel is not revoked and touches last_seen_at.
func (s *Service) Handler() http.Handler {
	return http.HandlerFunc(s.serveConnect)
}

func (s *Service) serveConnect(w http.ResponseWriter, r *http.Request) {
	raw, ok := bearerToken(r)
	if !ok {
		s.refuse(w, "missing_token")
		return
	}
	t, err := s.Authenticate(r.Context(), raw)
	if errors.Is(err, ErrUnauthorized) {
		s.refuse(w, "invalid_token")
		return
	}
	if err != nil {
		s.log.Error("tunnel: connect: authenticate failed", "error", err)
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{Subprotocol}})
	if err != nil {
		s.log.Info("tunnel: connect: upgrade failed", "tunnel_id", t.ID)
		return // Accept has written the response
	}
	if ws.Subprotocol() != Subprotocol {
		_ = ws.Close(websocket.StatusPolicyViolation, "unsupported protocol version")
		return
	}
	ws.SetReadLimit(gatewayReadLimit)

	c := newConn(t.ID, ws, s.limits)
	s.touch(t.ID)
	s.reg.put(t.ID, c)
	s.log.Info("tunnel: connected", "tunnel_id", t.ID, "owner_user_id", t.OwnerUserID)

	go s.heartbeat(c)
	reason := s.readLoop(c)
	s.reg.remove(t.ID, c)
	c.close(websocket.StatusNormalClosure, "")
	s.log.Info("tunnel: disconnected", "tunnel_id", t.ID, "reason", reason)
}

// readLoop dispatches client frames until the connection fails or closes
// and returns a short reason.
func (s *Service) readLoop(c *conn) string {
	for {
		f, err := readFrame(c.life, c.ws)
		if err != nil {
			switch {
			case c.isClosed():
				return "closed_by_gateway"
			case errors.Is(err, errBadFrame):
				_ = c.ws.Close(websocket.StatusUnsupportedData, "malformed frame")
				return "malformed_frame"
			case websocket.CloseStatus(err) != -1:
				return "closed_by_client"
			default:
				return "connection_lost"
			}
		}
		c.dispatch(f)
	}
}

// heartbeat pings the client, drops the connection when the tunnel was
// revoked (possibly through another replica) and touches last_seen_at.
func (s *Service) heartbeat(c *conn) {
	tick := time.NewTicker(s.limits.HeartbeatInterval)
	defer tick.Stop()
	for {
		select {
		case <-c.life.Done():
			return
		case <-tick.C:
		}
		ctx, cancel := context.WithTimeout(c.life, s.limits.HeartbeatInterval)
		err := c.ws.Ping(ctx)
		if err != nil {
			cancel()
			if c.life.Err() == nil {
				s.log.Info("tunnel: ping failed", "tunnel_id", c.tunnelID)
				s.reg.remove(c.tunnelID, c)
				c.close(websocket.StatusGoingAway, "ping timeout")
			}
			return
		}
		t, err := s.store.Tunnel(ctx, c.tunnelID)
		cancel()
		switch {
		case errors.Is(err, store.ErrNotFound) || (err == nil && t.RevokedAt != nil):
			s.log.Info("tunnel: revoked, disconnecting", "tunnel_id", c.tunnelID)
			s.reg.remove(c.tunnelID, c)
			c.close(closeRevoked, "revoked")
			return
		case err != nil:
			s.log.Warn("tunnel: heartbeat lookup failed", "tunnel_id", c.tunnelID, "error", err)
		default:
			s.touch(c.tunnelID)
		}
	}
}

func (s *Service) touch(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.store.TouchTunnel(ctx, id, s.now()); err != nil {
		s.log.Warn("tunnel: touch failed", "tunnel_id", id, "error", err)
	}
}

// refuse answers 401 without saying why (the reason is logged, the token
// never is).
func (s *Service) refuse(w http.ResponseWriter, reason string) {
	s.log.Info("tunnel: connect refused", "reason", reason)
	w.Header().Set("WWW-Authenticate", `Bearer realm="mcp-gateway-tunnel"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}

func bearerToken(r *http.Request) (string, bool) {
	scheme, tok, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || tok == "" {
		return "", false
	}
	return tok, true
}
