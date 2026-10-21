package tunnel

import (
	"context"
	"net/http"
	"slices"
	"time"

	"github.com/coder/websocket"
)

// MachineStore is what machine connections need from persistence (Brain
// decision ldjix4y1; migration 00030). NewMachineStore adapts
// *store.Store (WithJobs: no user is known on the connection path).
type MachineStore interface {
	// MachineTunnels returns the machine's live (not revoked) tunnel ids
	// and whether the machine may stay connected: not revoked and its
	// owner active. An unknown machine is (nil, false, nil).
	MachineTunnels(ctx context.Context, machineID string) (ids []string, live bool, err error)
	// TouchMachine records the machine's last_seen_at.
	TouchMachine(ctx context.Context, machineID string, at time.Time) error
}

// ServeMachine serves one machine connection (GET MachineConnectPath,
// subprotocol MachineSubprotocol). The caller has authenticated the
// machine token (internal/machines) and passes the machine id. The
// connection becomes the live connection of every tunnel linked to the
// machine (replacing older ones, also a previous connection of the same
// machine, which closes with 4001) and follows the machine's tunnel set:
// tunnels added or revoked later are attached or detached without a
// reconnect (SyncMachine, and every MachineSyncInterval). It ends with
// 4003 when the machine is revoked or its owner is no longer active.
func (s *Service) ServeMachine(w http.ResponseWriter, r *http.Request, machineID string) {
	if s.machineStore == nil {
		http.Error(w, "machine connections are not enabled", http.StatusServiceUnavailable)
		return
	}
	ids, live, err := s.machineStore.MachineTunnels(r.Context(), machineID)
	if err != nil {
		s.log.Error("tunnel: machine connect: lookup failed", "machine_id", machineID, "error", err)
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	if !live {
		s.log.Info("tunnel: machine connect refused", "machine_id", machineID, "reason", "revoked")
		http.Error(w, "machine revoked", http.StatusForbidden)
		return
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{MachineSubprotocol}})
	if err != nil {
		s.log.Info("tunnel: machine connect: upgrade failed", "machine_id", machineID)
		return // Accept has written the response
	}
	if ws.Subprotocol() != MachineSubprotocol {
		_ = ws.Close(websocket.StatusPolicyViolation, "unsupported protocol version")
		return
	}
	ws.SetReadLimit(gatewayReadLimit)

	l := newLink(ws, machineID)
	s.machinesMu.Lock()
	old := s.machines[machineID]
	s.machines[machineID] = l
	s.machinesMu.Unlock()
	s.touchMachine(machineID)
	// Serve the tunnels on the new connection before closing the one it
	// replaces: registering each view replaces the old one, so a request
	// during the handover never finds the tunnel offline.
	s.applyTunnels(l, ids, true)
	if old != nil {
		old.close(closeReplaced, "replaced")
	}
	s.log.Info("tunnel: machine connected", "machine_id", machineID, "tunnels", len(ids))

	go s.machineHeartbeat(l)
	reason := s.readLoop(l)
	s.machinesMu.Lock()
	if s.machines[machineID] == l {
		delete(s.machines, machineID)
	}
	s.machinesMu.Unlock()
	views := l.viewList()
	l.close(websocket.StatusNormalClosure, "")
	for _, c := range views {
		s.reg.remove(c.tunnelID, c)
		s.releaseHolder(c)
	}
	s.log.Info("tunnel: machine disconnected", "machine_id", machineID, "reason", reason)
}

// SyncMachine re-reads the machine's tunnel set now (after a server was
// added through the machine API on this replica). Connections on other
// replicas follow within MachineSyncInterval.
func (s *Service) SyncMachine(machineID string) {
	l := s.machineLink(machineID)
	if l == nil {
		return
	}
	s.syncMachine(l)
}

// DropMachine closes the machine's connection on this replica as revoked
// (4003). Other replicas close theirs within MachineSyncInterval.
func (s *Service) DropMachine(machineID string) {
	l := s.machineLink(machineID)
	if l == nil {
		return
	}
	s.dropLink(l, closeRevoked, "revoked")
}

// MachineConnected reports whether the machine has a live connection on
// this replica.
func (s *Service) MachineConnected(machineID string) bool { return s.machineLink(machineID) != nil }

func (s *Service) machineLink(machineID string) *link {
	s.machinesMu.Lock()
	defer s.machinesMu.Unlock()
	return s.machines[machineID]
}

// dropLink forgets l as the machine's connection and every tunnel view of
// it, then closes it, so MachineConnected and Online are false as soon as
// it returns (the read loop's own cleanup is then a no-op).
func (s *Service) dropLink(l *link, code websocket.StatusCode, reason string) {
	s.machinesMu.Lock()
	if s.machines[l.machine] == l {
		delete(s.machines, l.machine)
	}
	s.machinesMu.Unlock()
	views := l.viewList()
	for _, c := range views {
		s.reg.remove(c.tunnelID, c)
	}
	l.close(code, reason)
}

// syncMachine re-reads the machine and applies its tunnel set; a revoked
// machine (or inactive owner) is dropped.
func (s *Service) syncMachine(l *link) {
	ctx, cancel := context.WithTimeout(l.life, 5*time.Second)
	ids, live, err := s.machineStore.MachineTunnels(ctx, l.machine)
	cancel()
	switch {
	case err != nil:
		if l.life.Err() == nil {
			s.log.Warn("tunnel: machine sync failed", "machine_id", l.machine, "error", err)
		}
	case !live:
		s.log.Info("tunnel: machine revoked, disconnecting", "machine_id", l.machine)
		s.dropLink(l, closeRevoked, "revoked")
	default:
		s.applyTunnels(l, ids, false)
	}
}

// applyTunnels attaches the tunnels in ids that l does not serve yet and
// detaches those no longer listed, then tells the client the new set
// (always when initial).
func (s *Service) applyTunnels(l *link, ids []string, initial bool) {
	l.syncMu.Lock()
	defer l.syncMu.Unlock()
	changed := initial
	for _, c := range l.viewList() {
		if !slices.Contains(ids, c.tunnelID) {
			s.reg.remove(c.tunnelID, c)
			s.releaseHolder(c)
			c.detach()
			changed = true
		}
	}
	for _, id := range ids {
		c := l.attach(id, s.limits)
		if c == nil {
			continue // already served, or the link closed
		}
		s.reg.put(id, c)
		s.claimHolder(c)
		s.touch(id)
		changed = true
	}
	if changed && !l.isClosed() {
		list := append([]string{}, ids...)
		slices.Sort(list)
		if err := l.send(&frame{Type: frameTunnels, IDs: list}); err != nil {
			s.log.Debug("tunnel: machine tunnel list not sent", "machine_id", l.machine)
		}
	}
}

// machineHeartbeat syncs the machine every MachineSyncInterval and, every
// HeartbeatInterval, pings the client, touches the machine and its
// tunnels and re-checks the relay holders.
func (s *Service) machineHeartbeat(l *link) {
	syncTick := time.NewTicker(s.limits.MachineSyncInterval)
	defer syncTick.Stop()
	beat := time.NewTicker(s.limits.HeartbeatInterval)
	defer beat.Stop()
	for {
		select {
		case <-l.life.Done():
			return
		case <-syncTick.C:
			s.syncMachine(l)
		case <-beat.C:
			ctx, cancel := context.WithTimeout(l.life, s.limits.HeartbeatInterval)
			err := l.ws.Ping(ctx)
			cancel()
			if err != nil {
				if l.life.Err() == nil {
					s.log.Info("tunnel: machine ping failed", "machine_id", l.machine)
					s.dropLink(l, websocket.StatusGoingAway, "ping timeout")
				}
				return
			}
			s.touchMachine(l.machine)
			for _, c := range l.viewList() {
				s.touch(c.tunnelID)
				if !s.checkHolder(c) {
					// A newer connection of the machine holds a tunnel on
					// another replica: this whole connection is stale.
					s.dropLink(l, closeReplaced, "replaced")
					return
				}
			}
		}
	}
}

func (s *Service) touchMachine(id string) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.machineStore.TouchMachine(ctx, id, s.now()); err != nil {
		s.log.Warn("tunnel: machine touch failed", "machine_id", id, "error", err)
	}
}
