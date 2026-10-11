package tunnel

import "sync"

// Close reasons sent to the tunnel client.
const (
	closeRevoked = "revoked"
)

// registry holds the live connection of each tunnel on this replica.
type registry struct {
	mu    sync.Mutex
	conns map[string]*conn
}

type conn struct{}

func newRegistry() *registry { return &registry{conns: map[string]*conn{}} }

// drop closes and forgets tunnelID's live connection, if any.
func (r *registry) drop(tunnelID, _ string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.conns, tunnelID)
}
