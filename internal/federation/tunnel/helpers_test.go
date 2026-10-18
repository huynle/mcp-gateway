package tunnel

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
)

// memStore is an in-memory Store for unit tests (the Postgres-backed one
// is covered by the integration test).
type memStore struct {
	mu      sync.Mutex
	next    int
	tunnels map[string]*store.MCPTunnel
	touches int
	// holders is the HolderStore side (migration 00026).
	holders map[string]store.MCPTunnelHolder
	epochs  int64
}

func newMemStore() *memStore {
	return &memStore{tunnels: map[string]*store.MCPTunnel{}, holders: map[string]store.MCPTunnelHolder{}}
}

func (m *memStore) ClaimHolder(_ context.Context, id, holder string, at time.Time) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tunnels[id]
	if !ok {
		return 0, store.ErrNotFound
	}
	t.LastSeenAt = &at
	m.epochs++
	m.holders[id] = store.MCPTunnelHolder{TunnelID: id, Holder: holder, Epoch: m.epochs, ClaimedAt: at}
	return m.epochs, nil
}

func (m *memStore) ReleaseHolder(_ context.Context, id string, epoch int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if h, ok := m.holders[id]; ok && h.Epoch == epoch {
		delete(m.holders, id)
	}
	return nil
}

func (m *memStore) Holder(_ context.Context, id string) (*store.MCPTunnelHolder, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.holders[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	t := m.tunnels[id]
	h.LastSeenAt, h.Revoked = t.LastSeenAt, t.RevokedAt != nil
	return &h, nil
}

// holder returns the tunnel's holder row, if any.
func (m *memStore) holder(id string) (store.MCPTunnelHolder, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	h, ok := m.holders[id]
	return h, ok
}

// setLastSeen moves a tunnel's last_seen_at (staleness tests).
func (m *memStore) setLastSeen(id string, at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tunnels[id].LastSeenAt = &at
}

// setHolder overwrites a tunnel's holder row (tests).
func (m *memStore) setHolder(id, holder string, epoch int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.holders[id] = store.MCPTunnelHolder{TunnelID: id, Holder: holder, Epoch: epoch, ClaimedAt: time.Now()}
}

func (m *memStore) CreateTunnel(_ context.Context, owner, name string, hash []byte) (*store.MCPTunnel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.next++
	t := &store.MCPTunnel{
		ID: fmt.Sprintf("00000000-0000-4000-8000-%012d", m.next), OwnerUserID: owner, Name: name,
		TokenHash: append([]byte(nil), hash...), CreatedAt: time.Now(),
	}
	m.tunnels[t.ID] = t
	cp := *t
	return &cp, nil
}

func (m *memStore) RevokeTunnel(_ context.Context, owner, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tunnels[id]
	if !ok || t.OwnerUserID != owner || t.RevokedAt != nil {
		return store.ErrNotFound
	}
	t.RevokedAt = &at
	return nil
}

func (m *memStore) TunnelByTokenHash(_ context.Context, hash []byte) (*store.MCPTunnel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, t := range m.tunnels {
		if bytes.Equal(t.TokenHash, hash) {
			cp := *t
			return &cp, nil
		}
	}
	return nil, store.ErrNotFound
}

func (m *memStore) Tunnel(_ context.Context, id string) (*store.MCPTunnel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tunnels[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *t
	return &cp, nil
}

func (m *memStore) TouchTunnel(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tunnels[id]
	if !ok {
		return store.ErrNotFound
	}
	t.LastSeenAt = &at
	m.touches++
	return nil
}

func (m *memStore) touchCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.touches
}

const (
	ownerA = "11111111-1111-4111-8111-111111111111"
	ownerB = "22222222-2222-4222-8222-222222222222"
)
