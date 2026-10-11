package auth

import (
	"context"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/huynle/mcp-gateway/internal/store"
)

// memStore is an in-memory Store with the isolation rules of schema 14
// that matter here: AsUser sees a server only when the user owns it or it
// is published to them, writes owner-only rows (shared secret, OAuth
// client) only as the owner, and sees only its own connections; Bypass
// sees everything. One mutex is held for a whole transaction, so
// transactions are serialised (like the row lock the production store
// takes for refreshes).
type memStore struct {
	mu      sync.Mutex
	servers map[string]*store.MCPServer
	viewers map[string][]string // server ID -> users it is published to
	shared  map[string]*store.MCPServerSharedSecret
	clients map[string]*store.MCPOAuthClient
	conns   map[[2]string]*store.MCPUserConnection
	locks   int // LockUserConnection calls
}

func newMemStore() *memStore {
	return &memStore{
		servers: map[string]*store.MCPServer{}, viewers: map[string][]string{},
		shared: map[string]*store.MCPServerSharedSecret{}, clients: map[string]*store.MCPOAuthClient{},
		conns: map[[2]string]*store.MCPUserConnection{},
	}
}

func (m *memStore) addServer(s store.MCPServer, viewers ...string) *store.MCPServer {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := s
	m.servers[s.ID] = &cp
	m.viewers[s.ID] = viewers
	return &cp
}

func (m *memStore) conn(serverID, userID string) *store.MCPUserConnection {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.conns[[2]string{serverID, userID}]
	if c == nil {
		return nil
	}
	cp := *c
	return &cp
}

func (m *memStore) AsUser(ctx context.Context, userID string, fn func(Tx) error) error {
	if userID == "" {
		return errors.New("memstore: empty user")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return fn(&memTx{m: m, user: userID})
}

func (m *memStore) Bypass(ctx context.Context, fn func(Tx) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return fn(&memTx{m: m})
}

type memTx struct {
	m    *memStore
	user string // "" = bypass
}

func (t *memTx) visible(id string) (*store.MCPServer, bool) {
	s, ok := t.m.servers[id]
	if !ok {
		return nil, false
	}
	if t.user == "" || s.OwnerUserID == t.user || slices.Contains(t.m.viewers[id], t.user) {
		return s, true
	}
	return nil, false
}

func (t *memTx) owner(id string) error {
	s, ok := t.visible(id)
	if !ok {
		return store.ErrNotFound
	}
	if t.user != "" && s.OwnerUserID != t.user {
		return errors.New("memstore: row-level security violation")
	}
	return nil
}

func (t *memTx) GetServer(_ context.Context, id string) (*store.MCPServer, error) {
	s, ok := t.visible(id)
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *s
	return &cp, nil
}

func (t *memTx) GetOAuthClient(_ context.Context, serverID string) (*store.MCPOAuthClient, error) {
	if err := t.owner(serverID); err != nil {
		return nil, store.ErrNotFound
	}
	c, ok := t.m.clients[serverID]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *c
	return &cp, nil
}

func (t *memTx) UpsertOAuthClient(_ context.Context, c *store.MCPOAuthClient) error {
	if err := t.owner(c.ServerID); err != nil {
		return err
	}
	cp := *c
	cp.OwnerUserID = t.m.servers[c.ServerID].OwnerUserID
	cp.RegisteredAt = time.Now()
	t.m.clients[c.ServerID] = &cp
	return nil
}

func (t *memTx) GetSharedSecret(_ context.Context, serverID string) (*store.MCPServerSharedSecret, error) {
	if err := t.owner(serverID); err != nil {
		return nil, store.ErrNotFound
	}
	s, ok := t.m.shared[serverID]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *s
	return &cp, nil
}

func (t *memTx) SetSharedSecret(_ context.Context, s *store.MCPServerSharedSecret) error {
	if err := t.owner(s.ServerID); err != nil {
		return err
	}
	cp := *s
	cp.OwnerUserID = t.m.servers[s.ServerID].OwnerUserID
	t.m.shared[s.ServerID] = &cp
	return nil
}

func (t *memTx) getConn(serverID, userID string) (*store.MCPUserConnection, error) {
	if t.user != "" && t.user != userID {
		return nil, store.ErrNotFound
	}
	c, ok := t.m.conns[[2]string{serverID, userID}]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *c
	return &cp, nil
}

func (t *memTx) GetUserConnection(_ context.Context, serverID, userID string) (*store.MCPUserConnection, error) {
	return t.getConn(serverID, userID)
}

func (t *memTx) LockUserConnection(_ context.Context, serverID, userID string) (*store.MCPUserConnection, error) {
	t.m.locks++
	return t.getConn(serverID, userID)
}

func (t *memTx) UpsertUserConnection(_ context.Context, c *store.MCPUserConnection) error {
	if t.user != "" {
		if t.user != c.UserID {
			return errors.New("memstore: row-level security violation")
		}
		if _, ok := t.visible(c.ServerID); !ok {
			return errors.New("memstore: row-level security violation")
		}
	}
	cp := *c
	if cp.Status == "" {
		cp.Status = store.MCPConnectionActive
	}
	key := [2]string{c.ServerID, c.UserID}
	if old, ok := t.m.conns[key]; ok {
		cp.ID, cp.CreatedAt, cp.LastRefreshedAt = old.ID, old.CreatedAt, old.LastRefreshedAt
	} else {
		cp.ID, cp.CreatedAt = "conn-"+c.ServerID+"-"+c.UserID, time.Now()
	}
	cp.UpdatedAt = time.Now()
	t.m.conns[key] = &cp
	*c = cp
	return nil
}

func (t *memTx) SetUserConnectionStatus(_ context.Context, serverID, userID, status string) error {
	c, err := t.getConn(serverID, userID)
	if err != nil {
		return err
	}
	c.Status = status
	t.m.conns[[2]string{serverID, userID}] = c
	return nil
}

func (t *memTx) TouchUserConnectionRefreshed(_ context.Context, serverID, userID string, at time.Time) error {
	c, err := t.getConn(serverID, userID)
	if err != nil {
		return err
	}
	c.LastRefreshedAt = &at
	t.m.conns[[2]string{serverID, userID}] = c
	return nil
}

func (t *memTx) DeleteUserConnection(_ context.Context, serverID, userID string) (int64, error) {
	if _, err := t.getConn(serverID, userID); err != nil {
		return 0, nil
	}
	delete(t.m.conns, [2]string{serverID, userID})
	return 1, nil
}
