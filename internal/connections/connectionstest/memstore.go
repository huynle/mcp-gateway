// Package connectionstest holds an in-memory connections.Store for unit
// tests of the connections service and its portal pages. It mimics the
// PostgreSQL semantics the service relies on: AsUser only sees the user's
// own rows (row-level security), LockConnection holds a per-connection
// lock until the transaction callback returns (SELECT ... FOR UPDATE), and
// TakeConnectFlow is one use.
package connectionstest

import (
	"context"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/store"
)

// MemStore is the in-memory connections.Store. Safe for concurrent use.
type MemStore struct {
	mu      sync.Mutex
	apps    map[string]*store.VendorApp        // by id
	conns   map[string]*store.Connection       // by id
	secrets map[string]*store.ConnectionSecret // by connection id
	flows   map[string]*store.ConnectFlow      // by state
	locks   map[string]*sync.Mutex             // by connection id
	now     func() time.Time
}

// NewMemStore returns an empty store.
func NewMemStore() *MemStore {
	return &MemStore{
		apps: map[string]*store.VendorApp{}, conns: map[string]*store.Connection{},
		secrets: map[string]*store.ConnectionSecret{}, flows: map[string]*store.ConnectFlow{},
		locks: map[string]*sync.Mutex{}, now: time.Now,
	}
}

// Bypass implements connections.Store (every row visible).
func (m *MemStore) Bypass(_ context.Context, fn func(connections.Tx) error) error {
	tx := &memTx{m: m}
	defer tx.release()
	return fn(tx)
}

// AsUser implements connections.Store (only userID's rows visible).
func (m *MemStore) AsUser(_ context.Context, userID string, fn func(connections.Tx) error) error {
	if userID == "" {
		return store.ErrInvalidUserID
	}
	tx := &memTx{m: m, user: userID}
	defer tx.release()
	return fn(tx)
}

// VendorAppRows returns copies of every vendor app row (tests inspect the
// stored envelope).
func (m *MemStore) VendorAppRows() []store.VendorApp {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.VendorApp
	for _, a := range m.apps {
		out = append(out, *a)
	}
	return out
}

// ConnectionRows returns copies of every connection row.
func (m *MemStore) ConnectionRows() []store.Connection {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Connection
	for _, c := range m.conns {
		out = append(out, *c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.Before(out[j].CreatedAt) })
	return out
}

// SecretRows returns copies of every connection_secrets row.
func (m *MemStore) SecretRows() []store.ConnectionSecret {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.ConnectionSecret
	for _, s := range m.secrets {
		out = append(out, *s)
	}
	return out
}

// TamperSecret flips a byte of the stored ciphertext of connectionID.
func (m *MemStore) TamperSecret(connectionID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.secrets[connectionID]
	if !ok || len(s.Secret.Ciphertext) == 0 {
		return false
	}
	s.Secret.Ciphertext[0] ^= 0xff
	return true
}

// FlowCount returns how many in-flight flows are stored.
func (m *MemStore) FlowCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.flows)
}

// SetClock replaces the clock used for created_at timestamps.
func (m *MemStore) SetClock(now func() time.Time) { m.now = now }

type memTx struct {
	m      *MemStore
	user   string // empty = bypass
	locked []*sync.Mutex
}

func (t *memTx) release() {
	for i := len(t.locked) - 1; i >= 0; i-- {
		t.locked[i].Unlock()
	}
	t.locked = nil
}

func (t *memTx) visible(userID string) bool { return t.user == "" || t.user == userID }

func cloneApp(a *store.VendorApp) *store.VendorApp {
	c := *a
	c.Config = slices.Clone(a.Config)
	c.ClientSecret.Ciphertext = slices.Clone(a.ClientSecret.Ciphertext)
	c.ClientSecret.WrappedDataKey = slices.Clone(a.ClientSecret.WrappedDataKey)
	c.ClientSecret.Nonce = slices.Clone(a.ClientSecret.Nonce)
	return &c
}

func cloneConn(c *store.Connection) *store.Connection {
	d := *c
	d.Scopes = slices.Clone(c.Scopes)
	return &d
}

func (t *memTx) ListVendorApps(context.Context) ([]store.VendorApp, error) {
	t.m.mu.Lock()
	defer t.m.mu.Unlock()
	var out []store.VendorApp
	for _, a := range t.m.apps {
		out = append(out, *cloneApp(a))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Vendor != out[j].Vendor {
			return out[i].Vendor < out[j].Vendor
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

func (t *memTx) FindVendorApp(_ context.Context, vendor, name string) (*store.VendorApp, error) {
	t.m.mu.Lock()
	defer t.m.mu.Unlock()
	for _, a := range t.m.apps {
		if a.Vendor == vendor && a.Name == name {
			return cloneApp(a), nil
		}
	}
	return nil, store.ErrNotFound
}

func (t *memTx) GetVendorApp(_ context.Context, id string) (*store.VendorApp, error) {
	t.m.mu.Lock()
	defer t.m.mu.Unlock()
	if a, ok := t.m.apps[id]; ok {
		return cloneApp(a), nil
	}
	return nil, store.ErrNotFound
}

func (t *memTx) UpsertVendorApp(_ context.Context, a *store.VendorApp) error {
	t.m.mu.Lock()
	defer t.m.mu.Unlock()
	now := t.m.now()
	for _, existing := range t.m.apps {
		if existing.Vendor == a.Vendor && existing.Name == a.Name {
			a.ID, a.CreatedAt, a.UpdatedAt = existing.ID, existing.CreatedAt, now
			t.m.apps[a.ID] = cloneApp(a)
			return nil
		}
	}
	if a.ID == "" {
		a.ID = connectors.NewAccountID()
	}
	a.CreatedAt, a.UpdatedAt = now, now
	t.m.apps[a.ID] = cloneApp(a)
	return nil
}

func (t *memTx) ListConnections(_ context.Context, userID string) ([]store.ConnectionWithApp, error) {
	if !t.visible(userID) {
		return nil, nil
	}
	t.m.mu.Lock()
	defer t.m.mu.Unlock()
	var out []store.ConnectionWithApp
	for _, c := range t.m.conns {
		if c.UserID != userID {
			continue
		}
		row := store.ConnectionWithApp{Connection: *cloneConn(c)}
		if a, ok := t.m.apps[c.VendorAppID]; ok {
			row.Vendor, row.AppName = a.Vendor, a.Name
		}
		out = append(out, row)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Vendor != out[j].Vendor {
			return out[i].Vendor < out[j].Vendor
		}
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (t *memTx) getConn(id string) (*store.Connection, error) {
	c, ok := t.m.conns[id]
	if !ok || !t.visible(c.UserID) {
		return nil, store.ErrNotFound
	}
	return c, nil
}

func (t *memTx) GetConnection(_ context.Context, id string) (*store.Connection, error) {
	t.m.mu.Lock()
	defer t.m.mu.Unlock()
	c, err := t.getConn(id)
	if err != nil {
		return nil, err
	}
	return cloneConn(c), nil
}

func (t *memTx) FindConnection(_ context.Context, userID, vendorAppID, externalAccountID string) (*store.Connection, error) {
	if !t.visible(userID) {
		return nil, store.ErrNotFound
	}
	t.m.mu.Lock()
	defer t.m.mu.Unlock()
	for _, c := range t.m.conns {
		if c.UserID == userID && c.VendorAppID == vendorAppID && c.ExternalAccountID == externalAccountID {
			return cloneConn(c), nil
		}
	}
	return nil, store.ErrNotFound
}

func (t *memTx) LockConnection(ctx context.Context, id string) (*store.Connection, error) {
	t.m.mu.Lock()
	if _, err := t.getConn(id); err != nil {
		t.m.mu.Unlock()
		return nil, err
	}
	l, ok := t.m.locks[id]
	if !ok {
		l = &sync.Mutex{}
		t.m.locks[id] = l
	}
	t.m.mu.Unlock()
	l.Lock() // held until release()
	t.locked = append(t.locked, l)
	return t.GetConnection(ctx, id)
}

func (t *memTx) CreateConnection(_ context.Context, c *store.Connection) error {
	if !t.visible(c.UserID) {
		return store.ErrNotFound
	}
	t.m.mu.Lock()
	defer t.m.mu.Unlock()
	for _, e := range t.m.conns {
		if e.UserID == c.UserID && e.VendorAppID == c.VendorAppID && e.ExternalAccountID == c.ExternalAccountID {
			return store.ErrNotFound // unique violation stand-in
		}
	}
	now := t.m.now()
	c.ID = connectors.NewAccountID()
	if c.Status == "" {
		c.Status = store.ConnectionActive
	}
	if c.Scopes == nil {
		c.Scopes = []string{}
	}
	c.CreatedAt, c.UpdatedAt = now, now
	t.m.conns[c.ID] = cloneConn(c)
	return nil
}

func (t *memTx) UpdateConnection(_ context.Context, c *store.Connection) error {
	t.m.mu.Lock()
	defer t.m.mu.Unlock()
	e, err := t.getConn(c.ID)
	if err != nil {
		return err
	}
	e.Label, e.DisplayName, e.Scopes, e.Status, e.UpdatedAt = c.Label, c.DisplayName, slices.Clone(c.Scopes), c.Status, t.m.now()
	c.UpdatedAt = e.UpdatedAt
	return nil
}

func (t *memTx) SetConnectionStatus(_ context.Context, id, status string) error {
	t.m.mu.Lock()
	defer t.m.mu.Unlock()
	e, err := t.getConn(id)
	if err != nil {
		return err
	}
	e.Status, e.UpdatedAt = status, t.m.now()
	return nil
}

func (t *memTx) TouchConnectionRefreshed(_ context.Context, id string, at time.Time) error {
	t.m.mu.Lock()
	defer t.m.mu.Unlock()
	e, err := t.getConn(id)
	if err != nil {
		return nil
	}
	e.LastRefreshedAt = &at
	return nil
}

func (t *memTx) RevokeUserConnections(_ context.Context, userID string) ([]store.Connection, error) {
	if !t.visible(userID) {
		return nil, nil
	}
	t.m.mu.Lock()
	defer t.m.mu.Unlock()
	var out []store.Connection
	for _, c := range t.m.conns {
		if c.UserID == userID && c.Status != store.ConnectionRevoked {
			out = append(out, *cloneConn(c))
			c.Status = store.ConnectionRevoked
		}
	}
	for id, s := range t.m.secrets {
		if s.UserID == userID {
			delete(t.m.secrets, id)
		}
	}
	return out, nil
}

func (t *memTx) ListStaleConnections(_ context.Context, before time.Time, limit int) ([]store.Connection, error) {
	t.m.mu.Lock()
	defer t.m.mu.Unlock()
	var out []store.Connection
	for _, c := range t.m.conns {
		if !t.visible(c.UserID) || c.Status != store.ConnectionActive {
			continue
		}
		last := c.CreatedAt
		if c.LastRefreshedAt != nil {
			last = *c.LastRefreshedAt
		}
		if last.Before(before) {
			out = append(out, *cloneConn(c))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (t *memTx) PutSecret(_ context.Context, s *store.ConnectionSecret) error {
	t.m.mu.Lock()
	defer t.m.mu.Unlock()
	c, ok := t.m.conns[s.ConnectionID]
	if !ok || c.UserID != s.UserID || !t.visible(s.UserID) {
		return store.ErrNotFound
	}
	s.UpdatedAt = t.m.now()
	cp := *s
	cp.Secret.Ciphertext = slices.Clone(s.Secret.Ciphertext)
	cp.Secret.WrappedDataKey = slices.Clone(s.Secret.WrappedDataKey)
	cp.Secret.Nonce = slices.Clone(s.Secret.Nonce)
	t.m.secrets[s.ConnectionID] = &cp
	return nil
}

func (t *memTx) GetSecret(_ context.Context, connectionID string) (*store.ConnectionSecret, error) {
	t.m.mu.Lock()
	defer t.m.mu.Unlock()
	s, ok := t.m.secrets[connectionID]
	if !ok || !t.visible(s.UserID) {
		return nil, store.ErrNotFound
	}
	cp := *s
	cp.Secret.Ciphertext = slices.Clone(s.Secret.Ciphertext)
	cp.Secret.WrappedDataKey = slices.Clone(s.Secret.WrappedDataKey)
	cp.Secret.Nonce = slices.Clone(s.Secret.Nonce)
	return &cp, nil
}

func (t *memTx) DeleteSecret(_ context.Context, connectionID string) (int64, error) {
	t.m.mu.Lock()
	defer t.m.mu.Unlock()
	s, ok := t.m.secrets[connectionID]
	if !ok || !t.visible(s.UserID) {
		return 0, nil
	}
	delete(t.m.secrets, connectionID)
	return 1, nil
}

func (t *memTx) CreateConnectFlow(_ context.Context, f *store.ConnectFlow) error {
	if !t.visible(f.UserID) {
		return store.ErrNotFound
	}
	t.m.mu.Lock()
	defer t.m.mu.Unlock()
	f.CreatedAt = t.m.now()
	cp := *f
	cp.Scopes = slices.Clone(f.Scopes)
	t.m.flows[f.State] = &cp
	return nil
}

func (t *memTx) TakeConnectFlow(_ context.Context, state string, now time.Time) (*store.ConnectFlow, error) {
	t.m.mu.Lock()
	defer t.m.mu.Unlock()
	f, ok := t.m.flows[state]
	if !ok || !t.visible(f.UserID) {
		return nil, store.ErrNotFound
	}
	delete(t.m.flows, state)
	if !f.ExpiresAt.After(now) {
		return nil, store.ErrNotFound
	}
	cp := *f
	return &cp, nil
}

func (t *memTx) PurgeConnectFlows(_ context.Context, now time.Time) (int64, error) {
	t.m.mu.Lock()
	defer t.m.mu.Unlock()
	var n int64
	for state, f := range t.m.flows {
		if !f.ExpiresAt.After(now) && t.visible(f.UserID) {
			delete(t.m.flows, state)
			n++
		}
	}
	return n, nil
}

// Vendors is a helper for tests: the vendor names of the stored apps.
func (m *MemStore) Vendors() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, a := range m.apps {
		out = append(out, a.Vendor)
	}
	sort.Strings(out)
	return out
}

// String summarises the store for test failures.
func (m *MemStore) String() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var b strings.Builder
	for _, c := range m.conns {
		b.WriteString(c.ID + " " + c.UserID + " " + c.Status + "\n")
	}
	return b.String()
}

// Backdate sets a connection's last_refreshed_at (keep-alive tests).
func (m *MemStore) Backdate(connectionID string, at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if c, ok := m.conns[connectionID]; ok {
		c.LastRefreshedAt = &at
	}
}

// ExpireFlows sets every stored flow's expiry to at.
func (m *MemStore) ExpireFlows(at time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, f := range m.flows {
		f.ExpiresAt = at
	}
}
