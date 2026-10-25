// Package authservertest provides an in-memory authserver.Store for tests
// in this and other packages (cmd/gateway, the portal).
package authservertest

import (
	"bytes"
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/huynle/mcp-gateway/internal/authserver"
	"github.com/huynle/mcp-gateway/internal/store"
)

// MemStore is an in-memory authserver.Store that imitates row-level
// security: under AsUser only the scoped user's codes and refresh tokens
// are visible; under Bypass every row is.
type MemStore struct {
	mu       sync.Mutex
	seq      int
	users    map[string]*store.UserAuthFacts
	clients  map[string]*store.OAuthClient       // by row id
	codes    map[string]*store.OAuthCode         // by row id
	refresh  map[string]*store.OAuthRefreshToken // by row id
	keys     map[string]*store.SigningKey        // by row id
	devices  map[string]*store.OAuthDeviceGrant  // by row id
	FailWith error                               // when set, every transaction fails with it (outage)
	// Now is the clock the store stamps created_at / issued_at with (the
	// database's now() in production); tests set it to their fake clock.
	Now func() time.Time
}

// NewMemStore returns an empty store.
func NewMemStore() *MemStore {
	return &MemStore{
		users:   map[string]*store.UserAuthFacts{},
		clients: map[string]*store.OAuthClient{},
		codes:   map[string]*store.OAuthCode{},
		refresh: map[string]*store.OAuthRefreshToken{},
		keys:    map[string]*store.SigningKey{},
		devices: map[string]*store.OAuthDeviceGrant{},
		Now:     time.Now,
	}
}

// AddUser registers an active user with the given last company sign-in.
func (m *MemStore) AddUser(id string, lastSignIn *time.Time) {
	m.SetUser(id, store.UserActive, lastSignIn)
}

// SetUser sets a user's status and last company sign-in.
func (m *MemStore) SetUser(id, status string, lastSignIn *time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[id] = &store.UserAuthFacts{Status: status, LastCompanySignInAt: lastSignIn}
}

// Clients returns copies of every registered client.
func (m *MemStore) Clients() []store.OAuthClient {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.OAuthClient
	for _, c := range m.clients {
		out = append(out, *c)
	}
	return out
}

// RefreshTokens returns copies of every refresh token row.
func (m *MemStore) RefreshTokens() []store.OAuthRefreshToken {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.OAuthRefreshToken
	for _, t := range m.refresh {
		out = append(out, *t)
	}
	slices.SortFunc(out, func(a, b store.OAuthRefreshToken) int { return a.IssuedAt.Compare(b.IssuedAt) })
	return out
}

// Codes returns copies of every code row.
func (m *MemStore) Codes() []store.OAuthCode {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.OAuthCode
	for _, c := range m.codes {
		out = append(out, *c)
	}
	return out
}

// DeviceGrants returns copies of every device grant row, oldest first.
func (m *MemStore) DeviceGrants() []store.OAuthDeviceGrant {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.OAuthDeviceGrant
	for _, g := range m.devices {
		out = append(out, *g)
	}
	slices.SortFunc(out, func(a, b store.OAuthDeviceGrant) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return out
}

// SigningKeys returns copies of every signing key row.
func (m *MemStore) SigningKeys() []store.SigningKey {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.SigningKey
	for _, k := range m.keys {
		out = append(out, *k)
	}
	slices.SortFunc(out, func(a, b store.SigningKey) int { return b.CreatedAt.Compare(a.CreatedAt) })
	return out
}

func (m *MemStore) id(prefix string) string {
	m.seq++
	// A uuid-shaped id so callers that validate ids accept it.
	return fmt.Sprintf("%08x-%04x-4000-8000-%012x", m.seq, len(prefix), m.seq)
}

func (m *MemStore) Bypass(_ context.Context, fn func(authserver.Tx) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailWith != nil {
		return m.FailWith
	}
	return fn(&memTx{m: m})
}

func (m *MemStore) AsUser(_ context.Context, userID string, fn func(authserver.Tx) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.FailWith != nil {
		return m.FailWith
	}
	if _, ok := m.users[userID]; !ok {
		return store.ErrNotFound
	}
	return fn(&memTx{m: m, scope: userID})
}

type memTx struct {
	m     *MemStore
	scope string // "" = bypass
}

func (t *memTx) visible(userID string) bool { return t.scope == "" || userID == t.scope }

func (t *memTx) CreateClient(_ context.Context, c *store.OAuthClient) error {
	for _, e := range t.m.clients {
		if e.ClientID == c.ClientID {
			return fmt.Errorf("store: create oauth client: duplicate client_id")
		}
	}
	c.ID = t.m.id("client")
	c.CreatedAt = t.m.Now()
	if c.RedirectURIs == nil {
		c.RedirectURIs = []string{}
	}
	cp := *c
	t.m.clients[c.ID] = &cp
	return nil
}

func (t *memTx) FindClientByClientID(_ context.Context, clientID string) (*store.OAuthClient, error) {
	for _, c := range t.m.clients {
		if c.ClientID == clientID {
			cp := *c
			return &cp, nil
		}
	}
	return nil, store.ErrNotFound
}

func (t *memTx) GetClient(_ context.Context, id string) (*store.OAuthClient, error) {
	c, ok := t.m.clients[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *c
	return &cp, nil
}

func (t *memTx) TouchClient(_ context.Context, id string, at time.Time) error {
	if c, ok := t.m.clients[id]; ok {
		c.LastUsedAt = &at
	}
	return nil
}

func (t *memTx) CountUnusedClients(context.Context) (int64, error) {
	var n int64
	for _, c := range t.m.clients {
		if c.LastUsedAt == nil {
			n++
		}
	}
	return n, nil
}

func (t *memTx) PruneClients(_ context.Context, idleBefore time.Time) (int64, error) {
	var n int64
	for id, c := range t.m.clients {
		last := c.CreatedAt
		if c.LastUsedAt != nil {
			last = *c.LastUsedAt
		}
		if last.Before(idleBefore) {
			delete(t.m.clients, id)
			for cid, code := range t.m.codes {
				if code.ClientID == id {
					delete(t.m.codes, cid)
				}
			}
			for rid, r := range t.m.refresh {
				if r.ClientID == id {
					delete(t.m.refresh, rid)
				}
			}
			for did, g := range t.m.devices {
				if g.ClientID == id {
					delete(t.m.devices, did)
				}
			}
			n++
		}
	}
	return n, nil
}

func (t *memTx) CreateCode(_ context.Context, c *store.OAuthCode) error {
	if !t.visible(c.UserID) {
		return fmt.Errorf("store: create oauth code: row-level security (SQLSTATE 42501)")
	}
	c.ID = t.m.id("code")
	c.CreatedAt = t.m.Now()
	cp := *c
	t.m.codes[c.ID] = &cp
	return nil
}

func (t *memTx) ConsumeCode(_ context.Context, codeHash []byte, at time.Time) (*store.OAuthCode, bool, error) {
	for _, c := range t.m.codes {
		if bytes.Equal(c.CodeHash, codeHash) && t.visible(c.UserID) {
			consumed := c.ConsumedAt == nil
			if consumed {
				c.ConsumedAt = &at
			}
			cp := *c
			return &cp, consumed, nil
		}
	}
	return nil, false, store.ErrNotFound
}

func (t *memTx) SetCodeFamily(_ context.Context, id, familyID string) error {
	if c, ok := t.m.codes[id]; ok {
		c.FamilyID = &familyID
	}
	return nil
}

func (t *memTx) DeleteExpiredCodes(_ context.Context, before time.Time) (int64, error) {
	var n int64
	for id, c := range t.m.codes {
		if c.ExpiresAt.Before(before) {
			delete(t.m.codes, id)
			n++
		}
	}
	return n, nil
}

func (t *memTx) CreateRefreshToken(_ context.Context, r *store.OAuthRefreshToken) error {
	if !t.visible(r.UserID) {
		return fmt.Errorf("store: create oauth refresh token: row-level security (SQLSTATE 42501)")
	}
	r.ID = t.m.id("refresh")
	if r.FamilyID == "" {
		r.FamilyID = r.ID
	}
	if r.IssuedAt.IsZero() {
		r.IssuedAt = t.m.Now()
	}
	cp := *r
	t.m.refresh[r.ID] = &cp
	return nil
}

func (t *memTx) FindRefreshTokenByHash(_ context.Context, hash []byte) (*store.RefreshTokenLookup, error) {
	for _, r := range t.m.refresh {
		if bytes.Equal(r.TokenHash, hash) && t.visible(r.UserID) {
			l := &store.RefreshTokenLookup{Token: *r}
			if c, ok := t.m.clients[r.ClientID]; ok {
				l.ClientPublicID, l.ClientName = c.ClientID, c.ClientName
			}
			if u, ok := t.m.users[r.UserID]; ok {
				l.UserStatus, l.LastCompanySignInAt = u.Status, u.LastCompanySignInAt
			}
			return l, nil
		}
	}
	return nil, store.ErrNotFound
}

func (t *memTx) RotateRefreshToken(_ context.Context, id string, at time.Time) (bool, error) {
	r, ok := t.m.refresh[id]
	if !ok || !t.visible(r.UserID) || r.RotatedAt != nil {
		return false, nil
	}
	r.RotatedAt = &at
	r.LastUsedAt = &at
	return true, nil
}

func (t *memTx) TouchRefreshToken(_ context.Context, id string, at time.Time) error {
	if r, ok := t.m.refresh[id]; ok && t.visible(r.UserID) {
		r.LastUsedAt = &at
	}
	return nil
}

func (t *memTx) RevokeRefreshFamily(_ context.Context, familyID string, at time.Time) (int64, error) {
	var n int64
	for _, r := range t.m.refresh {
		if r.FamilyID == familyID && t.visible(r.UserID) && r.RevokedAt == nil {
			r.RevokedAt = &at
			n++
		}
	}
	return n, nil
}

func (t *memTx) RevokeUserRefreshTokens(_ context.Context, userID string, at time.Time) (int64, error) {
	var n int64
	for _, r := range t.m.refresh {
		if r.UserID == userID && r.RevokedAt == nil {
			r.RevokedAt = &at
			n++
		}
	}
	for id, c := range t.m.codes {
		if c.UserID == userID && c.ConsumedAt == nil {
			delete(t.m.codes, id)
		}
	}
	return n, nil
}

func (t *memTx) ListHarnesses(_ context.Context, userID string) ([]store.Harness, error) {
	if !t.visible(userID) {
		return nil, nil
	}
	created := map[string]time.Time{}
	for _, r := range t.m.refresh {
		if r.UserID != userID {
			continue
		}
		if c, ok := created[r.FamilyID]; !ok || r.IssuedAt.Before(c) {
			created[r.FamilyID] = r.IssuedAt
		}
	}
	var out []store.Harness
	for _, r := range t.m.refresh {
		if r.UserID != userID || r.RotatedAt != nil {
			continue
		}
		h := store.Harness{FamilyID: r.FamilyID, Scope: string(r.Scope), Resource: r.Resource, CreatedAt: created[r.FamilyID], ExpiresAt: r.ExpiresAt, RevokedAt: r.RevokedAt}
		last := r.IssuedAt
		if r.LastUsedAt != nil {
			last = *r.LastUsedAt
		}
		h.LastUsedAt = &last
		if c, ok := t.m.clients[r.ClientID]; ok {
			h.ClientName, h.ClientID = c.ClientName, c.ClientID
		}
		out = append(out, h)
	}
	slices.SortFunc(out, func(a, b store.Harness) int { return b.CreatedAt.Compare(a.CreatedAt) })
	return out, nil
}

// Device grants are jobs-only in PostgreSQL: under AsUser they are not
// reachable at all.
func (t *memTx) bypassOnly() error {
	if t.scope != "" {
		return fmt.Errorf("store: oauth_device_grants: permission denied (SQLSTATE 42501)")
	}
	return nil
}

func (t *memTx) CreateDeviceGrant(_ context.Context, g *store.OAuthDeviceGrant) error {
	if err := t.bypassOnly(); err != nil {
		return err
	}
	for _, e := range t.m.devices {
		if bytes.Equal(e.UserCodeHash, g.UserCodeHash) {
			return store.ErrUserCodeTaken
		}
		if bytes.Equal(e.DeviceCodeHash, g.DeviceCodeHash) {
			return fmt.Errorf("store: create device grant: duplicate device code")
		}
	}
	g.ID = t.m.id("device")
	g.Status = store.OAuthDevicePending
	g.CreatedAt = t.m.Now()
	cp := *g
	t.m.devices[g.ID] = &cp
	return nil
}

func (t *memTx) CountPendingDeviceGrants(_ context.Context, clientID string, at time.Time) (int64, error) {
	if err := t.bypassOnly(); err != nil {
		return 0, err
	}
	var n int64
	for _, g := range t.m.devices {
		if g.ClientID == clientID && g.Status == store.OAuthDevicePending && g.ExpiresAt.After(at) {
			n++
		}
	}
	return n, nil
}

func (t *memTx) findDevice(match func(*store.OAuthDeviceGrant) bool) (*store.OAuthDeviceGrant, error) {
	if err := t.bypassOnly(); err != nil {
		return nil, err
	}
	for _, g := range t.m.devices {
		if match(g) {
			cp := *g
			return &cp, nil
		}
	}
	return nil, store.ErrNotFound
}

func (t *memTx) FindDeviceGrantByUserCode(_ context.Context, hash []byte) (*store.OAuthDeviceGrant, error) {
	return t.findDevice(func(g *store.OAuthDeviceGrant) bool { return bytes.Equal(g.UserCodeHash, hash) })
}

func (t *memTx) LockDeviceGrant(_ context.Context, hash []byte) (*store.OAuthDeviceGrant, error) {
	return t.findDevice(func(g *store.OAuthDeviceGrant) bool { return bytes.Equal(g.DeviceCodeHash, hash) })
}

func (t *memTx) LockDeviceGrantByID(_ context.Context, id string) (*store.OAuthDeviceGrant, error) {
	return t.findDevice(func(g *store.OAuthDeviceGrant) bool { return g.ID == id })
}

func (t *memTx) UpdateDeviceGrant(_ context.Context, g *store.OAuthDeviceGrant) error {
	if err := t.bypassOnly(); err != nil {
		return err
	}
	e, ok := t.m.devices[g.ID]
	if !ok {
		return store.ErrNotFound
	}
	if (g.Status == store.OAuthDevicePending) != (g.UserID == "") || (g.FamilyID != nil && g.Status != store.OAuthDeviceRedeemed) {
		return fmt.Errorf("store: update device grant: check constraint (SQLSTATE 23514)")
	}
	e.Status, e.UserID, e.Interval, e.LastPolledAt = g.Status, g.UserID, g.Interval, g.LastPolledAt
	e.DecidedAt, e.RedeemedAt, e.FamilyID = g.DecidedAt, g.RedeemedAt, g.FamilyID
	return nil
}

func (t *memTx) DeleteExpiredDeviceGrants(_ context.Context, before time.Time) (int64, error) {
	if err := t.bypassOnly(); err != nil {
		return 0, err
	}
	var n int64
	for id, g := range t.m.devices {
		if g.ExpiresAt.Before(before) {
			delete(t.m.devices, id)
			n++
		}
	}
	return n, nil
}

func (t *memTx) FindUserAuthFacts(_ context.Context, userID string) (*store.UserAuthFacts, error) {
	u, ok := t.m.users[userID]
	if !ok {
		return nil, store.ErrNotFound
	}
	cp := *u
	return &cp, nil
}

func (t *memTx) ListSigningKeys(context.Context) ([]store.SigningKey, error) {
	var out []store.SigningKey
	for _, k := range t.m.keys {
		out = append(out, *k)
	}
	slices.SortFunc(out, func(a, b store.SigningKey) int { return b.CreatedAt.Compare(a.CreatedAt) })
	return out, nil
}

func (t *memTx) CreateSigningKey(_ context.Context, k *store.SigningKey) error {
	for _, e := range t.m.keys {
		if e.KID == k.KID {
			return fmt.Errorf("store: create signing key: duplicate kid")
		}
	}
	k.ID = t.m.id("key")
	if k.Status == "" {
		k.Status = store.SigningKeyActive
	}
	k.CreatedAt = t.m.Now()
	cp := *k
	t.m.keys[k.ID] = &cp
	return nil
}

func (t *memTx) RetireSigningKeys(_ context.Context, keepKID string, at time.Time) (int64, error) {
	var n int64
	for _, k := range t.m.keys {
		if k.KID != keepKID && k.Status == store.SigningKeyActive {
			k.Status = store.SigningKeyRetired
			k.RetiredAt = &at
			n++
		}
	}
	return n, nil
}

func (t *memTx) DeleteRetiredSigningKeys(_ context.Context, retiredBefore time.Time) (int64, error) {
	var n int64
	for id, k := range t.m.keys {
		if k.Status == store.SigningKeyRetired && k.RetiredAt != nil && k.RetiredAt.Before(retiredBefore) {
			delete(t.m.keys, id)
			n++
		}
	}
	return n, nil
}
