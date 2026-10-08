package identity_test

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/store"
)

// memStore is an in-memory identity.Store for unit tests. It is not a
// faithful PostgreSQL (no row-level security): every transaction sees every
// row, which is what the identity service relies on for its bypass-scope
// lookups. The Postgres adapter is covered by the integration tests.
type memStore struct {
	mu          sync.Mutex
	seq         int
	users       map[string]*store.User
	identities  map[string]*store.Identity
	roles       map[string]*store.Role // by id
	assignments map[string]map[string]bool
	sessions    map[string]*store.Session
}

func newMemStore() *memStore {
	return &memStore{
		users:       map[string]*store.User{},
		identities:  map[string]*store.Identity{},
		roles:       map[string]*store.Role{},
		assignments: map[string]map[string]bool{},
		sessions:    map[string]*store.Session{},
	}
}

func (m *memStore) id(prefix string) string {
	m.seq++
	// uuid-shaped so store.WithUser-style validation would accept it.
	return fmt.Sprintf("%08x-0000-4000-8000-%012x", len(prefix), m.seq)
}

func (m *memStore) Bypass(_ context.Context, fn func(identity.Tx) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return fn(&memTx{m: m})
}

func (m *memStore) AsUser(_ context.Context, userID string, fn func(identity.Tx) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[userID]; !ok {
		return store.ErrNotFound
	}
	return fn(&memTx{m: m})
}

// Test helpers (callers hold no lock).

func (m *memStore) userCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.users)
}

func (m *memStore) roleNames(userID string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var names []string
	for roleID := range m.assignments[userID] {
		names = append(names, m.roles[roleID].Name)
	}
	return names
}

func (m *memStore) liveSessions(userID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, s := range m.sessions {
		if s.UserID == userID && s.RevokedAt == nil {
			n++
		}
	}
	return n
}

type memTx struct{ m *memStore }

func (t *memTx) Raw() store.Tx { return nil }

func (t *memTx) FindIdentity(_ context.Context, issuer, subject string) (*store.Identity, error) {
	for _, i := range t.m.identities {
		if i.Issuer == issuer && i.Subject == subject {
			c := *i
			return &c, nil
		}
	}
	return nil, store.ErrNotFound
}

func (t *memTx) GetUser(_ context.Context, id string) (*store.User, error) {
	u, ok := t.m.users[id]
	if !ok {
		return nil, store.ErrNotFound
	}
	c := *u
	return &c, nil
}

func (t *memTx) CreateUser(_ context.Context, displayName string) (*store.User, error) {
	now := time.Now()
	u := &store.User{ID: t.m.id("user"), DisplayName: displayName, Status: store.UserActive, CreatedAt: now, UpdatedAt: now}
	t.m.users[u.ID] = u
	c := *u
	return &c, nil
}

func (t *memTx) CreateIdentity(_ context.Context, userID, issuer, subject string) (*store.Identity, error) {
	if _, err := t.FindIdentity(context.Background(), issuer, subject); err == nil {
		return nil, fmt.Errorf("duplicate identity %s %s", issuer, subject)
	}
	i := &store.Identity{ID: t.m.id("identity"), UserID: userID, Issuer: issuer, Subject: subject, CreatedAt: time.Now()}
	t.m.identities[i.ID] = i
	c := *i
	return &c, nil
}

func (t *memTx) RecordSignIn(_ context.Context, userID, identityID, displayName string, at time.Time) error {
	u, ok := t.m.users[userID]
	if !ok {
		return store.ErrNotFound
	}
	u.LastCompanySignInAt = &at
	u.DisplayName = displayName
	if i, ok := t.m.identities[identityID]; ok {
		i.LastSignInAt = &at
	}
	return nil
}

func (t *memTx) FindRoleByName(_ context.Context, name string) (*store.Role, error) {
	for _, r := range t.m.roles {
		if r.Name == name {
			c := *r
			return &c, nil
		}
	}
	return nil, store.ErrNotFound
}

func (t *memTx) EnsureRole(ctx context.Context, name, description string) (*store.Role, error) {
	if r, err := t.FindRoleByName(ctx, name); err == nil {
		return r, nil
	}
	r := &store.Role{ID: t.m.id("role"), Name: name, Description: description, Definition: []byte(`{}`)}
	t.m.roles[r.ID] = r
	c := *r
	return &c, nil
}

func (t *memTx) ListRoles(context.Context) ([]store.Role, error) {
	var out []store.Role
	for _, r := range t.m.roles {
		out = append(out, *r)
	}
	return out, nil
}

func (t *memTx) AssignRole(_ context.Context, userID, roleID string, _ *string) error {
	if t.m.assignments[userID] == nil {
		t.m.assignments[userID] = map[string]bool{}
	}
	t.m.assignments[userID][roleID] = true
	return nil
}

func (t *memTx) SetUserRole(_ context.Context, userID, roleID string, _ *string) error {
	t.m.assignments[userID] = map[string]bool{roleID: true}
	return nil
}

func (t *memTx) RolesForUser(_ context.Context, userID string) ([]store.Role, error) {
	var out []store.Role
	for roleID := range t.m.assignments[userID] {
		out = append(out, *t.m.roles[roleID])
	}
	return out, nil
}

func (t *memTx) ListUsers(context.Context) ([]store.User, error) {
	var out []store.User
	for _, u := range t.m.users {
		out = append(out, *u)
	}
	return out, nil
}

func (t *memTx) SetUserStatus(_ context.Context, userID, status string, at time.Time) error {
	u, ok := t.m.users[userID]
	if !ok {
		return store.ErrNotFound
	}
	u.Status = status
	if status == store.UserDisabled {
		u.DisabledAt = &at
	} else {
		u.DisabledAt = nil
	}
	return nil
}

func (t *memTx) CreateSession(_ context.Context, userID string, tokenHash []byte, expiresAt time.Time) (*store.Session, error) {
	s := &store.Session{ID: t.m.id("session"), UserID: userID, TokenHash: tokenHash, CreatedAt: time.Now(), ExpiresAt: expiresAt}
	t.m.sessions[s.ID] = s
	c := *s
	return &c, nil
}

func (t *memTx) FindSessionByTokenHash(_ context.Context, hash []byte) (*store.Session, error) {
	for _, s := range t.m.sessions {
		if bytes.Equal(s.TokenHash, hash) {
			c := *s
			return &c, nil
		}
	}
	return nil, store.ErrNotFound
}

func (t *memTx) TouchSession(_ context.Context, id string, at time.Time) error {
	if s, ok := t.m.sessions[id]; ok {
		s.LastSeenAt = &at
	}
	return nil
}

func (t *memTx) RevokeSession(_ context.Context, id string, at time.Time) error {
	if s, ok := t.m.sessions[id]; ok && s.RevokedAt == nil {
		s.RevokedAt = &at
	}
	return nil
}

func (t *memTx) RevokeUserSessions(_ context.Context, userID string, at time.Time) (int64, error) {
	var n int64
	for _, s := range t.m.sessions {
		if s.UserID == userID && s.RevokedAt == nil {
			s.RevokedAt = &at
			n++
		}
	}
	return n, nil
}
