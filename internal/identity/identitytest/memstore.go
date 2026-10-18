// Package identitytest provides an in-memory identity.Store for tests in
// this and other packages (the portal).
package identitytest

import (
	"bytes"
	"context"
	"fmt"
	"maps"
	"sort"
	"sync"
	"time"

	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/store"
)

// MemStore is an in-memory identity.Store for unit tests. It is not a
// faithful PostgreSQL (no row-level security): every transaction sees every
// row, which is what the identity service relies on for its bypass-scope
// lookups. The Postgres adapter is covered by the integration tests.
type MemStore struct {
	mu          sync.Mutex
	seq         int
	users       map[string]*store.User
	identities  map[string]*store.Identity
	roles       map[string]*store.Role // by id
	assignments map[string]map[string]bool
	sessions    map[string]*store.Session
	invites     map[string]*store.SignupInvite
	signups     []signupEvent
}

type signupEvent struct {
	key []byte
	at  time.Time
}

// NewMemStore returns an empty store.
func NewMemStore() *MemStore {
	return &MemStore{
		users:       map[string]*store.User{},
		identities:  map[string]*store.Identity{},
		roles:       map[string]*store.Role{},
		assignments: map[string]map[string]bool{},
		sessions:    map[string]*store.Session{},
		invites:     map[string]*store.SignupInvite{},
	}
}

// SetDefaultRole flags the named role as the default (creating it when
// missing), as the admin default-role page does in PostgreSQL.
func (m *MemStore) SetDefaultRole(name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	tx := &memTx{m: m}
	r, _ := tx.EnsureRole(context.Background(), name, "")
	for id, role := range m.roles {
		role.IsDefault = id == r.ID
	}
}

func (m *MemStore) id(prefix string) string {
	m.seq++
	// uuid-shaped so store.WithUser-style validation would accept it.
	return fmt.Sprintf("%08x-0000-4000-8000-%012x", len(prefix), m.seq)
}

// Bypass runs fn and, like a PostgreSQL transaction, undoes every change
// when fn fails.
func (m *MemStore) Bypass(_ context.Context, fn func(identity.Tx) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	snap := m.snapshot()
	if err := fn(&memTx{m: m}); err != nil {
		m.restore(snap)
		return err
	}
	return nil
}

type memSnapshot struct {
	users       map[string]store.User
	identities  map[string]store.Identity
	roles       map[string]store.Role
	assignments map[string]map[string]bool
	sessions    map[string]store.Session
	invites     map[string]store.SignupInvite
	signups     []signupEvent
}

func (m *MemStore) snapshot() memSnapshot {
	s := memSnapshot{
		users: map[string]store.User{}, identities: map[string]store.Identity{}, roles: map[string]store.Role{},
		assignments: map[string]map[string]bool{}, sessions: map[string]store.Session{}, invites: map[string]store.SignupInvite{},
		signups: append([]signupEvent(nil), m.signups...),
	}
	for k, v := range m.users {
		s.users[k] = *v
	}
	for k, v := range m.identities {
		s.identities[k] = *v
	}
	for k, v := range m.roles {
		s.roles[k] = *v
	}
	for k, v := range m.assignments {
		s.assignments[k] = maps.Clone(v)
	}
	for k, v := range m.sessions {
		s.sessions[k] = *v
	}
	for k, v := range m.invites {
		s.invites[k] = *v
	}
	return s
}

func (m *MemStore) restore(s memSnapshot) {
	m.users, m.identities, m.roles = map[string]*store.User{}, map[string]*store.Identity{}, map[string]*store.Role{}
	m.sessions, m.invites = map[string]*store.Session{}, map[string]*store.SignupInvite{}
	for k, v := range s.users {
		m.users[k] = &v
	}
	for k, v := range s.identities {
		m.identities[k] = &v
	}
	for k, v := range s.roles {
		m.roles[k] = &v
	}
	for k, v := range s.sessions {
		m.sessions[k] = &v
	}
	for k, v := range s.invites {
		m.invites[k] = &v
	}
	m.assignments = s.assignments
	m.signups = s.signups
}

func (m *MemStore) AsUser(_ context.Context, userID string, fn func(identity.Tx) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.users[userID]; !ok {
		return store.ErrNotFound
	}
	return fn(&memTx{m: m})
}

// Test helpers (callers hold no lock).

// UserCount returns how many users exist.
func (m *MemStore) UserCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.users)
}

// RoleNames returns the names of the roles assigned to userID (unordered).
func (m *MemStore) RoleNames(userID string) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var names []string
	for roleID := range m.assignments[userID] {
		names = append(names, m.roles[roleID].Name)
	}
	return names
}

// LiveSessions counts the unrevoked sessions of userID.
func (m *MemStore) LiveSessions(userID string) int {
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

type memTx struct{ m *MemStore }

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

func (t *memTx) CreateUser(_ context.Context, displayName, status string) (*store.User, error) {
	now := time.Now()
	if status == "" {
		status = store.UserActive
	}
	u := &store.User{ID: t.m.id("user"), DisplayName: displayName, Status: status, CreatedAt: now, UpdatedAt: now}
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

func (t *memTx) FindDefaultRole(context.Context) (*store.Role, error) {
	for _, r := range t.m.roles {
		if r.IsDefault {
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

func (t *memTx) TransitionUserStatus(ctx context.Context, userID, from, to string, at time.Time) error {
	u, ok := t.m.users[userID]
	if !ok || u.Status != from {
		return store.ErrNotFound
	}
	return t.SetUserStatus(ctx, userID, to, at)
}

func (t *memTx) LockSignups(context.Context) error { return nil }

func (t *memTx) CountSignups(_ context.Context, key []byte, since time.Time) (int, int, error) {
	var global, perKey int
	for _, e := range t.m.signups {
		if e.at.After(since) {
			global++
			if bytes.Equal(e.key, key) {
				perKey++
			}
		}
	}
	return global, perKey, nil
}

func (t *memTx) RecordSignup(_ context.Context, key []byte, at, pruneBefore time.Time) error {
	kept := t.m.signups[:0]
	for _, e := range t.m.signups {
		if pruneBefore.IsZero() || !e.at.Before(pruneBefore) {
			kept = append(kept, e)
		}
	}
	t.m.signups = append(kept, signupEvent{key: bytes.Clone(key), at: at})
	return nil
}

func (t *memTx) CreateInvite(_ context.Context, inv *store.SignupInvite) error {
	inv.ID = t.m.id("invite")
	inv.CreatedAt = time.Now()
	c := *inv
	t.m.invites[inv.ID] = &c
	return nil
}

func (t *memTx) ConsumeInvite(_ context.Context, hash []byte, userID string, at time.Time) (string, error) {
	for _, inv := range t.m.invites {
		if bytes.Equal(inv.CodeHash, hash) && inv.UsedAt == nil && inv.RevokedAt == nil && inv.ExpiresAt.After(at) {
			inv.UsedAt, inv.UsedBy = &at, &userID
			return inv.ID, nil
		}
	}
	return "", store.ErrNotFound
}

func (t *memTx) RevokeInvite(_ context.Context, id string, at time.Time) error {
	inv, ok := t.m.invites[id]
	if !ok || inv.UsedAt != nil || inv.RevokedAt != nil {
		return store.ErrNotFound
	}
	inv.RevokedAt = &at
	return nil
}

func (t *memTx) ListInvites(_ context.Context, limit int) ([]store.SignupInvite, error) {
	var out []store.SignupInvite
	for _, inv := range t.m.invites {
		out = append(out, *inv)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].CreatedAt.After(out[j].CreatedAt) })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}
