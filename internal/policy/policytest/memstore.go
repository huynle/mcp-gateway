// Package policytest provides an in-memory policy.Store for tests of the
// policy service, the /mcp policy stage and the admin pages.
package policytest

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/store"
)

// MemStore implements policy.Store in memory. Mutators that bypass the
// service (Assign, PutRole, PutRestriction) stand in for the identity
// module and for another replica changing the tables.
type MemStore struct {
	mu           sync.Mutex
	roles        map[string]policy.StoredRole
	assignments  []policy.Assignment
	restrictions map[string]policy.UserRestriction
	versions     []policy.Version
	loads        int
	loadErr      error
	seq          int
}

// NewMemStore returns an empty store.
func NewMemStore() *MemStore {
	return &MemStore{roles: map[string]policy.StoredRole{}, restrictions: map[string]policy.UserRestriction{}}
}

// PutRole adds or replaces a role without touching the service.
func (m *MemStore) PutRole(r policy.Role) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := m.roles[r.Name]
	cur.Role = r
	m.roles[r.Name] = cur
}

// Assign binds user to the named role (like identity.Service would).
func (m *MemStore) Assign(userID, role string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a := policy.Assignment{UserID: userID, Role: role}
	if !slices.Contains(m.assignments, a) {
		m.assignments = append(m.assignments, a)
	}
}

// Unassign removes every assignment of role.
func (m *MemStore) Unassign(role string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.assignments = slices.DeleteFunc(m.assignments, func(a policy.Assignment) bool { return a.Role == role })
}

// PutRestriction adds or replaces a user's restriction.
func (m *MemStore) PutRestriction(u policy.UserRestriction) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.restrictions[u.UserID] = u
}

// Versions returns the persisted versions in creation order.
func (m *MemStore) Versions() []policy.Version {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Clone(m.versions)
}

// Loads counts Load calls.
func (m *MemStore) Loads() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loads
}

// FailLoads makes every later Load return err (nil restores).
func (m *MemStore) FailLoads(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loadErr = err
}

// Load implements policy.Store.
func (m *MemStore) Load(context.Context) (policy.Snapshot, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.loads++
	if m.loadErr != nil {
		return policy.Snapshot{}, m.loadErr
	}
	var s policy.Snapshot
	for _, r := range m.roles {
		s.Roles = append(s.Roles, r)
	}
	slices.SortFunc(s.Roles, func(a, b policy.StoredRole) int { return strings.Compare(a.Name, b.Name) })
	s.Assignments = slices.Clone(m.assignments)
	for _, u := range m.restrictions {
		s.Restrictions = append(s.Restrictions, u)
	}
	return s, nil
}

// SaveRole implements policy.Store.
func (m *MemStore) SaveRole(_ context.Context, r policy.Role) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur := m.roles[r.Name]
	cur.Role = r
	m.roles[r.Name] = cur
	return nil
}

// DeleteRole implements policy.Store.
func (m *MemStore) DeleteRole(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.roles[name]; !ok {
		return store.ErrNotFound
	}
	for _, a := range m.assignments {
		if a.Role == name {
			return policy.ErrRoleAssigned
		}
	}
	delete(m.roles, name)
	return nil
}

// SetDefaultRole implements policy.Store.
func (m *MemStore) SetDefaultRole(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.roles[name]; !ok {
		return store.ErrNotFound
	}
	for n, r := range m.roles {
		r.IsDefault = n == name
		m.roles[n] = r
	}
	return nil
}

// SaveVersion implements policy.Store: idempotent on the hash.
func (m *MemStore) SaveVersion(_ context.Context, v policy.Version) (policy.Version, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, existing := range m.versions {
		if existing.Hash == v.Hash {
			return existing, nil
		}
	}
	m.seq++
	v.ID = fmt.Sprintf("version-%d", m.seq)
	v.CreatedAt = time.Now()
	m.versions = append(m.versions, v)
	return v, nil
}
