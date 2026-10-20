package machines

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/huynle/mcp-gateway/internal/caps"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/store"
)

// memStore is an in-memory Store for unit tests (the PostgreSQL one is
// covered by the integration and security tests).
type memStore struct {
	mu       sync.Mutex
	next     int
	users    map[string]*memUser
	requests map[string]*store.MachineDeviceRequest
	machines map[string]*store.Machine
	codes    map[string]*store.MachineEnrollmentCode
	tokens   map[string]tokenRow
	jtis     map[string]time.Time
	tunnels  map[string]*store.MCPTunnel
	maxMach  int // 0 = unlimited
	maxTun   int
}

type memUser struct{ name, status string }

type tokenRow struct {
	machine string
	exp     time.Time
}

func newMemStore() *memStore {
	return &memStore{
		users: map[string]*memUser{}, requests: map[string]*store.MachineDeviceRequest{}, machines: map[string]*store.Machine{},
		codes: map[string]*store.MachineEnrollmentCode{}, tokens: map[string]tokenRow{}, jtis: map[string]time.Time{},
		tunnels: map[string]*store.MCPTunnel{},
	}
}

func (m *memStore) id() string {
	m.next++
	return fmt.Sprintf("00000000-0000-4000-8000-%012d", m.next)
}

func (m *memStore) addUser(id, name, status string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[id] = &memUser{name: name, status: status}
}

func (m *memStore) setStatus(id, status string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.users[id].status = status
}

func (m *memStore) fill(mc *store.Machine) *store.Machine {
	cp := *mc
	if u := m.users[mc.OwnerUserID]; u != nil {
		cp.OwnerName, cp.OwnerStatus = u.name, u.status
	}
	return &cp
}

func (m *memStore) active(user string) bool {
	u := m.users[user]
	return u != nil && u.status == store.UserActive
}

func (m *memStore) CreateDeviceRequest(_ context.Context, d *store.MachineDeviceRequest) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.requests {
		if bytes.Equal(x.UserCodeHash, d.UserCodeHash) || bytes.Equal(x.DeviceCodeHash, d.DeviceCodeHash) {
			return errCodeCollision
		}
	}
	d.ID, d.Status, d.CreatedAt = m.id(), store.MachineRequestPending, time.Now()
	cp := *d
	m.requests[d.ID] = &cp
	return nil
}

func (m *memStore) DeviceRequestByUserCode(_ context.Context, hash []byte) (*store.MachineDeviceRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.requests {
		if bytes.Equal(x.UserCodeHash, hash) {
			cp := *x
			return &cp, nil
		}
	}
	return nil, store.ErrNotFound
}

func (m *memStore) PollDeviceRequest(_ context.Context, hash []byte, at time.Time, fn func(*store.MachineDeviceRequest) PollDecision) (*store.MachineDeviceRequest, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, x := range m.requests {
		if bytes.Equal(x.DeviceCodeHash, hash) {
			cp := *x
			d := fn(&cp)
			x.LastPolledAt, x.Interval = &at, d.Interval
			if d.Consume && x.Status == store.MachineRequestApproved {
				x.Status = store.MachineRequestConsumed
			}
			return &cp, nil
		}
	}
	return nil, store.ErrNotFound
}

// create stores mc for its owner, replacing (revoking, tunnels moved)
// the owner's live machine of the same name; the caller holds m.mu.
func (m *memStore) create(mc *store.Machine, at time.Time) (string, error) {
	var old *store.Machine
	live := 0
	for _, x := range m.machines {
		if x.OwnerUserID != mc.OwnerUserID || x.RevokedAt != nil {
			continue
		}
		if x.Name == mc.Name {
			old = x
			continue
		}
		live++
	}
	if m.maxMach > 0 && live >= m.maxMach {
		return "", &caps.ExceededError{Resource: caps.Machines, Limit: m.maxMach}
	}
	mc.ID, mc.CreatedAt = m.id(), at
	cp := *mc
	m.machines[mc.ID] = &cp
	if old == nil {
		return "", nil
	}
	old.RevokedAt, old.RevokeReason = &at, store.MachineReplaced
	for _, t := range m.tunnels {
		if t.MachineID == old.ID {
			t.MachineID = mc.ID
		}
	}
	return old.ID, nil
}

func (m *memStore) ApproveDeviceRequest(_ context.Context, requestID, approver string, at time.Time) (*store.Machine, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.requests[requestID]
	if d == nil || d.Status != store.MachineRequestPending || !at.Before(d.ExpiresAt) {
		return nil, "", ErrRequestGone
	}
	if !m.active(approver) {
		return nil, "", ErrInactiveOwner
	}
	mc := &store.Machine{OwnerUserID: approver, Name: d.Name, PublicKey: d.PublicKey, Fingerprint: d.Fingerprint,
		ClientVersion: d.ClientVersion, EnrolledVia: store.MachineEnrolledDevice, EnrolledIP: d.RequestIP}
	old, err := m.create(mc, at)
	if err != nil {
		return nil, "", err
	}
	d.Status, d.DecidedBy, d.MachineID, d.DecidedAt = store.MachineRequestApproved, approver, mc.ID, &at
	return m.fill(mc), old, nil
}

func (m *memStore) DenyDeviceRequest(_ context.Context, requestID, by string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	d := m.requests[requestID]
	if d == nil || d.Status != store.MachineRequestPending {
		return ErrRequestGone
	}
	d.Status, d.DecidedBy, d.DecidedAt = store.MachineRequestDenied, by, &at
	return nil
}

func (m *memStore) Enroll(_ context.Context, codeHash []byte, mc *store.Machine, at time.Time) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.codes {
		if !bytes.Equal(c.CodeHash, codeHash) {
			continue
		}
		if c.UsedAt != nil || c.RevokedAt != nil || !at.Before(c.ExpiresAt) || !m.active(c.OwnerUserID) {
			return "", ErrInvalidCode
		}
		mc.OwnerUserID = c.OwnerUserID
		old, err := m.create(mc, at)
		if err != nil {
			return "", err
		}
		c.UsedAt, c.MachineID = &at, mc.ID
		return old, nil
	}
	return "", ErrInvalidCode
}

func (m *memStore) Machine(_ context.Context, id string) (*store.Machine, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	x := m.machines[id]
	if x == nil {
		return nil, store.ErrNotFound
	}
	return m.fill(x), nil
}

func (m *memStore) RecordJTI(_ context.Context, machineID, jti string, exp, _ time.Time) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := machineID + "/" + jti
	if _, seen := m.jtis[k]; seen {
		return false, nil
	}
	m.jtis[k] = exp
	return true, nil
}

func (m *memStore) IssueToken(_ context.Context, hash []byte, machineID string, exp time.Time, ip string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tokens[string(hash)] = tokenRow{machine: machineID, exp: exp}
	if x := m.machines[machineID]; x != nil {
		x.LastSeenAt, x.LastIP = &at, ip
	}
	return nil
}

func (m *memStore) TokenMachine(_ context.Context, hash []byte, at time.Time) (*store.MachineAccess, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.tokens[string(hash)]
	if !ok || !at.Before(r.exp) {
		return nil, store.ErrNotFound
	}
	return &store.MachineAccess{Machine: *m.fill(m.machines[r.machine]), ExpiresAt: r.exp}, nil
}

func (m *memStore) Revoke(_ context.Context, id, ownerID, actorID, reason string, at time.Time) (*store.Machine, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	x := m.machines[id]
	if x == nil || x.RevokedAt != nil || (ownerID != "" && x.OwnerUserID != ownerID) {
		return nil, store.ErrNotFound
	}
	x.RevokedAt, x.RevokedBy, x.RevokeReason = &at, actorID, reason
	for _, t := range m.tunnels {
		if t.MachineID == id && t.RevokedAt == nil {
			t.RevokedAt = &at
		}
	}
	return m.fill(x), nil
}

func (m *memStore) ListMachines(_ context.Context, ownerID string) ([]store.Machine, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Machine
	for _, x := range m.machines {
		if x.OwnerUserID == ownerID {
			out = append(out, *x)
		}
	}
	return out, nil
}

func (m *memStore) ListAllMachines(context.Context) ([]store.Machine, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Machine
	for _, x := range m.machines {
		out = append(out, *m.fill(x))
	}
	return out, nil
}

func (m *memStore) MachineTunnels(_ context.Context, machineID string) ([]store.MCPTunnel, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.MCPTunnel
	for _, t := range m.tunnels {
		if t.MachineID == machineID {
			out = append(out, *t)
		}
	}
	slices.SortFunc(out, func(a, b store.MCPTunnel) int { return a.CreatedAt.Compare(b.CreatedAt) })
	return out, nil
}

func (m *memStore) EnsureTunnel(_ context.Context, mc *store.Machine, server string) (*store.MCPTunnel, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	live := 0
	for _, t := range m.tunnels {
		if t.MachineID == mc.ID && t.ServerName == server && t.RevokedAt == nil {
			cp := *t
			return &cp, false, nil
		}
		if t.OwnerUserID == mc.OwnerUserID && t.RevokedAt == nil {
			live++
		}
	}
	if m.maxTun > 0 && live >= m.maxTun {
		return nil, false, &caps.ExceededError{Resource: caps.Tunnels, Limit: m.maxTun}
	}
	t := &store.MCPTunnel{ID: m.id(), OwnerUserID: mc.OwnerUserID, Name: mc.Name + "/" + server, MachineID: mc.ID, ServerName: server, CreatedAt: time.Now()}
	m.tunnels[t.ID] = t
	cp := *t
	return &cp, true, nil
}

func (m *memStore) RevokeTunnel(_ context.Context, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t := m.tunnels[id]; t != nil {
		t.RevokedAt = &at
	}
	return nil
}

func (m *memStore) CreateEnrollmentCode(_ context.Context, c *store.MachineEnrollmentCode, maxUsable int, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, x := range m.codes {
		if x.OwnerUserID == c.OwnerUserID && x.UsedAt == nil && x.RevokedAt == nil && at.Before(x.ExpiresAt) {
			n++
		}
	}
	if n >= maxUsable {
		return ErrTooManyCodes
	}
	c.ID, c.CreatedAt = m.id(), at
	cp := *c
	m.codes[c.ID] = &cp
	return nil
}

func (m *memStore) ListEnrollmentCodes(_ context.Context, ownerID string) ([]store.MachineEnrollmentCode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.MachineEnrollmentCode
	for _, c := range m.codes {
		if c.OwnerUserID == ownerID {
			out = append(out, *c)
		}
	}
	return out, nil
}

func (m *memStore) RevokeEnrollmentCode(_ context.Context, ownerID, id string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.codes[id]
	if c == nil || c.OwnerUserID != ownerID || c.UsedAt != nil || c.RevokedAt != nil {
		return store.ErrNotFound
	}
	c.RevokedAt = &at
	return nil
}

// fakeServers is the user's MCP servers (names are global, like the
// gateway's).
type fakeServers struct {
	mu        sync.Mutex
	servers   map[string]*store.MCPServer // by name
	maxPer    int
	refreshes int
	refreshFn func(*store.MCPServer) (int, snapshot.Diff, error)
	approved  map[string]int
}

func newFakeServers() *fakeServers {
	return &fakeServers{servers: map[string]*store.MCPServer{}, approved: map[string]int{}}
}

func (f *fakeServers) OwnServer(_ context.Context, owner, name string) (*store.MCPServer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := f.servers[name]
	if s == nil || s.OwnerUserID != owner {
		return nil, store.ErrNotFound
	}
	cp := *s
	return &cp, nil
}

func (f *fakeServers) CreateServer(_ context.Context, s *store.MCPServer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.servers[s.Name] != nil {
		return ErrServerNameTaken
	}
	n := 0
	for _, x := range f.servers {
		if x.OwnerUserID == s.OwnerUserID {
			n++
		}
	}
	if f.maxPer > 0 && n >= f.maxPer {
		return &caps.ExceededError{Resource: caps.Servers, Limit: f.maxPer}
	}
	s.ID = fmt.Sprintf("50000000-0000-4000-8000-%012d", len(f.servers)+1)
	cp := *s
	f.servers[s.Name] = &cp
	return nil
}

func (f *fakeServers) SetServerURL(_ context.Context, owner string, s *store.MCPServer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	x := f.servers[s.Name]
	if x == nil || x.OwnerUserID != owner {
		return store.ErrNotFound
	}
	x.URL = s.URL
	return nil
}

func (f *fakeServers) Refresh(_ context.Context, _ string, s *store.MCPServer) (int, snapshot.Diff, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshes++
	if f.refreshFn != nil {
		return f.refreshFn(s)
	}
	return 1, snapshot.Diff{Added: []string{"echo"}}, nil
}

func (f *fakeServers) Review(_ context.Context, _, serverID string) (int, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.approved[serverID], f.approved[serverID] == 0, nil
}

// fakeTunnels records machine connection calls.
type fakeTunnels struct {
	mu      sync.Mutex
	online  map[string]bool
	synced  []string
	dropped []string
}

func newFakeTunnels() *fakeTunnels { return &fakeTunnels{online: map[string]bool{}} }

func (f *fakeTunnels) ServeMachine(w http.ResponseWriter, _ *http.Request, machineID string) {
	_, _ = w.Write([]byte("serving " + machineID))
}

func (f *fakeTunnels) SyncMachine(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.synced = append(f.synced, id)
}

func (f *fakeTunnels) DropMachine(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.dropped = append(f.dropped, id)
}

func (f *fakeTunnels) Online(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.online[id]
}

func (f *fakeTunnels) setOnline(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.online[id] = true
}

func (f *fakeTunnels) droppedIDs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.dropped)
}
