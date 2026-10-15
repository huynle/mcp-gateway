package gatewaytools

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/federation/client"
	"github.com/huynle/mcp-gateway/internal/federation/connector"
	fedportal "github.com/huynle/mcp-gateway/internal/federation/portal"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/permissions"
	"github.com/huynle/mcp-gateway/internal/store"
)

const (
	alice = "11111111-1111-4111-8111-111111111111"
	bob   = "22222222-2222-4222-8222-222222222222"
	base  = "https://gw.example.com"
)

// fakeServers is the user-scoped server store: a server is visible to its
// owner and to the users in sharedWith (published to a role they hold).
type fakeServers struct {
	mu         sync.Mutex
	servers    map[string]*store.MCPServer
	sharedWith map[string][]string // server id -> users
	conns      map[string][]store.MCPUserConnection
	info       map[string]fedportal.CredentialInfo
	tunnels    map[string][]store.MCPTunnel
	deleted    []string
}

func newFakeServers() *fakeServers {
	return &fakeServers{servers: map[string]*store.MCPServer{}, sharedWith: map[string][]string{},
		conns: map[string][]store.MCPUserConnection{}, info: map[string]fedportal.CredentialInfo{}, tunnels: map[string][]store.MCPTunnel{}}
}

func (f *fakeServers) add(s store.MCPServer) *store.MCPServer {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s.ID == "" {
		s.ID = connectors.NewAccountID()
	}
	if s.Audience == "" {
		s.Audience = store.MCPAudiencePrivate
	}
	if s.Status == "" {
		s.Status = store.MCPServerActive
	}
	f.servers[s.ID] = &s
	return &s
}

func (f *fakeServers) visible(userID string, s *store.MCPServer) bool {
	return s.OwnerUserID == userID || slices.Contains(f.sharedWith[s.ID], userID)
}

func (f *fakeServers) ListVisibleServers(_ context.Context, userID string) ([]store.MCPServer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.MCPServer
	for _, s := range f.servers {
		if f.visible(userID, s) {
			out = append(out, *s)
		}
	}
	slices.SortFunc(out, func(a, b store.MCPServer) int { return strings.Compare(a.Name, b.Name) })
	return out, nil
}

func (f *fakeServers) GetServer(_ context.Context, userID, id string) (*store.MCPServer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.servers[id]
	if !ok || !f.visible(userID, s) {
		return nil, store.ErrNotFound
	}
	c := *s
	return &c, nil
}

func (f *fakeServers) DeleteServer(_ context.Context, userID, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.servers[id]
	if !ok || s.OwnerUserID != userID {
		return store.ErrNotFound
	}
	delete(f.servers, id)
	f.deleted = append(f.deleted, id)
	return nil
}

func (f *fakeServers) ListConnections(_ context.Context, userID string) ([]store.MCPUserConnection, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.conns[userID]), nil
}

func (f *fakeServers) CredentialInfo(_ context.Context, userID, id string) (fedportal.CredentialInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.servers[id]
	if !ok || s.OwnerUserID != userID {
		return fedportal.CredentialInfo{}, nil
	}
	return f.info[id], nil
}

func (f *fakeServers) ListTunnels(_ context.Context, userID string) ([]store.MCPTunnel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.tunnels[userID]), nil
}

// fakeManager creates servers into fakeServers like connector.Manager:
// permission first, then the name rules, then the unique name.
type fakeManager struct {
	servers   *fakeServers
	permitted map[string]bool
	changed   []string
	created   []*store.MCPServer
}

func (m *fakeManager) CreateServer(_ context.Context, s *store.MCPServer) error {
	if !m.permitted[s.OwnerUserID] {
		return permissions.ErrNotPermitted
	}
	if err := connector.ValidateServerName(s.Name); err != nil {
		return err
	}
	all, _ := m.servers.ListVisibleServers(context.Background(), s.OwnerUserID)
	m.servers.mu.Lock()
	for _, other := range m.servers.servers {
		if other.Name == s.Name {
			m.servers.mu.Unlock()
			return connector.ErrServerNameTaken
		}
	}
	m.servers.mu.Unlock()
	_ = all
	stored := m.servers.add(*s)
	*s = *stored
	m.created = append(m.created, stored)
	m.changed = append(m.changed, s.ID)
	return nil
}

func (m *fakeManager) ServerChanged(_ context.Context, id string) error {
	m.changed = append(m.changed, id)
	return nil
}

// fakeSnapshots keeps a latest and an approved record per server.
type fakeSnapshots struct {
	mu        sync.Mutex
	latest    map[string]*snapshot.Record
	current   map[string]*snapshot.Record
	nextDiff  snapshot.Diff
	skipped   []snapshot.Skipped
	refreshes []string
	refreshBy []snapshot.Actor
	approves  int
	modesBy   []snapshot.Actor
}

func newFakeSnapshots() *fakeSnapshots {
	return &fakeSnapshots{latest: map[string]*snapshot.Record{}, current: map[string]*snapshot.Record{}}
}

func (f *fakeSnapshots) Latest(_ context.Context, _ snapshot.Actor, id string) (*snapshot.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.latest[id]; ok {
		return r, nil
	}
	return nil, snapshot.ErrNoSnapshot
}

func (f *fakeSnapshots) Current(_ context.Context, _ snapshot.Actor, id string) (*snapshot.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r, ok := f.current[id]; ok {
		return r, nil
	}
	return nil, snapshot.ErrNoSnapshot
}

func (f *fakeSnapshots) Refresh(_ context.Context, a snapshot.Actor, id string, _ snapshot.Session) (*snapshot.Record, snapshot.Diff, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshes = append(f.refreshes, id)
	f.refreshBy = append(f.refreshBy, a)
	v := 1
	if r, ok := f.latest[id]; ok {
		v = r.Version + 1
	}
	rec := &snapshot.Record{ServerID: id, Version: v, Status: store.MCPSnapshotPending, Snapshot: &snapshot.Snapshot{}}
	f.latest[id] = rec
	d := f.nextDiff
	d.ToVersion = v
	out := *rec
	out.Skipped = f.skipped
	return &out, d, nil
}

// SetApprovalModes applies modes to the approved record like
// snapshot.Service (a user actor needs its own private server: the fake
// does not know servers, so it trusts the caller's check).
func (f *fakeSnapshots) SetApprovalModes(_ context.Context, a snapshot.Actor, id string, modes map[string]snapshot.Approval) (*snapshot.Record, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cur, ok := f.current[id]
	if !ok {
		return nil, 0, snapshot.ErrNoSnapshot
	}
	review, n, err := snapshot.ApplyApprovals(cur.Review, modes, a.UserID, time.Now())
	if err != nil {
		return nil, 0, err
	}
	f.modesBy = append(f.modesBy, a)
	next := *cur
	next.Review = review
	f.current[id] = &next
	return &next, n, nil
}

// Approve exists only to prove nothing calls it.
func (f *fakeSnapshots) Approve(context.Context, snapshot.Actor, string, int, snapshot.ReviewDecisions) (*snapshot.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.approves++
	return nil, errors.New("approve must never be called by the gateway tools")
}

// approved gives a server an approved snapshot with enabled of its tools
// enabled.
func (f *fakeSnapshots) approved(id string, version int, tools []string, enabled int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec := &snapshot.Record{ServerID: id, Version: version, Status: store.MCPSnapshotApproved, Snapshot: &snapshot.Snapshot{}, Review: snapshot.Review{}}
	for i, name := range tools {
		rec.Snapshot.Tools = append(rec.Snapshot.Tools, snapshot.Tool{Name: name})
		rec.Review[name] = snapshot.ToolReview{Enabled: i < enabled}
	}
	f.current[id], f.latest[id] = rec, rec
}

// fakeDetector answers per URL.
type fakeDetector struct {
	results map[string]*auth.DetectResult
	errs    map[string]error
	calls   []string
}

func (d *fakeDetector) Detect(_ context.Context, u string) (*auth.DetectResult, error) {
	d.calls = append(d.calls, u)
	if err, ok := d.errs[u]; ok {
		return nil, err
	}
	if r, ok := d.results[u]; ok {
		return r, nil
	}
	return nil, &client.Error{Class: client.ClassUnreachable, Op: "connect"}
}

// fakeClients opens sessions (or fails) per server.
type fakeClients struct {
	err    error
	opened []string
	as     []string
}

func (c *fakeClients) Open(_ context.Context, s *store.MCPServer, userID string) (fedportal.Session, error) {
	c.opened = append(c.opened, s.ID)
	c.as = append(c.as, userID)
	if c.err != nil {
		return nil, c.err
	}
	return fakeSession{}, nil
}

type fakeSession struct{}

func (fakeSession) Capabilities() *sdk.ServerCapabilities                  { return &sdk.ServerCapabilities{} }
func (fakeSession) ListTools(context.Context) ([]*sdk.Tool, error)         { return nil, nil }
func (fakeSession) ListResources(context.Context) ([]*sdk.Resource, error) { return nil, nil }
func (fakeSession) ListResourceTemplates(context.Context) ([]*sdk.ResourceTemplate, error) {
	return nil, nil
}
func (fakeSession) ListPrompts(context.Context) ([]*sdk.Prompt, error) { return nil, nil }
func (fakeSession) ReadResource(context.Context, string) (*sdk.ReadResourceResult, error) {
	return nil, errors.New("not used")
}
func (fakeSession) GetPrompt(context.Context, string, map[string]string) (*sdk.GetPromptResult, error) {
	return nil, errors.New("not used")
}
func (fakeSession) Close() error { return nil }

// fakeChecker is netguard's CheckURL in miniature: loopback, link-local
// (metadata) and private literals are blocked unless allow-listed.
type fakeChecker struct{ allow []string }

func (c fakeChecker) CheckURL(_ context.Context, u *url.URL) error {
	h := u.Hostname()
	if slices.Contains(c.allow, h) {
		return nil
	}
	if h == "localhost" || strings.HasPrefix(h, "127.") || strings.HasPrefix(h, "169.254.") || strings.HasPrefix(h, "10.") || h == "[::1]" || h == "::1" {
		return fmt.Errorf("netguard: %s: blocked", h)
	}
	return nil
}

// fakePermStore is permissions.Store in memory.
type fakePermStore struct {
	mu        sync.Mutex
	permitted map[string]bool
	enabled   map[string]bool
	lookups   int
}

func newFakePermStore() *fakePermStore {
	return &fakePermStore{permitted: map[string]bool{}, enabled: map[string]bool{}}
}

func (s *fakePermStore) MayAddServers(_ context.Context, userID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lookups++
	return s.permitted[userID], nil
}

func (s *fakePermStore) GatewayToolsEnabled(_ context.Context, userID string) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.enabled[userID], nil
}

func (s *fakePermStore) SetGatewayToolsEnabled(_ context.Context, userID string, on bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.enabled[userID] = on
	return nil
}

func (s *fakePermStore) set(userID string, permitted, enabled bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.permitted[userID], s.enabled[userID] = permitted, enabled
}
