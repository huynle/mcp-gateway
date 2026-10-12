package admin_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/federation/admin"
	"github.com/huynle/mcp-gateway/internal/federation/auth"
	fedportal "github.com/huynle/mcp-gateway/internal/federation/portal"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/store"
)

const (
	adminID  = "00000000-0000-4000-8000-00000000000a"
	ownerID  = "00000000-0000-4000-8000-00000000000b"
	memberID = "00000000-0000-4000-8000-00000000000c"
	csrf     = "csrf-token"

	roleEng   = "10000000-0000-4000-8000-000000000001"
	roleSales = "10000000-0000-4000-8000-000000000002"
)

// --- store ---------------------------------------------------------------------

type fakeStore struct {
	mu       sync.Mutex
	servers  map[string]*admin.Server
	order    []string
	clients  map[string]string // server -> static client ID
	tunnels  []admin.Tunnel
	hosts    []store.NetguardAllowHost
	n        int
	writes   []string
	failList error
}

func newFakeStore() *fakeStore {
	return &fakeStore{servers: map[string]*admin.Server{}, clients: map[string]string{}}
}

func (f *fakeStore) id() string {
	f.n++
	return fmt.Sprintf("20000000-0000-4000-8000-%012d", f.n)
}

func (f *fakeStore) add(s admin.Server) *admin.Server {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s.ID == "" {
		s.ID = f.id()
	}
	if s.OwnerUserID == "" {
		s.OwnerUserID, s.OwnerName = ownerID, "Olivia Owner"
	}
	if s.Audience == "" {
		s.Audience = store.MCPAudiencePrivate
	}
	if s.Status == "" {
		s.Status = store.MCPServerActive
	}
	if s.CredentialMode == "" {
		s.CredentialMode = store.MCPCredentialPerUser
	}
	if s.AuthKind == "" {
		s.AuthKind = store.MCPAuthNone
	}
	if s.URL == "" {
		s.URL = "https://mcp.example.com/mcp"
	}
	cp := s
	f.servers[s.ID] = &cp
	f.order = append(f.order, s.ID)
	return &cp
}

func (f *fakeStore) get(id string) *admin.Server {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.servers[id]
	if !ok {
		return nil
	}
	cp := *s
	return &cp
}

func (f *fakeStore) wrote() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.writes)
}

func (f *fakeStore) ListServers(context.Context) ([]admin.Server, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failList != nil {
		return nil, f.failList
	}
	var out []admin.Server
	for _, id := range f.order {
		if s, ok := f.servers[id]; ok {
			out = append(out, *s)
		}
	}
	return out, nil
}

func (f *fakeStore) GetServer(_ context.Context, id string) (*admin.Server, error) {
	if s := f.get(id); s != nil {
		return s, nil
	}
	return nil, store.ErrNotFound
}

func (f *fakeStore) StaticClientID(_ context.Context, serverID string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.clients[serverID], nil
}

func (f *fakeStore) SetPublishedRoles(_ context.Context, serverID string, roleIDs []string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.servers[serverID]
	if !ok {
		return store.ErrNotFound
	}
	s.PublishedRoleIDs = slices.Clone(roleIDs)
	s.Audience = store.MCPAudiencePrivate
	if len(roleIDs) > 0 {
		s.Audience = store.MCPAudiencePublished
	}
	f.writes = append(f.writes, "roles:"+serverID+":"+strings.Join(roleIDs, ","))
	return nil
}

func (f *fakeStore) SetStatus(_ context.Context, serverID, status string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.servers[serverID]
	if !ok {
		return store.ErrNotFound
	}
	s.Status = status
	f.writes = append(f.writes, "status:"+serverID+":"+status)
	return nil
}

// UpdateAddress mimics the schema 17 trigger: an address change of a
// published server withdraws its approved snapshot.
func (f *fakeStore) UpdateAddress(_ context.Context, serverID, rawURL string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.servers[serverID]
	if !ok {
		return store.ErrNotFound
	}
	if s.URL != rawURL && s.Audience == store.MCPAudiencePublished {
		s.ApprovedVersion = 0
	}
	s.URL = rawURL
	f.writes = append(f.writes, "address:"+serverID+":"+rawURL)
	return nil
}

func (f *fakeStore) DeleteServer(_ context.Context, serverID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.servers[serverID]; !ok {
		return store.ErrNotFound
	}
	delete(f.servers, serverID)
	f.writes = append(f.writes, "delete:"+serverID)
	return nil
}

func (f *fakeStore) ListTunnels(context.Context) ([]admin.Tunnel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.tunnels), nil
}

func (f *fakeStore) GetTunnel(_ context.Context, id string) (*admin.Tunnel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, t := range f.tunnels {
		if t.ID == id {
			return &t, nil
		}
	}
	return nil, store.ErrNotFound
}

func (f *fakeStore) ListAllowHosts(context.Context) ([]store.NetguardAllowHost, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.hosts), nil
}

func (f *fakeStore) AddAllowHost(_ context.Context, h *store.NetguardAllowHost) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, e := range f.hosts {
		if e.Pattern == h.Pattern {
			return admin.ErrDuplicate
		}
	}
	h.ID, h.CreatedAt = f.id(), time.Now()
	f.hosts = append(f.hosts, *h)
	f.writes = append(f.writes, "host+:"+h.Pattern)
	return nil
}

func (f *fakeStore) DeleteAllowHost(_ context.Context, id string) (*store.NetguardAllowHost, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, e := range f.hosts {
		if e.ID == id {
			f.hosts = slices.Delete(f.hosts, i, i+1)
			f.writes = append(f.writes, "host-:"+e.Pattern)
			return &e, nil
		}
	}
	return nil, store.ErrNotFound
}

type fakeRoles []admin.Role

func (f fakeRoles) ListRoles(context.Context) ([]admin.Role, error) { return f, nil }

// --- snapshots -----------------------------------------------------------------

type fakeSnapshots struct {
	mu        sync.Mutex
	latest    map[string]*snapshot.Record
	current   map[string]*snapshot.Record
	actors    []snapshot.Actor
	approvals []snapshot.ReviewDecisions
	refreshed []string
}

func newFakeSnapshots() *fakeSnapshots {
	return &fakeSnapshots{latest: map[string]*snapshot.Record{}, current: map[string]*snapshot.Record{}}
}

func (f *fakeSnapshots) pending(serverID string, snap *snapshot.Snapshot) {
	f.mu.Lock()
	defer f.mu.Unlock()
	v := 1
	if l := f.latest[serverID]; l != nil {
		v = l.Version + 1
	}
	f.latest[serverID] = &snapshot.Record{ServerID: serverID, Version: v, Status: store.MCPSnapshotPending, Snapshot: snap}
}

func (f *fakeSnapshots) Refresh(_ context.Context, a snapshot.Actor, serverID string, _ snapshot.Session) (*snapshot.Record, snapshot.Diff, error) {
	f.mu.Lock()
	f.actors = append(f.actors, a)
	f.refreshed = append(f.refreshed, serverID)
	f.mu.Unlock()
	f.pending(serverID, &snapshot.Snapshot{Tools: []snapshot.Tool{{Name: "search", Annotations: &snapshot.Annotations{ReadOnlyHint: true}}}})
	return f.latest[serverID], snapshot.Diff{}, nil
}

func (f *fakeSnapshots) Latest(_ context.Context, a snapshot.Actor, serverID string) (*snapshot.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.actors = append(f.actors, a)
	if r := f.latest[serverID]; r != nil {
		return r, nil
	}
	return nil, snapshot.ErrNoSnapshot
}

func (f *fakeSnapshots) Current(_ context.Context, a snapshot.Actor, serverID string) (*snapshot.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.actors = append(f.actors, a)
	if r := f.current[serverID]; r != nil {
		return r, nil
	}
	return nil, snapshot.ErrNoSnapshot
}

func (f *fakeSnapshots) Approve(_ context.Context, a snapshot.Actor, serverID string, version int, d snapshot.ReviewDecisions) (*snapshot.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.actors = append(f.actors, a)
	l := f.latest[serverID]
	if l == nil || l.Version != version {
		return nil, snapshot.ErrStaleVersion
	}
	f.approvals = append(f.approvals, d)
	rv := snapshot.Review{}
	for name, dec := range d.Tools {
		if dec.Enabled != nil {
			rv[name] = snapshot.ToolReview{Enabled: *dec.Enabled}
		}
	}
	rec := *l
	rec.Status, rec.Review, rec.ApprovedBy = store.MCPSnapshotApproved, rv, a.UserID
	f.current[serverID] = &rec
	return &rec, nil
}

// --- auth, tunnels, factory, hook, allow list, audit ---------------------------

type fakeAuth struct {
	mu      sync.Mutex
	shared  map[string]auth.Credential
	clients map[string][3]string
	actors  []auth.Actor
	err     error
}

func (f *fakeAuth) SetSharedCredential(_ context.Context, a auth.Actor, serverID string, c auth.Credential) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	if f.shared == nil {
		f.shared = map[string]auth.Credential{}
	}
	f.shared[serverID] = c
	f.actors = append(f.actors, a)
	return nil
}

func (f *fakeAuth) SetStaticClient(_ context.Context, a auth.Actor, serverID, clientID, secret, issuer string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.clients == nil {
		f.clients = map[string][3]string{}
	}
	f.clients[serverID] = [3]string{clientID, secret, issuer}
	f.actors = append(f.actors, a)
	return nil
}

type fakeTunnels struct {
	mu      sync.Mutex
	online  map[string]bool
	revoked []string // owner/id
}

func (f *fakeTunnels) Revoke(_ context.Context, owner, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revoked = append(f.revoked, owner+"/"+id)
	return nil
}

func (f *fakeTunnels) Online(id string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.online[id]
}

type fakeSession struct{}

func (fakeSession) Capabilities() *mcp.ServerCapabilities                  { return &mcp.ServerCapabilities{} }
func (fakeSession) ListTools(context.Context) ([]*mcp.Tool, error)         { return nil, nil }
func (fakeSession) ListResources(context.Context) ([]*mcp.Resource, error) { return nil, nil }
func (fakeSession) ListPrompts(context.Context) ([]*mcp.Prompt, error)     { return nil, nil }
func (fakeSession) Close() error                                           { return nil }
func (fakeSession) ReadResource(context.Context, string) (*mcp.ReadResourceResult, error) {
	return nil, errors.New("unused")
}
func (fakeSession) GetPrompt(context.Context, string, map[string]string) (*mcp.GetPromptResult, error) {
	return nil, errors.New("unused")
}
func (fakeSession) ListResourceTemplates(context.Context) ([]*mcp.ResourceTemplate, error) {
	return nil, nil
}

type fakeFactory struct {
	mu    sync.Mutex
	users []string
	err   error
}

func (f *fakeFactory) Open(_ context.Context, _ *store.MCPServer, userID string) (fedportal.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.users = append(f.users, userID)
	if f.err != nil {
		return nil, f.err
	}
	return fakeSession{}, nil
}

type fakeHook struct {
	mu      sync.Mutex
	changed []string
}

func (f *fakeHook) ServerChanged(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.changed = append(f.changed, id)
	return nil
}

func (f *fakeHook) calls() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.changed)
}

type fakeAllowList struct {
	mu sync.Mutex
	n  int
}

func (f *fakeAllowList) Invalidate() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.n++
}

func (f *fakeAllowList) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.n
}

type fakeAudit struct {
	mu     sync.Mutex
	events []audit.Event
}

func (f *fakeAudit) Record(_ context.Context, ev audit.Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, ev)
	return nil
}

func (f *fakeAudit) actions() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, e := range f.events {
		out = append(out, e.ResourceIdentity["action"])
	}
	return out
}

func (f *fakeAudit) last() audit.Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.events) == 0 {
		return audit.Event{}
	}
	return f.events[len(f.events)-1]
}

// --- harness -------------------------------------------------------------------

type harness struct {
	mux     *http.ServeMux
	st      *fakeStore
	snaps   *fakeSnapshots
	auth    *fakeAuth
	tunnels *fakeTunnels
	factory *fakeFactory
	hook    *fakeHook
	allow   *fakeAllowList
	audit   *fakeAudit
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{
		mux: http.NewServeMux(), st: newFakeStore(), snaps: newFakeSnapshots(), auth: &fakeAuth{},
		tunnels: &fakeTunnels{online: map[string]bool{}}, factory: &fakeFactory{}, hook: &fakeHook{},
		allow: &fakeAllowList{}, audit: &fakeAudit{},
	}
	identity := func(r *http.Request) (string, string, bool) {
		return r.Header.Get("X-Test-User"), csrf, r.Header.Get("X-Test-Admin") == "1"
	}
	admin.NewAdmin(admin.Deps{
		Store: h.st, Roles: fakeRoles{{ID: roleEng, Name: "engineering"}, {ID: roleSales, Name: "sales"}},
		Snapshots: h.snaps, Auth: h.auth, Tunnels: h.tunnels, ClientFactory: h.factory, Hook: h.hook,
		AllowList: h.allow, Identity: identity, Audit: h.audit, Log: slog.New(slog.DiscardHandler),
	}).Mount(h.mux.Handle)
	return h
}

type req struct {
	method string
	path   string
	form   url.Values
	user   string // default admin
	member bool   // signed in, not an admin
	anon   bool   // not signed in
	noCSRF bool
}

func (h *harness) do(t *testing.T, r req) *httptest.ResponseRecorder {
	t.Helper()
	if r.method == "" {
		r.method = http.MethodGet
	}
	var body *strings.Reader
	if r.method == http.MethodPost {
		form := url.Values{}
		for k, v := range r.form {
			form[k] = v
		}
		if !r.noCSRF {
			form.Set("_csrf", csrf)
		}
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	hr := httptest.NewRequestWithContext(t.Context(), r.method, r.path, body)
	if r.method == http.MethodPost {
		hr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	switch {
	case r.anon:
	case r.member:
		hr.Header.Set("X-Test-User", memberID)
	case r.user != "":
		hr.Header.Set("X-Test-User", r.user)
	default:
		hr.Header.Set("X-Test-User", adminID)
		hr.Header.Set("X-Test-Admin", "1")
	}
	rec := httptest.NewRecorder()
	h.mux.ServeHTTP(rec, hr)
	return rec
}
