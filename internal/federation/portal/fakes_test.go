package portal

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

	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/portal/nav"
	"github.com/huynle/mcp-gateway/internal/store"
)

const (
	alice = "aaaaaaaa-0000-4000-8000-000000000001"
	bob   = "bbbbbbbb-0000-4000-8000-000000000002"
	base  = "https://gw.example"
)

// --- store ---------------------------------------------------------------------

type fakeStore struct {
	mu      sync.Mutex
	seq     int
	servers map[string]*store.MCPServer
	viewers map[string][]string // published server -> users with a role
	conns   map[string]store.MCPUserConnection
	creds   map[string]CredentialInfo
	tunnels []store.MCPTunnel
	deleted []string
}

func newFakeStore() *fakeStore {
	return &fakeStore{servers: map[string]*store.MCPServer{}, viewers: map[string][]string{},
		conns: map[string]store.MCPUserConnection{}, creds: map[string]CredentialInfo{}}
}

func (f *fakeStore) nextID() string {
	f.seq++
	return fmt.Sprintf("5e000000-0000-4000-8000-%012d", f.seq)
}

func (f *fakeStore) add(s store.MCPServer, viewers ...string) *store.MCPServer {
	f.mu.Lock()
	defer f.mu.Unlock()
	if s.ID == "" {
		s.ID = f.nextID()
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
	f.servers[s.ID] = &s
	f.viewers[s.ID] = viewers
	return &s
}

func (f *fakeStore) visible(userID string, s *store.MCPServer) bool {
	return s.OwnerUserID == userID || (s.Audience == store.MCPAudiencePublished && slices.Contains(f.viewers[s.ID], userID))
}

func (f *fakeStore) ListVisibleServers(_ context.Context, userID string) ([]store.MCPServer, error) {
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

func (f *fakeStore) GetServer(_ context.Context, userID, id string) (*store.MCPServer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.servers[id]
	if !ok || !f.visible(userID, s) {
		return nil, store.ErrNotFound
	}
	c := *s
	return &c, nil
}

func (f *fakeStore) CreateServer(_ context.Context, userID string, s *store.MCPServer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, o := range f.servers {
		if o.Name == s.Name {
			return ErrNameTaken
		}
	}
	s.ID = f.nextID()
	s.OwnerUserID = userID
	s.Audience = store.MCPAudiencePrivate
	s.Status = store.MCPServerActive
	c := *s
	f.servers[s.ID] = &c
	return nil
}

func (f *fakeStore) UpdateServer(_ context.Context, userID string, s *store.MCPServer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.servers[s.ID]
	if !ok || o.OwnerUserID != userID {
		return store.ErrNotFound
	}
	c := *s
	c.OwnerUserID, c.Audience, c.Status = o.OwnerUserID, o.Audience, o.Status
	f.servers[s.ID] = &c
	return nil
}

func (f *fakeStore) DeleteServer(_ context.Context, userID, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	o, ok := f.servers[id]
	if !ok || o.OwnerUserID != userID {
		return store.ErrNotFound
	}
	delete(f.servers, id)
	f.deleted = append(f.deleted, id)
	return nil
}

func (f *fakeStore) ListConnections(_ context.Context, userID string) ([]store.MCPUserConnection, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.MCPUserConnection
	for _, c := range f.conns {
		if c.UserID == userID {
			out = append(out, c)
		}
	}
	return out, nil
}

func (f *fakeStore) setConn(serverID, userID, status string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.conns[serverID+"/"+userID] = store.MCPUserConnection{ServerID: serverID, UserID: userID, Status: status}
}

func (f *fakeStore) CredentialInfo(_ context.Context, userID, serverID string) (CredentialInfo, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.servers[serverID]
	if !ok || s.OwnerUserID != userID {
		return CredentialInfo{}, nil
	}
	return f.creds[serverID], nil
}

func (f *fakeStore) ListTunnels(_ context.Context, userID string) ([]store.MCPTunnel, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []store.MCPTunnel
	for _, t := range f.tunnels {
		if t.OwnerUserID == userID {
			out = append(out, t)
		}
	}
	return out, nil
}

// --- snapshots -------------------------------------------------------------------

type approval struct {
	actor    snapshot.Actor
	serverID string
	version  int
	d        snapshot.ReviewDecisions
}

type fakeSnapshots struct {
	mu         sync.Mutex
	latest     map[string]*snapshot.Record
	current    map[string]*snapshot.Record
	next       map[string]*snapshot.Snapshot // what Refresh discovers
	refreshed  []string
	approvals  []approval
	approveErr error
}

func newFakeSnapshots() *fakeSnapshots {
	return &fakeSnapshots{latest: map[string]*snapshot.Record{}, current: map[string]*snapshot.Record{}, next: map[string]*snapshot.Snapshot{}}
}

func (f *fakeSnapshots) Refresh(ctx context.Context, a snapshot.Actor, serverID string, sess snapshot.Session) (*snapshot.Record, snapshot.Diff, error) {
	if _, err := sess.ListTools(ctx); err != nil {
		return nil, snapshot.Diff{}, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.refreshed = append(f.refreshed, a.UserID+"/"+serverID)
	v := 1
	if l := f.latest[serverID]; l != nil {
		v = l.Version + 1
	}
	rec := &snapshot.Record{ServerID: serverID, Version: v, Status: store.MCPSnapshotPending, Snapshot: f.next[serverID]}
	f.latest[serverID] = rec
	var from *snapshot.Snapshot
	if c := f.current[serverID]; c != nil {
		from = c.Snapshot
	}
	return rec, snapshot.Compare(from, rec.Snapshot), nil
}

func (f *fakeSnapshots) Diff(_ context.Context, _ snapshot.Actor, serverID string) (snapshot.Diff, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	l := f.latest[serverID]
	if l == nil {
		return snapshot.Diff{}, snapshot.ErrNoSnapshot
	}
	var from *snapshot.Snapshot
	d := snapshot.Diff{ToVersion: l.Version}
	if c := f.current[serverID]; c != nil {
		from = c.Snapshot
		d.FromVersion = c.Version
		if c.Version == l.Version {
			return d, nil
		}
	}
	cd := snapshot.Compare(from, l.Snapshot)
	cd.FromVersion, cd.ToVersion = d.FromVersion, d.ToVersion
	return cd, nil
}

func (f *fakeSnapshots) Latest(_ context.Context, _ snapshot.Actor, serverID string) (*snapshot.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if l := f.latest[serverID]; l != nil {
		return l, nil
	}
	return nil, snapshot.ErrNoSnapshot
}

func (f *fakeSnapshots) Current(_ context.Context, _ snapshot.Actor, serverID string) (*snapshot.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c := f.current[serverID]; c != nil {
		return c, nil
	}
	return nil, snapshot.ErrNoSnapshot
}

func (f *fakeSnapshots) Approve(_ context.Context, a snapshot.Actor, serverID string, version int, d snapshot.ReviewDecisions) (*snapshot.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.approvals = append(f.approvals, approval{a, serverID, version, d})
	if f.approveErr != nil {
		return nil, f.approveErr
	}
	l := f.latest[serverID]
	if l == nil || l.Version != version {
		return nil, snapshot.ErrStaleVersion
	}
	rec := *l
	rec.Status = store.MCPSnapshotApproved
	rec.Review = snapshot.Review{}
	for _, t := range l.Snapshot.Tools {
		dec := d.Tools[t.Name]
		on := dec.Enabled != nil && *dec.Enabled
		rec.Review[t.Name] = snapshot.ToolReview{Enabled: on, Kind: t.HintKind()}
	}
	f.current[serverID] = &rec
	f.latest[serverID] = &rec
	return &rec, nil
}

// approved stores snap as both the latest and the approved version 1.
func (f *fakeSnapshots) approved(serverID string, snap *snapshot.Snapshot, review snapshot.Review) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rec := &snapshot.Record{ServerID: serverID, Version: 1, Status: store.MCPSnapshotApproved, Snapshot: snap, Review: review}
	f.current[serverID] = rec
	f.latest[serverID] = rec
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

// --- auth --------------------------------------------------------------------------

type credCall struct {
	actor    auth.Actor
	userID   string
	serverID string
	c        auth.Credential
}

type fakeAuth struct {
	mu          sync.Mutex
	detect      *auth.DetectResult
	detectErr   error
	detected    []string
	shared      []credCall
	user        []credCall
	clients     []string
	disconnects []string
	userErr     error
}

func (f *fakeAuth) Detect(_ context.Context, u string) (*auth.DetectResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.detected = append(f.detected, u)
	return f.detect, f.detectErr
}

func (f *fakeAuth) SetSharedCredential(_ context.Context, a auth.Actor, serverID string, c auth.Credential) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.shared = append(f.shared, credCall{actor: a, serverID: serverID, c: c})
	return nil
}

func (f *fakeAuth) SetUserCredential(_ context.Context, userID, serverID string, c auth.Credential) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.userErr != nil {
		return f.userErr
	}
	f.user = append(f.user, credCall{userID: userID, serverID: serverID, c: c})
	return nil
}

func (f *fakeAuth) SetStaticClient(_ context.Context, a auth.Actor, serverID, clientID, secret, issuer string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clients = append(f.clients, serverID+"|"+clientID+"|"+secret+"|"+issuer)
	return nil
}

func (f *fakeAuth) Disconnect(_ context.Context, userID, serverID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.disconnects = append(f.disconnects, userID+"/"+serverID)
	return nil
}

// --- tunnels -----------------------------------------------------------------------

type fakeTunnels struct {
	st      *fakeStore
	online  map[string]bool
	revoked []string
}

func (f *fakeTunnels) CreateTunnel(_ context.Context, owner, name string) (*store.MCPTunnel, string, error) {
	f.st.mu.Lock()
	defer f.st.mu.Unlock()
	t := store.MCPTunnel{ID: f.st.nextID(), OwnerUserID: owner, Name: name, CreatedAt: time.Now()}
	f.st.tunnels = append(f.st.tunnels, t)
	return &t, "mgt_ABCDEFGH_" + strings.Repeat("s", 43), nil
}

func (f *fakeTunnels) Revoke(_ context.Context, owner, id string) error {
	f.st.mu.Lock()
	defer f.st.mu.Unlock()
	for i, t := range f.st.tunnels {
		if t.ID == id && t.OwnerUserID == owner && t.RevokedAt == nil {
			now := time.Now()
			f.st.tunnels[i].RevokedAt = &now
			f.revoked = append(f.revoked, id)
			return nil
		}
	}
	return errors.New("tunnel: forbidden")
}

func (f *fakeTunnels) Online(id string) bool { return f.online[id] }

// --- upstream session ----------------------------------------------------------------

type fakeSession struct {
	tools     []*mcp.Tool
	resources map[string]*mcp.ReadResourceResult
	prompts   map[string]*mcp.GetPromptResult
	reads     []string
	gets      []map[string]string
	closed    bool
}

func (s *fakeSession) Capabilities() *mcp.ServerCapabilities { return &mcp.ServerCapabilities{} }
func (s *fakeSession) ListTools(context.Context) ([]*mcp.Tool, error) {
	return s.tools, nil
}
func (s *fakeSession) ListResources(context.Context) ([]*mcp.Resource, error) { return nil, nil }
func (s *fakeSession) ListResourceTemplates(context.Context) ([]*mcp.ResourceTemplate, error) {
	return nil, nil
}
func (s *fakeSession) ListPrompts(context.Context) ([]*mcp.Prompt, error) { return nil, nil }
func (s *fakeSession) ReadResource(_ context.Context, uri string) (*mcp.ReadResourceResult, error) {
	s.reads = append(s.reads, uri)
	if r, ok := s.resources[uri]; ok {
		return r, nil
	}
	return nil, errors.New("upstream says: secret internal detail")
}
func (s *fakeSession) GetPrompt(_ context.Context, name string, args map[string]string) (*mcp.GetPromptResult, error) {
	s.gets = append(s.gets, args)
	if r, ok := s.prompts[name]; ok {
		return r, nil
	}
	return nil, errors.New("upstream says: secret internal detail")
}
func (s *fakeSession) Close() error { s.closed = true; return nil }

type fakeFactory struct {
	sess   *fakeSession
	err    error
	opened []string
}

func (f *fakeFactory) Open(_ context.Context, server *store.MCPServer, userID string) (Session, error) {
	f.opened = append(f.opened, userID+"/"+server.ID)
	if f.err != nil {
		return nil, f.err
	}
	return f.sess, nil
}

// fakePerms answers CanAddServers: everyone but the denied users may add
// servers.
type fakePerms struct {
	mu     sync.Mutex
	denied map[string]bool
	asked  []string
}

func (f *fakePerms) CanAddServers(_ context.Context, userID string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, userID)
	return userID != "" && !f.denied[userID]
}

type fakeHook struct {
	mu      sync.Mutex
	changed []string
}

func (h *fakeHook) ServerChanged(_ context.Context, id string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.changed = append(h.changed, id)
}

// --- harness ---------------------------------------------------------------------------

type env struct {
	t    *testing.T
	st   *fakeStore
	snap *fakeSnapshots
	auth *fakeAuth
	tun  *fakeTunnels
	fac  *fakeFactory
	hook *fakeHook
	perm *fakePerms
	mux  *http.ServeMux
}

func newEnv(t *testing.T) *env {
	t.Helper()
	e := &env{t: t, st: newFakeStore(), snap: newFakeSnapshots(), auth: &fakeAuth{}, fac: &fakeFactory{sess: &fakeSession{}}, hook: &fakeHook{},
		perm: &fakePerms{denied: map[string]bool{}}}
	e.tun = &fakeTunnels{st: e.st, online: map[string]bool{}}
	p := NewPortal(Deps{
		Store: e.st, Snapshots: e.snap, Auth: e.auth, Tunnels: e.tun, ClientFactory: e.fac, Hook: e.hook, Permissions: e.perm,
		Identity: func(r *http.Request) (string, string, bool) {
			u := r.Header.Get("X-Test-User")
			if u == "" {
				return "", "", false
			}
			return u, "csrf-" + u, false
		},
		BaseURL: base,
		Log:     slog.New(slog.DiscardHandler),
	})
	e.mux = http.NewServeMux()
	p.Mount(func(pattern string, h http.Handler) { e.mux.Handle(pattern, h) })
	return e
}

type resp struct {
	code int
	body string
	hdr  http.Header
}

func (e *env) do(r *http.Request, user string) resp {
	e.t.Helper()
	if user != "" {
		r.Header.Set("X-Test-User", user)
		r = r.WithContext(nav.WithData(r.Context(), nav.Data{SignedIn: true, CSRFToken: "csrf-" + user}))
	}
	w := httptest.NewRecorder()
	e.mux.ServeHTTP(w, r)
	return resp{code: w.Code, body: w.Body.String(), hdr: w.Header()}
}

func (e *env) get(path, user string) resp {
	e.t.Helper()
	return e.do(httptest.NewRequestWithContext(e.t.Context(), http.MethodGet, path, nil), user)
}

// post submits form values with the user's CSRF token (unless the form
// sets _csrf itself).
func (e *env) post(path, user string, form url.Values) resp {
	e.t.Helper()
	if form == nil {
		form = url.Values{}
	}
	if _, ok := form["_csrf"]; !ok {
		form.Set("_csrf", "csrf-"+user)
	}
	r := httptest.NewRequestWithContext(e.t.Context(), http.MethodPost, path, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return e.do(r, user)
}

func mustContain(t *testing.T, body string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Errorf("body lacks %q:\n%s", w, body)
		}
	}
}

func mustNotContain(t *testing.T, body string, bad ...string) {
	t.Helper()
	for _, b := range bad {
		if strings.Contains(body, b) {
			t.Errorf("body contains %q:\n%s", b, body)
		}
	}
}
