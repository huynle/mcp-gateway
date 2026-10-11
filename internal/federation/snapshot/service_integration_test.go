//go:build integration

package snapshot_test

import (
	"context"
	"errors"
	"net/url"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/store/migrations"
)

// Store-backed tests of the snapshot Service. They run against their own
// database (gateway_snapshot_test, created from GATEWAY_TEST_DATABASE_URL)
// so they never race the store package's TRUNCATE (quirk 01mepmn6), and
// retry the concurrent ALTER ROLE (quirk aihn7hjb).

const (
	testDB      = "gateway_snapshot_test"
	appPassword = "gateway-app-test"
	jobsPass    = "gateway-jobs-test"
)

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	raw := os.Getenv("GATEWAY_TEST_DATABASE_URL")
	if raw == "" {
		t.Skip("GATEWAY_TEST_DATABASE_URL not set; skipping integration test")
	}
	ctx := t.Context()
	admin, err := pgx.Connect(ctx, raw)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = admin.Close(ctx) }()
	var exists bool
	if err := admin.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, testDB).Scan(&exists); err != nil {
		t.Fatal(err)
	}
	if !exists {
		if _, err := admin.Exec(ctx, `CREATE DATABASE `+testDB); err != nil {
			t.Fatalf("create database: %v", err)
		}
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	u.Path = "/" + testDB
	superURL := u.String()
	if err := migrations.Up(ctx, superURL); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	super, err := pgx.Connect(ctx, superURL)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = super.Close(ctx) }()
	for _, stmt := range []string{
		"ALTER ROLE gateway_app LOGIN PASSWORD '" + appPassword + "'",
		"ALTER ROLE gateway_jobs LOGIN PASSWORD '" + jobsPass + "'",
		"TRUNCATE users, roles, role_assignments, mcp_servers CASCADE",
	} {
		if err := execRetrying(ctx, super, stmt); err != nil {
			t.Fatalf("%s: %v", stmt, err)
		}
	}
	appURL, jobsURL := *u, *u
	appURL.User = url.UserPassword("gateway_app", appPassword)
	jobsURL.User = url.UserPassword("gateway_jobs", jobsPass)
	st, err := store.New(ctx, appURL.String(), store.WithJobsURL(jobsURL.String()))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(st.Close)
	return st
}

func execRetrying(ctx context.Context, conn *pgx.Conn, stmt string) error {
	var err error
	for attempt := 0; attempt < 20; attempt++ {
		if _, err = conn.Exec(ctx, stmt); err == nil || !strings.Contains(err.Error(), "concurrently updated") {
			return err
		}
		time.Sleep(100 * time.Millisecond)
	}
	return err
}

func newUser(t *testing.T, st *store.Store, name string) string {
	t.Helper()
	var id string
	err := st.WithJobs(t.Context(), func(tx store.Tx) error {
		u := &store.User{DisplayName: name, Status: store.UserActive}
		if err := tx.Users().Create(t.Context(), u); err != nil {
			return err
		}
		id = u.ID
		return nil
	})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	return id
}

func newServer(t *testing.T, st *store.Store, owner, name string) string {
	t.Helper()
	s := &store.MCPServer{
		Name: name, URL: "https://" + name + ".example.com/mcp", OwnerUserID: owner,
		CredentialMode: store.MCPCredentialPerUser, AuthKind: store.MCPAuthNone,
	}
	if err := st.WithUser(t.Context(), owner, func(tx store.Tx) error {
		return store.CreateMCPServer(t.Context(), tx, s)
	}); err != nil {
		t.Fatalf("create server: %v", err)
	}
	return s.ID
}

// publish publishes serverID to a new role held by users (admin action).
func publish(t *testing.T, st *store.Store, serverID string, users ...string) {
	t.Helper()
	ctx := t.Context()
	err := st.WithJobs(ctx, func(tx store.Tx) error {
		r := &store.Role{Name: "readers-" + serverID[:8], Definition: []byte(`{}`)}
		if err := tx.Roles().Create(ctx, r); err != nil {
			return err
		}
		for _, u := range users {
			if err := tx.Roles().Assign(ctx, &store.RoleAssignment{UserID: u, RoleID: r.ID}); err != nil {
				return err
			}
		}
		return store.PublishMCPServer(ctx, tx, serverID, []string{r.ID})
	})
	if err != nil {
		t.Fatalf("publish: %v", err)
	}
}

// session is a fake upstream.
type session struct{ tools []*mcp.Tool }

func (s *session) Capabilities() *mcp.ServerCapabilities {
	return &mcp.ServerCapabilities{Tools: &mcp.ToolCapabilities{}}
}
func (s *session) ListTools(context.Context) ([]*mcp.Tool, error) { return s.tools, nil }
func (s *session) ListResources(context.Context) ([]*mcp.Resource, error) {
	return nil, errors.New("not advertised")
}
func (s *session) ListResourceTemplates(context.Context) ([]*mcp.ResourceTemplate, error) {
	return nil, errors.New("not advertised")
}
func (s *session) ListPrompts(context.Context) ([]*mcp.Prompt, error) {
	return nil, errors.New("not advertised")
}

func schema(props string, required ...string) map[string]any {
	m := map[string]any{"type": "object", "additionalProperties": false, "properties": map[string]any{}}
	for _, p := range strings.Split(props, ",") {
		if p == "" {
			continue
		}
		name, typ, _ := strings.Cut(p, ":")
		m["properties"].(map[string]any)[name] = map[string]any{"type": typ}
	}
	if len(required) > 0 {
		m["required"] = required
	}
	return m
}

func v1Tools() *session {
	return &session{tools: []*mcp.Tool{
		{Name: "search", Description: "search notes", InputSchema: schema("query:string", "query"),
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		{Name: "save", Description: "save a note", InputSchema: schema("text:string", "text")},
		{Name: "purge", Description: "delete everything", InputSchema: schema("")},
	}}
}

func v2Tools() *session {
	return &session{tools: []*mcp.Tool{
		// changed input schema: an extra "cmd" property.
		{Name: "search", Description: "search notes", InputSchema: schema("query:string,cmd:string", "query"),
			Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
		// unchanged.
		{Name: "save", Description: "save a note", InputSchema: schema("text:string", "text")},
		// purge removed; export added.
		{Name: "export", Description: "export", InputSchema: schema(""), Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true}},
	}}
}

func yes() *bool { b := true; return &b }

func TestIntegrationSnapshotOwnerLifecycle(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()
	alice := newUser(t, st, "alice")
	srv := newServer(t, st, alice, "notes")
	svc := snapshot.NewService(st)
	owner := snapshot.Actor{UserID: alice}

	if _, err := svc.Diff(ctx, owner, srv); !errors.Is(err, snapshot.ErrNoSnapshot) {
		t.Errorf("Diff before discovery = %v, want ErrNoSnapshot", err)
	}
	if _, err := svc.Approve(ctx, owner, srv, 1, snapshot.ReviewDecisions{}); !errors.Is(err, snapshot.ErrNoSnapshot) {
		t.Errorf("Approve before discovery = %v, want ErrNoSnapshot", err)
	}

	rec, err := svc.Create(ctx, owner, srv, v1Tools())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if rec.Version != 1 || rec.Status != store.MCPSnapshotPending || len(rec.Snapshot.Tools) != 3 {
		t.Fatalf("created = v%d %s %d tools", rec.Version, rec.Status, len(rec.Snapshot.Tools))
	}
	// Nothing is callable before approval.
	if _, err := svc.Current(ctx, owner, srv); !errors.Is(err, snapshot.ErrNoSnapshot) {
		t.Errorf("Current before approval = %v", err)
	}
	if _, _, err := svc.Allowed(ctx, owner, srv, "search", map[string]any{"query": "x"}); !errors.Is(err, snapshot.ErrToolNotReviewed) {
		t.Errorf("Allowed before approval = %v, want ErrToolNotReviewed", err)
	}
	d, err := svc.Diff(ctx, owner, srv)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(d.Added, []string{"purge", "save", "search"}) || d.FromVersion != 0 || d.ToVersion != 1 {
		t.Errorf("first diff = %+v", d)
	}

	// Approve with nothing decided: every tool listed, nothing enabled.
	cur, err := svc.Approve(ctx, owner, srv, 1, snapshot.ReviewDecisions{})
	if err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if cur.Status != store.MCPSnapshotApproved || cur.ApprovedBy != alice || len(cur.Review) != 3 {
		t.Errorf("approved = %+v", cur)
	}
	for name, tr := range cur.Review {
		if tr.Enabled {
			t.Errorf("%s enabled without a decision", name)
		}
	}
	if cur.Review["save"].Kind != snapshot.KindWrite || cur.Review["search"].Kind != snapshot.KindRead {
		t.Errorf("kinds = %+v", cur.Review)
	}
	if _, _, err := svc.Allowed(ctx, owner, srv, "search", map[string]any{"query": "x"}); !errors.Is(err, snapshot.ErrToolDisabled) {
		t.Errorf("Allowed of unapproved tool = %v, want ErrToolDisabled", err)
	}

	// Re-approve the same version enabling reads and save explicitly.
	if _, err := svc.Approve(ctx, owner, srv, 1, snapshot.ReviewDecisions{
		EnableReads: true, Tools: map[string]snapshot.Decision{"save": {Enabled: yes()}},
	}); err != nil {
		t.Fatalf("re-approve: %v", err)
	}
	if _, kind, err := svc.Allowed(ctx, owner, srv, "search", map[string]any{"query": "x"}); err != nil || kind != snapshot.KindRead {
		t.Errorf("Allowed(search) = %s, %v", kind, err)
	}
	if _, kind, err := svc.Allowed(ctx, owner, srv, "save", map[string]any{"text": "hi"}); err != nil || kind != snapshot.KindWrite {
		t.Errorf("Allowed(save) = %s, %v", kind, err)
	}
	if _, _, err := svc.Allowed(ctx, owner, srv, "purge", nil); !errors.Is(err, snapshot.ErrToolDisabled) {
		t.Errorf("Allowed(purge) = %v, want ErrToolDisabled (write not enabled by EnableReads)", err)
	}
	if _, _, err := svc.Allowed(ctx, owner, srv, "search", map[string]any{"query": "x", "cmd": "rm"}); !errors.Is(err, snapshot.ErrArgsInvalid) {
		t.Errorf("extra property = %v, want ErrArgsInvalid", err)
	}
	if _, _, err := svc.Allowed(ctx, owner, srv, "nope", nil); !errors.Is(err, snapshot.ErrToolNotReviewed) {
		t.Errorf("unknown tool = %v", err)
	}

	// Refresh with nothing changed adds no version.
	same, diff, err := svc.Refresh(ctx, owner, srv, v1Tools())
	if err != nil {
		t.Fatal(err)
	}
	if same.Version != 1 || !diff.Empty() {
		t.Errorf("unchanged refresh = v%d, diff %+v", same.Version, diff)
	}

	// Refresh with a changed schema, an added and a removed tool.
	pend, diff, err := svc.Refresh(ctx, owner, srv, v2Tools())
	if err != nil {
		t.Fatal(err)
	}
	if pend.Version != 2 || pend.Status != store.MCPSnapshotPending {
		t.Errorf("refresh = v%d %s", pend.Version, pend.Status)
	}
	if !slices.Equal(diff.Added, []string{"export"}) || !slices.Equal(diff.Removed, []string{"purge"}) ||
		len(diff.Changed) != 1 || diff.Changed[0].Name != "search" ||
		!slices.Equal(diff.Changed[0].Fields, []string{snapshot.FieldInputSchema}) || diff.FromVersion != 1 || diff.ToVersion != 2 {
		t.Errorf("refresh diff = %+v", diff)
	}
	if d2, err := svc.Diff(ctx, owner, srv); err != nil || d2.ToVersion != 2 || len(d2.Changed) != 1 {
		t.Errorf("Diff = %+v, %v", d2, err)
	}
	// Until approved, calls are still served from the pinned v1.
	if _, _, err := svc.Allowed(ctx, owner, srv, "search", map[string]any{"query": "x", "cmd": "rm"}); !errors.Is(err, snapshot.ErrArgsInvalid) {
		t.Errorf("v2 args before approval = %v, want ErrArgsInvalid", err)
	}
	// Approving an older pending version is refused.
	if _, err := svc.Approve(ctx, owner, srv, 3, snapshot.ReviewDecisions{}); !errors.Is(err, snapshot.ErrStaleVersion) {
		t.Errorf("approve unknown version = %v, want ErrStaleVersion", err)
	}

	cur, err = svc.Approve(ctx, owner, srv, 2, snapshot.ReviewDecisions{})
	if err != nil {
		t.Fatalf("approve v2: %v", err)
	}
	if _, _, err := svc.Allowed(ctx, owner, srv, "search", map[string]any{"query": "x"}); !errors.Is(err, snapshot.ErrToolDisabled) {
		t.Errorf("changed tool after approval = %v, want ErrToolDisabled until reviewed", err)
	}
	if _, _, err := svc.Allowed(ctx, owner, srv, "save", map[string]any{"text": "hi"}); err != nil {
		t.Errorf("unchanged tool lost its review: %v", err)
	}
	if _, _, err := svc.Allowed(ctx, owner, srv, "export", nil); !errors.Is(err, snapshot.ErrToolDisabled) {
		t.Errorf("added tool = %v, want ErrToolDisabled", err)
	}
	if _, _, err := svc.Allowed(ctx, owner, srv, "purge", nil); !errors.Is(err, snapshot.ErrToolNotReviewed) {
		t.Errorf("removed tool = %v, want ErrToolNotReviewed", err)
	}
	if _, ok := cur.Review["purge"]; ok {
		t.Error("removed tool still in the review")
	}
	// Re-enable the changed tool: the new schema is now the pinned one.
	if _, err := svc.Approve(ctx, owner, srv, 2, snapshot.ReviewDecisions{Tools: map[string]snapshot.Decision{"search": {Enabled: yes()}}}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.Allowed(ctx, owner, srv, "search", map[string]any{"query": "x", "cmd": "ls"}); err != nil {
		t.Errorf("re-enabled search with v2 args = %v", err)
	}
}

func TestIntegrationSnapshotPublishedServerReview(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()
	alice := newUser(t, st, "alice")
	bob := newUser(t, st, "bob")
	carol := newUser(t, st, "carol")
	admin := newUser(t, st, "admin")
	srv := newServer(t, st, alice, "shared")
	svc := snapshot.NewService(st)
	owner := snapshot.Actor{UserID: alice}

	if _, err := svc.Create(ctx, owner, srv, v1Tools()); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Approve(ctx, owner, srv, 1, snapshot.ReviewDecisions{EnableReads: true}); err != nil {
		t.Fatalf("owner approve while private: %v", err)
	}
	publish(t, st, srv, bob)

	// The owner may still discover (pending), but no longer approve.
	if _, _, err := svc.Refresh(ctx, owner, srv, v2Tools()); err != nil {
		t.Fatalf("owner refresh of published server: %v", err)
	}
	if _, err := svc.Approve(ctx, owner, srv, 2, snapshot.ReviewDecisions{EnableReads: true}); !errors.Is(err, snapshot.ErrReviewNotAllowed) {
		t.Errorf("owner approve of published server = %v, want ErrReviewNotAllowed", err)
	}
	// Nor a user it is published to.
	if _, err := svc.Approve(ctx, snapshot.Actor{UserID: bob}, srv, 2, snapshot.ReviewDecisions{}); !errors.Is(err, snapshot.ErrReviewNotAllowed) {
		t.Errorf("reader approve = %v, want ErrReviewNotAllowed", err)
	}
	// (A refresh identical to the latest snapshot writes nothing; a
	// different one is an insert, which only the owner may do.)
	if _, _, err := svc.Refresh(ctx, snapshot.Actor{UserID: bob}, srv, v1Tools()); !errors.Is(err, snapshot.ErrReviewNotAllowed) {
		t.Errorf("reader refresh = %v, want ErrReviewNotAllowed", err)
	}
	// The refused approval changed nothing: v1 is still current.
	if cur, err := svc.Current(ctx, owner, srv); err != nil || cur.Version != 1 {
		t.Fatalf("current after refused approval = %+v, %v", cur, err)
	}

	// bob sees the published server and may call its approved reads; carol
	// cannot see it at all.
	if _, _, err := svc.Allowed(ctx, snapshot.Actor{UserID: bob}, srv, "search", map[string]any{"query": "x"}); err != nil {
		t.Errorf("bob Allowed = %v", err)
	}
	if _, _, err := svc.Allowed(ctx, snapshot.Actor{UserID: carol}, srv, "search", map[string]any{"query": "x"}); !errors.Is(err, snapshot.ErrToolNotReviewed) {
		t.Errorf("carol Allowed = %v, want ErrToolNotReviewed", err)
	}

	// The admin path (WithJobs) approves.
	cur, err := svc.Approve(ctx, snapshot.Actor{UserID: admin, Admin: true}, srv, 2, snapshot.ReviewDecisions{
		Tools: map[string]snapshot.Decision{"export": {Enabled: yes()}},
	})
	if err != nil {
		t.Fatalf("admin approve: %v", err)
	}
	if cur.Version != 2 || cur.ApprovedBy != admin || cur.Review["export"].ReviewedBy != admin {
		t.Errorf("admin approval = v%d by %q, export %+v", cur.Version, cur.ApprovedBy, cur.Review["export"])
	}
	if _, _, err := svc.Allowed(ctx, snapshot.Actor{UserID: bob}, srv, "export", nil); err != nil {
		t.Errorf("bob Allowed(export) after admin approval = %v", err)
	}
	if _, _, err := svc.Allowed(ctx, snapshot.Actor{UserID: bob}, srv, "search", map[string]any{"query": "x"}); !errors.Is(err, snapshot.ErrToolDisabled) {
		t.Errorf("bob Allowed(changed search) = %v, want ErrToolDisabled", err)
	}
	// System actor (connector / jobs) reads through WithJobs.
	if _, _, err := svc.Allowed(ctx, snapshot.System(), srv, "export", nil); err != nil {
		t.Errorf("system Allowed = %v", err)
	}
	if _, err := svc.Current(ctx, snapshot.Actor{}, srv); !errors.Is(err, snapshot.ErrNoActor) {
		t.Errorf("empty actor = %v, want ErrNoActor", err)
	}
}
