package policy_test

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/observability"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/policy/policytest"
	"github.com/huynle/mcp-gateway/internal/store"
)

// memRecorder collects audit events.
type memRecorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (m *memRecorder) Record(_ context.Context, ev audit.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, ev)
	return nil
}

func (m *memRecorder) last() audit.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.events) == 0 {
		return audit.Event{}
	}
	return m.events[len(m.events)-1]
}

type fixtureSvc struct {
	svc   *policy.Service
	st    *policytest.MemStore
	rec   *memRecorder
	logs  *bytes.Buffer
	clock *time.Time
}

func newService(t *testing.T) fixtureSvc {
	t.Helper()
	st := policytest.NewMemStore()
	st.PutRole(policy.Role{Name: "member", Rules: []policy.ToolRule{
		{App: "fake", Tool: "*", Outcome: policy.OutcomeDeny},
		{App: "fake", Tool: "list_items", Outcome: policy.OutcomeAllow},
		{App: "fake", Tool: "create_item", Outcome: policy.OutcomeConfirm},
	}})
	st.PutRole(policy.Role{Name: "admin"})
	st.Assign("u-alice", "member")
	st.Assign("u-alice", "admin")
	rec := &memRecorder{}
	logs := &bytes.Buffer{}
	now := time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC)
	svc, err := policy.New(st, policy.Options{
		Audit:   rec,
		Metrics: observability.NewMetrics(),
		Log:     slog.New(slog.NewTextHandler(logs, nil)),
		MaxAge:  10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	svc.SetClock(func() time.Time { return now })
	return fixtureSvc{svc: svc, st: st, rec: rec, logs: logs, clock: &now}
}

func listItems() connectors.Tool  { return connectors.Tool{App: "fake", Name: "list_items", Kind: connectors.KindRead} }
func createItem() connectors.Tool { return connectors.Tool{App: "fake", Name: "create_item", Kind: connectors.KindWrite} }

func TestServiceCompilesAndPersistsFirstVersion(t *testing.T) {
	f := newService(t)
	ctx := context.Background()
	c, err := f.svc.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if c.Version == "" || c.ID == "" {
		t.Fatalf("current = %+v, want a version and a persisted ID", c)
	}
	versions := f.st.Versions()
	if len(versions) != 1 || versions[0].Hash != c.Version || versions[0].Cedar != c.Cedar || versions[0].CreatedBy != "" {
		t.Errorf("stored versions = %+v", versions)
	}
	// A second Current within MaxAge neither reloads nor re-persists.
	if _, err := f.svc.Current(ctx); err != nil {
		t.Fatal(err)
	}
	if f.st.Loads() != 1 || len(f.st.Versions()) != 1 {
		t.Errorf("loads = %d, versions = %d, want 1 and 1", f.st.Loads(), len(f.st.Versions()))
	}
}

func TestServiceDecideFillsRolesAndCounts(t *testing.T) {
	f := newService(t)
	ctx := context.Background()
	d, err := f.svc.Decide(ctx, policy.Input{UserID: "u-alice", Tool: listItems(), AccountLabel: "company"})
	if err != nil {
		t.Fatal(err)
	}
	if d.Outcome != policy.OutcomeAllow {
		t.Errorf("alice list_items = %+v", d)
	}
	d, _ = f.svc.Decide(ctx, policy.Input{UserID: "u-alice", Tool: createItem(), AccountLabel: "company"})
	if d.Outcome != policy.OutcomeConfirm {
		t.Errorf("alice create_item = %+v", d)
	}
	// Roles passed by the caller are ignored: the service knows the
	// assignments (a token cannot claim a role).
	d, _ = f.svc.Decide(ctx, policy.Input{UserID: "u-nobody", Roles: []string{"member"}, Tool: listItems(), AccountLabel: "company"})
	if d.Outcome != policy.OutcomeHidden {
		t.Errorf("nobody with claimed roles = %+v", d)
	}
	ok, err := f.svc.Visible(ctx, policy.Input{UserID: "u-alice", Tool: listItems()})
	if err != nil || !ok {
		t.Errorf("Visible alice list_items = %v, %v", ok, err)
	}
	ok, _ = f.svc.Visible(ctx, policy.Input{UserID: "u-nobody", Tool: listItems()})
	if ok {
		t.Error("Visible nobody list_items = true")
	}
}

func TestServiceSaveRoleCreatesVersionAndAudits(t *testing.T) {
	f := newService(t)
	ctx := context.Background()
	before, _ := f.svc.Current(ctx)

	// A stub approval bound to the version in force now.
	approval := struct{ PolicyVersion string }{PolicyVersion: before.Version}

	role, err := f.svc.Role(ctx, "member")
	if err != nil {
		t.Fatal(err)
	}
	role.Rules = append(role.Rules, policy.ToolRule{App: "FAKE", Tool: "Get_Item", Outcome: "ALLOW"})
	role.Description = "Members"
	if err := f.svc.SaveRole(ctx, "u-admin", role); err != nil {
		t.Fatal(err)
	}
	after, _ := f.svc.Current(ctx)
	if after.Version == before.Version {
		t.Fatal("role change kept the policy version")
	}
	if approval.PolicyVersion == after.Version {
		t.Error("approval bound to the old version still matches")
	}
	versions := f.st.Versions()
	if len(versions) != 2 || versions[1].Hash != after.Version || versions[1].CreatedBy != "u-admin" {
		t.Errorf("versions = %+v", versions)
	}
	if after.ID == "" || after.ID == before.ID {
		t.Errorf("after.ID = %q, before.ID = %q", after.ID, before.ID)
	}
	// The saved role is normalised and effective at once.
	saved, _ := f.svc.Role(ctx, "member")
	if saved.Description != "Members" || len(saved.Rules) != 4 || saved.Rules[2].Tool != "get_item" {
		t.Errorf("saved role = %+v", saved)
	}
	d, _ := f.svc.Decide(ctx, policy.Input{UserID: "u-alice", Tool: connectors.Tool{App: "fake", Name: "get_item", Kind: connectors.KindRead}, AccountLabel: "company"})
	if d.Outcome != policy.OutcomeAllow || d.Version != after.Version {
		t.Errorf("get_item after save = %+v", d)
	}
	ev := f.rec.last()
	if ev.UserID != "u-admin" || ev.ResourceIdentity["action"] != "role_saved" || ev.ResourceIdentity["role"] != "member" || ev.PolicyVersion != after.Version || ev.Outcome != "succeeded" || ev.Tool != "" {
		t.Errorf("audit event = %+v", ev)
	}
}

func TestServiceSaveRoleRejectsInvalid(t *testing.T) {
	f := newService(t)
	ctx := context.Background()
	err := f.svc.SaveRole(ctx, "u-admin", policy.Role{Name: "Bad Name"})
	if !errors.Is(err, policy.ErrInvalidRole) {
		t.Errorf("invalid name: %v", err)
	}
	err = f.svc.SaveRole(ctx, "u-admin", policy.Role{Name: "x", Rules: []policy.ToolRule{{App: "fake", Tool: "*", Outcome: "sometimes"}}})
	if !errors.Is(err, policy.ErrInvalidRole) {
		t.Errorf("invalid outcome: %v", err)
	}
	if len(f.st.Versions()) > 1 || len(f.rec.events) != 0 {
		t.Errorf("rejected saves left traces: versions=%d events=%d", len(f.st.Versions()), len(f.rec.events))
	}
}

func TestServiceCreateAndDeleteRole(t *testing.T) {
	f := newService(t)
	ctx := context.Background()
	if err := f.svc.SaveRole(ctx, "u-admin", policy.Role{Name: "auditor", Rules: []policy.ToolRule{{App: "fake", Tool: "*", Outcome: policy.OutcomeAllow}}}); err != nil {
		t.Fatal(err)
	}
	roles, err := f.svc.Roles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range roles {
		names = append(names, r.Name)
	}
	if strings.Join(names, ",") != "admin,auditor,member" {
		t.Errorf("roles = %v", names)
	}
	// Assigned roles cannot be deleted.
	if err := f.svc.DeleteRole(ctx, "u-admin", "member"); !errors.Is(err, policy.ErrRoleAssigned) {
		t.Errorf("delete assigned role: %v", err)
	}
	if err := f.svc.DeleteRole(ctx, "u-admin", "ghost"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("delete unknown role: %v", err)
	}
	v1, _ := f.svc.Current(ctx)
	if err := f.svc.DeleteRole(ctx, "u-admin", "auditor"); err != nil {
		t.Fatal(err)
	}
	v2, _ := f.svc.Current(ctx)
	if v1.Version == v2.Version {
		t.Error("deleting a role kept the version")
	}
	if _, err := f.svc.Role(ctx, "auditor"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("deleted role still readable: %v", err)
	}
	if ev := f.rec.last(); ev.ResourceIdentity["action"] != "role_deleted" || ev.ResourceIdentity["role"] != "auditor" {
		t.Errorf("audit = %+v", ev)
	}
}

func TestServiceDefaultRole(t *testing.T) {
	f := newService(t)
	ctx := context.Background()
	if err := f.svc.SetDefaultRole(ctx, "u-admin", "ghost"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("unknown default: %v", err)
	}
	if err := f.svc.SetDefaultRole(ctx, "u-admin", "member"); err != nil {
		t.Fatal(err)
	}
	name, err := f.svc.DefaultRole(ctx)
	if err != nil || name != "member" {
		t.Errorf("DefaultRole = %q, %v", name, err)
	}
	roles, _ := f.svc.Roles(ctx)
	for _, r := range roles {
		if r.IsDefault != (r.Name == "member") {
			t.Errorf("%s IsDefault = %v", r.Name, r.IsDefault)
		}
	}
	if ev := f.rec.last(); ev.ResourceIdentity["action"] != "default_role_set" || ev.ResourceIdentity["role"] != "member" {
		t.Errorf("audit = %+v", ev)
	}
}

func TestServiceRefreshesOnAgeInvalidateAndUnknownUser(t *testing.T) {
	f := newService(t)
	ctx := context.Background()
	if _, err := f.svc.Current(ctx); err != nil {
		t.Fatal(err)
	}
	// An assignment made behind the service's back (identity module).
	f.st.Assign("u-bob", "member")
	d, _ := f.svc.Decide(ctx, policy.Input{UserID: "u-alice", Tool: listItems(), AccountLabel: "company"})
	if d.Outcome != policy.OutcomeAllow || f.st.Loads() != 1 {
		t.Fatalf("known user forced a reload: loads=%d", f.st.Loads())
	}
	// Unknown user: refreshed at once (bounded to once per second).
	d, _ = f.svc.Decide(ctx, policy.Input{UserID: "u-bob", Tool: listItems(), AccountLabel: "company"})
	if d.Outcome != policy.OutcomeAllow {
		t.Errorf("bob after assignment = %+v (loads=%d)", d, f.st.Loads())
	}
	loads := f.st.Loads()
	d, _ = f.svc.Decide(ctx, policy.Input{UserID: "u-carol", Tool: listItems(), AccountLabel: "company"})
	if d.Outcome != policy.OutcomeHidden || f.st.Loads() != loads {
		t.Errorf("second unknown user within a second reloaded: loads=%d", f.st.Loads())
	}
	// Age: after MaxAge the next read reloads and sees new data.
	f.st.Assign("u-carol", "member")
	*f.clock = f.clock.Add(11 * time.Second)
	d, _ = f.svc.Decide(ctx, policy.Input{UserID: "u-carol", Tool: listItems(), AccountLabel: "company"})
	if d.Outcome != policy.OutcomeAllow {
		t.Errorf("carol after MaxAge = %+v", d)
	}
	// Invalidate: immediate.
	f.st.Assign("u-dave", "member")
	f.svc.Invalidate()
	d, _ = f.svc.Decide(ctx, policy.Input{UserID: "u-dave", Tool: listItems(), AccountLabel: "company"})
	if d.Outcome != policy.OutcomeAllow {
		t.Errorf("dave after Invalidate = %+v", d)
	}
	// Each distinct version got a row, assignments included.
	if n := len(f.st.Versions()); n != 4 {
		t.Errorf("versions = %d, want 4 (initial + bob + carol + dave)", n)
	}
}

func TestServiceLogsRestrictionWarnings(t *testing.T) {
	f := newService(t)
	f.st.PutRestriction(policy.UserRestriction{UserID: "u-alice", Rules: []policy.ToolRule{{App: "fake", Tool: "*", Outcome: policy.OutcomeAllow}}})
	if _, err := f.svc.Current(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.logs.String(), "policy.restriction_ignored") || !strings.Contains(f.logs.String(), "u-alice") {
		t.Errorf("warning not logged:\n%s", f.logs.String())
	}
}

func TestServiceLoadFailureKeepsLastGood(t *testing.T) {
	f := newService(t)
	ctx := context.Background()
	first, err := f.svc.Current(ctx)
	if err != nil {
		t.Fatal(err)
	}
	f.st.FailLoads(errors.New("db down"))
	f.svc.Invalidate()
	c, err := f.svc.Current(ctx)
	if err != nil || c.Version != first.Version {
		t.Errorf("Current with a failing store = %v, %v; want the last good policy", c, err)
	}
	d, err := f.svc.Decide(ctx, policy.Input{UserID: "u-alice", Tool: listItems(), AccountLabel: "company"})
	if err != nil || d.Outcome != policy.OutcomeAllow {
		t.Errorf("Decide with a failing store = %+v, %v", d, err)
	}
	// Without any policy ever loaded, the failure surfaces.
	st := policytest.NewMemStore()
	st.FailLoads(errors.New("db down"))
	svc, _ := policy.New(st, policy.Options{})
	if _, err := svc.Current(ctx); err == nil {
		t.Error("Current without a last good policy succeeded")
	}
	if d, err := svc.Decide(ctx, policy.Input{UserID: "u", Tool: listItems()}); err == nil || d.Outcome != policy.OutcomeDeny {
		t.Errorf("Decide without a policy = %+v, %v; want deny and an error", d, err)
	}
}
