package permissions_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/permissions"
)

// memStore is an in-memory permissions.Store.
type memStore struct {
	mu      sync.Mutex
	may     map[string]bool
	enabled map[string]bool
	err     error
}

func newMemStore() *memStore {
	return &memStore{may: map[string]bool{}, enabled: map[string]bool{}}
}

func (m *memStore) MayAddServers(_ context.Context, userID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.may[userID], m.err
}

func (m *memStore) GatewayToolsEnabled(_ context.Context, userID string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.enabled[userID], m.err
}

func (m *memStore) SetGatewayToolsEnabled(_ context.Context, userID string, on bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.enabled[userID] = on
	return nil
}

type recorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *recorder) Record(_ context.Context, ev audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
	return nil
}

func TestCanAddServers(t *testing.T) {
	st := newMemStore()
	st.may["builder"] = true
	svc := permissions.New(st, permissions.Options{})
	ctx := t.Context()
	if !svc.CanAddServers(ctx, "builder") {
		t.Error("a user whose role may add servers was refused")
	}
	if svc.CanAddServers(ctx, "member") {
		t.Error("a user without the permission was allowed")
	}
	if svc.CanAddServers(ctx, "") {
		t.Error("no user was allowed")
	}
}

func TestCanAddServersFailsClosed(t *testing.T) {
	st := newMemStore()
	st.may["builder"] = true
	st.err = errors.New("database down")
	svc := permissions.New(st, permissions.Options{})
	if svc.CanAddServers(t.Context(), "builder") {
		t.Error("allowed while the store fails")
	}
	if svc.GatewayToolsActive(t.Context(), "builder") {
		t.Error("gateway tools active while the store fails")
	}
}

func TestSetGatewayToolsNeedsPermissionToTurnOn(t *testing.T) {
	st := newMemStore()
	rec := &recorder{}
	svc := permissions.New(st, permissions.Options{Audit: rec})
	ctx := t.Context()

	err := svc.SetGatewayToolsEnabled(ctx, "member", true)
	if !errors.Is(err, permissions.ErrNotPermitted) {
		t.Fatalf("turn on without permission = %v, want ErrNotPermitted", err)
	}
	if st.enabled["member"] {
		t.Error("toggle stored without permission")
	}
	if len(rec.events) != 0 {
		t.Errorf("refused toggle audited as a change: %+v", rec.events)
	}
	// Turning it off is always allowed (e.g. after the role was taken away).
	st.enabled["member"] = true
	if err := svc.SetGatewayToolsEnabled(ctx, "member", false); err != nil {
		t.Fatalf("turn off without permission: %v", err)
	}
	if st.enabled["member"] {
		t.Error("toggle still on")
	}
}

func TestSetGatewayToolsPersistsAndAudits(t *testing.T) {
	st := newMemStore()
	st.may["builder"] = true
	rec := &recorder{}
	svc := permissions.New(st, permissions.Options{Audit: rec})
	ctx := t.Context()

	for _, on := range []bool{true, false} {
		if err := svc.SetGatewayToolsEnabled(ctx, "builder", on); err != nil {
			t.Fatalf("set %v: %v", on, err)
		}
		got, err := svc.GatewayToolsEnabled(ctx, "builder")
		if err != nil || got != on {
			t.Fatalf("GatewayToolsEnabled = %v, %v; want %v", got, err, on)
		}
	}
	if len(rec.events) != 2 {
		t.Fatalf("audit events = %d, want 2", len(rec.events))
	}
	want := []string{"true", "false"}
	for i, ev := range rec.events {
		if ev.UserID != "builder" || ev.Outcome != "succeeded" || ev.Tool != "" {
			t.Errorf("event %d = %+v", i, ev)
		}
		if ev.ResourceIdentity["action"] != permissions.ActionGatewayToolsToggled || ev.ResourceIdentity["enabled"] != want[i] {
			t.Errorf("event %d resource = %v", i, ev.ResourceIdentity)
		}
	}
	if permissions.ActionGatewayToolsToggled != "user.gateway_tools_toggled" {
		t.Errorf("action = %q", permissions.ActionGatewayToolsToggled)
	}
}

// Active = permitted and switched on: losing the permission switches the
// tools off without touching the stored setting.
func TestGatewayToolsActive(t *testing.T) {
	st := newMemStore()
	st.may["builder"] = true
	svc := permissions.New(st, permissions.Options{})
	ctx := t.Context()
	if svc.GatewayToolsActive(ctx, "builder") {
		t.Error("active before the user switched it on")
	}
	if err := svc.SetGatewayToolsEnabled(ctx, "builder", true); err != nil {
		t.Fatal(err)
	}
	if !svc.GatewayToolsActive(ctx, "builder") {
		t.Error("not active when permitted and on")
	}
	st.may["builder"] = false
	if svc.GatewayToolsActive(ctx, "builder") {
		t.Error("still active after the permission was taken away")
	}
	if on, _ := svc.GatewayToolsEnabled(ctx, "builder"); !on {
		t.Error("the stored setting changed when the permission went away")
	}
}
