package gatewaytools

import (
	"context"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	isettings "github.com/huynle/mcp-gateway/internal/settings"
)

type fakeRates struct{ snap isettings.Snapshot }

func (r *fakeRates) Snapshot(context.Context) isettings.Snapshot { return r.snap }
func (r *fakeRates) Limits(_ context.Context, u, a string) (int, int) {
	x := r.snap.UserDefault
	if z := r.snap.Users[u]; z.Admin != nil {
		x = *z.Admin
	}
	if z := r.snap.Users[u]; z.Self != nil && *z.Self < x {
		x = *z.Self
	}
	y := r.snap.AppDefault
	if n, ok := r.snap.Apps[a]; ok {
		y = n
	}
	return x, y
}
func (r *fakeRates) IsAdmin(_ context.Context, u string) bool { return r.snap.Admins[u] }
func (r *fakeRates) SetSelf(_ context.Context, u string, n *int) error {
	x := r.snap.Users[u]
	x.Self = n
	r.snap.Users[u] = x
	return nil
}
func (r *fakeRates) SetOrg(_ context.Context, _ string, u, a int) error {
	r.snap.UserDefault = u
	r.snap.AppDefault = a
	return nil
}
func (r *fakeRates) SetApp(_ context.Context, _, a string, n *int) error {
	if n == nil {
		delete(r.snap.Apps, a)
	} else {
		r.snap.Apps[a] = *n
	}
	return nil
}
func (r *fakeRates) SetUserAdmin(_ context.Context, _, u string, n *int) error {
	x := r.snap.Users[u]
	x.Admin = n
	r.snap.Users[u] = x
	return nil
}

func TestRateSettingsTools(t *testing.T) {
	w := newWorld(t)
	r := &fakeRates{snap: isettings.Snapshot{UserDefault: 60, AppDefault: 600, Apps: map[string]int{"brain": 1000}, Users: map[string]isettings.UserLimit{}, Admins: map[string]bool{alice: true}}}
	w.conn.d.Rates = r
	w.reg = connectors.NewRegistry()
	if err := w.conn.Register(w.reg); err != nil {
		t.Fatal(err)
	}
	if got := len(w.reg.List()); got != 12 {
		t.Fatalf("tools=%d, want 12", got)
	}
	out := w.ok(alice, ToolGetRateLimits, map[string]any{"app": "brain"})
	if out["effective_user_per_min"] != float64(60) || out["effective_app_per_min"] != float64(1000) {
		t.Fatalf("limits=%v", out)
	}
	w.ok(alice, ToolSetOrgRateLimits, map[string]any{"user_per_min": float64(600), "app_per_min": float64(3000)})
	w.ok(alice, ToolSetMyRateLimit, map[string]any{"per_min": float64(500)})
	if u, a := r.Limits(t.Context(), alice, "gmail"); u != 500 || a != 3000 {
		t.Fatalf("changed=%d/%d", u, a)
	}
	if _, err := w.call(bob, ToolSetOrgRateLimits, map[string]any{"user_per_min": float64(1), "app_per_min": float64(1)}); err == nil {
		t.Fatal("nonadmin changed org settings")
	}
}
