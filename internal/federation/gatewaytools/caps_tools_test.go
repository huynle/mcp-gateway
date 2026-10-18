package gatewaytools

import (
	"context"
	"maps"
	"slices"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/caps"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/permissions"
	"github.com/huynle/mcp-gateway/internal/policy"
	isettings "github.com/huynle/mcp-gateway/internal/settings"
)

type fakeCaps struct {
	org    caps.Values
	users  map[string]caps.Values
	admins map[string]bool
	usage  caps.Values
	sets   []string
}

func (f *fakeCaps) eff(user string) caps.Values {
	out := maps.Clone(caps.Builtin)
	maps.Copy(out, f.org)
	maps.Copy(out, f.users[user])
	return out
}
func (f *fakeCaps) Effective(_ context.Context, u string) caps.Values { return f.eff(u) }
func (f *fakeCaps) Usage(context.Context, string) (caps.Values, error) {
	return maps.Clone(f.usage), nil
}
func (f *fakeCaps) Defaults() caps.Values { return maps.Clone(caps.Builtin) }
func (f *fakeCaps) CapsSnapshot(context.Context) isettings.CapsSnapshot {
	return isettings.CapsSnapshot{Org: maps.Clone(f.org), Users: maps.Clone(f.users), Admins: f.admins}
}
func (f *fakeCaps) IsAdmin(_ context.Context, u string) bool { return f.admins[u] }
func patchInto(v caps.Values, p caps.Patch) caps.Values {
	if v == nil {
		v = caps.Values{}
	}
	for r, n := range p {
		if n == nil {
			delete(v, r)
		} else {
			v[r] = *n
		}
	}
	return v
}
func (f *fakeCaps) SetOrg(_ context.Context, actor string, p caps.Patch) error {
	if !f.admins[actor] {
		return isettings.ErrNotAdmin
	}
	f.sets = append(f.sets, "org")
	f.org = patchInto(f.org, p)
	return nil
}
func (f *fakeCaps) SetUser(_ context.Context, actor, user string, p caps.Patch) error {
	if !f.admins[actor] {
		return isettings.ErrNotAdmin
	}
	f.sets = append(f.sets, "user:"+user)
	f.users[user] = patchInto(f.users[user], p)
	return nil
}

func capsWorld(t *testing.T) (*world, *fakeCaps) {
	w := newWorld(t)
	f := &fakeCaps{org: caps.Values{}, users: map[string]caps.Values{}, admins: map[string]bool{alice: true}, usage: caps.Values{caps.Servers: 2}}
	w.conn.d.Caps = f
	w.reg = connectors.NewRegistry()
	if err := w.conn.Register(w.reg); err != nil {
		t.Fatal(err)
	}
	return w, f
}

func TestLimitToolsRegisteredAndConfirm(t *testing.T) {
	w, _ := capsWorld(t)
	for _, name := range []string{ToolGetLimits, ToolSetOrgLimits, ToolSetUserLimits} {
		tool, ok := w.reg.Get(App + "." + name)
		if !ok {
			t.Fatalf("%s not registered", name)
		}
		if name == ToolGetLimits && tool.Kind != connectors.KindRead || name != ToolGetLimits && tool.Kind != connectors.KindWrite {
			t.Errorf("%s kind %s", name, tool.Kind)
		}
	}
	for _, name := range []string{ToolSetOrgLimits, ToolSetUserLimits} {
		if !slices.Contains(policy.GatewayConfirmTools, name) {
			t.Errorf("%s does not always require approval", name)
		}
	}
	// The setters are hidden from members, like the admin rate tools.
	ps := newFakePermStore()
	ps.set(alice, true, true)
	ps.set(bob, true, true)
	gate := NewGate(permissions.New(ps, permissions.Options{}), GateOptions{TTL: time.Nanosecond, Admin: admins{alice: true}})
	d := gate.Decider(&allowAll{})
	for _, name := range []string{ToolSetOrgLimits, ToolSetUserLimits} {
		if ok, _ := d.Visible(t.Context(), policy.Input{UserID: bob, Tool: gwTool(name)}); ok {
			t.Errorf("%s visible to a member", name)
		}
		if ok, _ := d.Visible(t.Context(), policy.Input{UserID: alice, Tool: gwTool(name)}); !ok {
			t.Errorf("%s hidden from an admin", name)
		}
	}
	if ok, _ := d.Visible(t.Context(), policy.Input{UserID: bob, Tool: gwTool(ToolGetLimits)}); !ok {
		t.Error("get_limits hidden from a member")
	}
}

func TestGetLimits(t *testing.T) {
	w, f := capsWorld(t)
	f.users[bob] = caps.Values{caps.Tunnels: 1}
	out := w.ok(bob, ToolGetLimits, nil)
	lim, _ := out["limits"].(map[string]any)
	use, _ := out["usage"].(map[string]any)
	if lim["tunnels"] != float64(1) || lim["servers"] != float64(10) || use["servers"] != float64(2) || out["admin"] != false {
		t.Fatalf("get_limits = %v", out)
	}
	if _, ok := out["user_overrides"]; ok {
		t.Error("member sees overrides")
	}
	if class, _ := w.fail(bob, ToolGetLimits, map[string]any{"user_id": alice}); class != "not_permitted" {
		t.Errorf("member reading another user = %s", class)
	}
	out = w.ok(alice, ToolGetLimits, map[string]any{"user_id": bob})
	if lim, _ := out["limits"].(map[string]any); lim["tunnels"] != float64(1) || out["user_id"] != bob {
		t.Fatalf("admin view of bob = %v", out)
	}
	if _, ok := out["user_overrides"].(map[string]any); !ok {
		t.Errorf("admin sees no overrides: %v", out)
	}
}

func TestSetLimits(t *testing.T) {
	w, f := capsWorld(t)
	w.ok(alice, ToolSetOrgLimits, map[string]any{"servers": float64(3), "pending_approvals": float64(0)})
	if f.org[caps.Servers] != 3 || f.org[caps.PendingApprovals] != 0 {
		t.Fatalf("org = %v", f.org)
	}
	w.ok(alice, ToolSetOrgLimits, map[string]any{"clear": []any{"servers"}})
	if _, ok := f.org[caps.Servers]; ok {
		t.Fatal("servers not cleared")
	}
	w.ok(alice, ToolSetUserLimits, map[string]any{"user_id": bob, "tunnels": float64(0), "connections_total": float64(40)})
	if f.users[bob][caps.Tunnels] != 0 || f.users[bob][caps.ConnectionsTotal] != 40 {
		t.Fatalf("bob = %v", f.users[bob])
	}
	for _, args := range []map[string]any{
		{},
		{"servers": float64(-1)},
		{"servers": float64(100001)},
		{"servers": float64(1.5)},
		{"servers": float64(1), "clear": []any{"servers"}},
		{"clear": []any{"users"}},
	} {
		if class, _ := w.fail(alice, ToolSetOrgLimits, args); class != "args_invalid" {
			t.Errorf("%v = %s, want args_invalid", args, class)
		}
	}
	if class, _ := w.fail(alice, ToolSetUserLimits, map[string]any{"user_id": "bob", "servers": float64(1)}); class != "args_invalid" {
		t.Errorf("bad user id = %s", class)
	}
	before := len(f.sets)
	if _, err := w.call(bob, ToolSetOrgLimits, map[string]any{"servers": float64(1)}); err == nil {
		t.Error("member changed org limits")
	}
	if _, err := w.call(bob, ToolSetUserLimits, map[string]any{"user_id": bob, "servers": float64(100)}); err == nil {
		t.Error("member raised its own limit")
	}
	if len(f.sets) != before {
		t.Error("member change reached the settings")
	}
}
