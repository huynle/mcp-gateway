package gatewaytools

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/permissions"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// allowAll is the policy below the gate: it allows and lists everything,
// so whatever is hidden was hidden by the gate.
type allowAll struct{ calls int }
type admins map[string]bool

func (a admins) IsAdmin(_ context.Context, u string) bool { return a[u] }

func (a *allowAll) Decide(context.Context, policy.Input) (policy.Decision, error) {
	a.calls++
	return policy.Decision{Outcome: policy.OutcomeAllow}, nil
}

func (a *allowAll) Visible(context.Context, policy.Input) (bool, error) { return true, nil }

func gwTool(name string) connectors.Tool {
	return connectors.Tool{App: App, Name: name, Kind: connectors.KindRead, InputSchema: json.RawMessage(`{"type":"object"}`)}
}

// clock is a settable time source.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func newGateWorld(t *testing.T) (*fakePermStore, *permissions.Service, *Gate, *clock) {
	t.Helper()
	ps := newFakePermStore()
	svc := permissions.New(ps, permissions.Options{})
	clk := &clock{t: time.Unix(1_700_000_000, 0)}
	return ps, svc, NewGate(svc, GateOptions{TTL: 2 * time.Second, Now: clk.now}), clk
}

// The visibility matrix: the gateway.* tools are listed and callable only
// when the user may add MCP servers AND switched the tools on. "On in the
// database but the role was removed" is off. Other apps are the base's.
func TestGateVisibilityMatrix(t *testing.T) {
	for _, tc := range []struct {
		name               string
		permitted, enabled bool
		want               bool
	}{
		{"not permitted, off", false, false, false},
		{"not permitted, on in the database (role removed)", false, true, false},
		{"permitted, off", true, false, false},
		{"permitted, on", true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ps, _, gate, _ := newGateWorld(t)
			ps.set(alice, tc.permitted, tc.enabled)
			base := &allowAll{}
			d := gate.Decider(base)
			in := policy.Input{UserID: alice, Tool: gwTool(ToolListServers)}
			vis, err := d.Visible(t.Context(), in)
			if err != nil || vis != tc.want {
				t.Errorf("Visible = %v, %v; want %v", vis, err, tc.want)
			}
			dec, err := d.Decide(t.Context(), in)
			want := policy.OutcomeHidden
			if tc.want {
				want = policy.OutcomeAllow
			}
			if err != nil || dec.Outcome != want {
				t.Errorf("Decide = %s, %v; want %s", dec.Outcome, err, want)
			}
			// tools/list goes through PolicyVisibility over the same
			// decider.
			pv := mcp.PolicyVisibility{Decider: d}
			if got := pv.Visible(t.Context(), &tokens.Principal{UserID: alice}, gwTool(ToolAddServer)); got != tc.want {
				t.Errorf("PolicyVisibility = %v, want %v", got, tc.want)
			}
			// Another app is untouched by the gate.
			other := connectors.Tool{App: "fake", Name: "list_items", Kind: connectors.KindRead}
			if ok, _ := d.Visible(t.Context(), policy.Input{UserID: alice, Tool: other}); !ok {
				t.Error("the gate hid another app's tool")
			}
		})
	}
}

// The policy below the gate is still consulted when the gate is open (so
// token narrowing, restrictions and the delete confirmation apply), and
// never when it is closed.
func TestGateDefersToPolicyWhenOpen(t *testing.T) {
	ps, _, gate, _ := newGateWorld(t)
	ps.set(alice, true, true)
	base := &allowAll{}
	d := gate.Decider(base)
	if _, err := d.Decide(t.Context(), policy.Input{UserID: alice, Tool: gwTool(ToolListServers)}); err != nil {
		t.Fatal(err)
	}
	if base.calls != 1 {
		t.Errorf("open gate: base consulted %d times, want 1", base.calls)
	}
	if _, err := d.Decide(t.Context(), policy.Input{UserID: bob, Tool: gwTool(ToolListServers)}); err != nil {
		t.Fatal(err)
	}
	if base.calls != 1 {
		t.Errorf("closed gate consulted the policy")
	}
}

func TestAdminRateToolsAreHiddenFromMembers(t *testing.T) {
	ps := newFakePermStore()
	svc := permissions.New(ps, permissions.Options{})
	ps.set(alice, true, true)
	ps.set(bob, true, true)
	gate := NewGate(svc, GateOptions{TTL: time.Nanosecond, Admin: admins{alice: true}})
	d := gate.Decider(&allowAll{})
	for _, tc := range []struct {
		user string
		want bool
	}{{alice, true}, {bob, false}} {
		ok, err := d.Visible(t.Context(), policy.Input{UserID: tc.user, Tool: gwTool(ToolSetOrgRateLimits)})
		if err != nil || ok != tc.want {
			t.Errorf("%s visible=%v,%v want %v", tc.user, ok, err, tc.want)
		}
	}
}

// Switching the tools off through the setting wrapper takes effect at
// once; a change made elsewhere (role removed, another replica) within
// the cache TTL.
func TestGateToggleOffTakesEffect(t *testing.T) {
	ps, svc, gate, clk := newGateWorld(t)
	ps.set(alice, true, true)
	ctx := t.Context()
	if !gate.Active(ctx, alice) {
		t.Fatal("gate closed for a permitted user who switched the tools on")
	}
	// Cached: a second check within the TTL does not hit the store.
	before := ps.lookups
	gate.Active(ctx, alice)
	if ps.lookups != before {
		t.Errorf("second check within the TTL looked the permission up again")
	}

	// My account switch (through the wrapper the portal is given).
	setting := gate.Setting(svc)
	if err := setting.SetGatewayToolsEnabled(ctx, alice, false); err != nil {
		t.Fatal(err)
	}
	if gate.Active(ctx, alice) {
		t.Error("switching the tools off did not close the gate at once")
	}
	if err := setting.SetGatewayToolsEnabled(ctx, alice, true); err != nil {
		t.Fatal(err)
	}
	if !gate.Active(ctx, alice) {
		t.Error("switching the tools on did not open the gate at once")
	}

	// The role is taken away elsewhere: closed once the TTL passed.
	ps.set(alice, false, true)
	clk.add(2 * time.Second)
	if gate.Active(ctx, alice) {
		t.Error("gate still open after the role was removed and the TTL passed")
	}
	if setting.CanAddServers(ctx, bob) {
		t.Error("setting wrapper: bob may add servers")
	}
}

// Accounts: an open gate gives the user the gateway anchor account; a
// closed one gives none; other apps go to the fallback.
func TestGateAccounts(t *testing.T) {
	ps, _, gate, _ := newGateWorld(t)
	ps.set(alice, true, true)
	anchors := &fakeAnchors{}
	fallback := connectors.NewStaticAccountSource()
	fallback.Add(alice, connectors.Account{ID: "f1", App: "fake", Label: connectors.LabelCompany})
	src := gate.Accounts(fallback, anchors)
	got, err := src.ListAccounts(t.Context(), alice, App)
	if err != nil || len(got) != 1 || got[0].ID != "anchor-"+alice || got[0].Label != connectors.LabelCompany || got[0].App != App {
		t.Fatalf("alice's gateway accounts = %+v, %v", got, err)
	}
	if got, _ := src.ListAccounts(t.Context(), bob, App); len(got) != 0 {
		t.Errorf("bob (gate closed) has gateway accounts: %+v", got)
	}
	if got, _ := src.ListAccounts(t.Context(), alice, "fake"); len(got) != 1 || got[0].ID != "f1" {
		t.Errorf("fallback accounts = %+v", got)
	}
}

type fakeAnchors struct{}

func (fakeAnchors) GatewayAccount(_ context.Context, userID string) (string, error) {
	return "anchor-" + userID, nil
}
