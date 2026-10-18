package connections_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/huynle/mcp-gateway/internal/caps"
	"github.com/huynle/mcp-gateway/internal/connections"
)

type capLimits struct {
	v       caps.Values
	refused atomic.Int64
}

func (c *capLimits) Limit(_ context.Context, _ string, r caps.Resource) int { return c.v[r] }
func (c *capLimits) Refused(context.Context, string, caps.Resource, int)    { c.refused.Add(1) }

func TestCallbackRefusesNewConnectionAtCapButNeverReconnect(t *testing.T) {
	env := newTestEnv(t)
	v := newFakeVendor(t)
	registerFakeApp(t, env, v)
	for _, id := range []string{"acct-2", "acct-3"} {
		v.users[id] = userInfo{ID: id, Login: id, Email: id + "@acme.test"}
	}
	l := &capLimits{v: caps.Values{caps.ConnectionsPerApp: 2, caps.ConnectionsTotal: 20}}
	env.svc.SetCaps(l)
	if _, err := connect(t, env, userAlice, "acct-company", "repo"); err != nil {
		t.Fatal(err)
	}
	if _, err := connect(t, env, userAlice, "acct-2"); err != nil {
		t.Fatal(err)
	}
	_, err := connect(t, env, userAlice, "acct-3")
	var ce *caps.ExceededError
	if !errors.As(err, &ce) || ce.Resource != caps.ConnectionsPerApp || ce.Limit != 2 {
		t.Fatalf("third connection = %v, want per-app cap", err)
	}
	if l.refused.Load() != 1 {
		t.Errorf("refusals = %d", l.refused.Load())
	}
	conns, err := env.svc.Connections(context.Background(), userAlice)
	if err != nil || len(conns) != 2 {
		t.Fatalf("connections = %d (%v), want 2 (nothing stored)", len(conns), err)
	}
	// Reconnect and grant-more of an existing account are never blocked.
	if _, err := connect(t, env, userAlice, "acct-company", "write:org"); err != nil {
		t.Fatalf("grant more at cap: %v", err)
	}
	if err := env.svc.Disconnect(context.Background(), userAlice, conns[1].ID); err != nil {
		t.Fatal(err)
	}
	// A revoked connection frees its slot; reconnecting it is allowed.
	if _, err := connect(t, env, userAlice, "acct-3"); err != nil {
		t.Fatalf("after disconnect: %v", err)
	}
	if _, err := connect(t, env, userAlice, conns[1].ExternalAccountID); !errors.As(err, &ce) {
		// The revoked row exists, but reconnecting it would raise the
		// live count above the cap: refused like a new one.
		t.Fatalf("reviving a revoked account at cap = %v, want cap", err)
	}
	// Other users have their own budget; the total cap applies across apps.
	l.v[caps.ConnectionsTotal] = 1
	if _, err := connect(t, env, userBob, "acct-company"); err != nil {
		t.Fatalf("bob: %v", err)
	}
	if _, err := connect(t, env, userBob, "acct-2"); !errors.As(err, &ce) || ce.Resource != caps.ConnectionsTotal {
		t.Fatalf("bob total = %v", err)
	}
}

func TestCallbackCapRedirectShowsMessage(t *testing.T) {
	cases := map[string]string{
		"/connections?error=cap_exceeded&resource=connections_per_app&limit=5": "You have reached the limit of 5 connected accounts for this app",
		"/connections?error=cap_exceeded&resource=connections_total&limit=20":  "You have reached the limit of 20 connected accounts",
		"/connections?error=cap_exceeded&resource=bogus&limit=5":               "You have reached the limit of connected accounts",
		"/connections?error=cap_exceeded&resource=connections_total&limit=<b>": "You have reached the limit of connected accounts",
	}
	for path, want := range cases {
		if got := connections.FlowErrorMessageForTest(httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil).URL.Query()); !strings.Contains(got, want) || !strings.Contains(got, "ask an admin") {
			t.Errorf("%s: %q, want %q", path, got, want)
		}
	}
}
