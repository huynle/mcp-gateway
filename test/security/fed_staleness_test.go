//go:build integration || e2e || security

package security

// Stale-cache attacks (decision mrvsu07m: visibility cached per user for
// 10 s, registry reloaded every minute; every call re-checks the server
// and the snapshot as the caller under RLS). A change made on another
// replica (here: straight in the database, no ServerChanged) must take
// effect on the very next call, before any cache expires.

import (
	"encoding/json"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/policy"
)

// TestSecurityFedStaleVisibilityAndAudit: after an unpublish, a disable
// or a deletion of a tool from the approved review that the serving
// replica has not heard about yet, bob's next tool call and resource read
// are refused and never reach the upstream. Audit rows of federated calls
// and reads carry no arguments and no resource content.
func TestSecurityFedStaleVisibilityAndAudit(t *testing.T) {
	w := newWorld(t, options{federation: true})
	ctx := t.Context()
	w.allowLoopback()
	const argCanary, contentCanary = "audit-arg-canary-77", "readme text"
	w.forbid(argCanary, "tool argument")
	up := newUpstream(t, notesServer)
	s := w.addServer(w.alice, "stale", up.URL(), nil)
	w.review(w.alice, s, "search")
	w.publish(s, []policy.ToolRule{{App: "stale", Tool: "search", Outcome: policy.OutcomeAllow},
		{App: "stale", Tool: policy.ResourcesReadTool, Outcome: policy.OutcomeAllow}}, roleRestricted)
	bob := w.client(w.bob)
	if res, err := w.call(bob, "stale.search", map[string]any{"q": argCanary}); err != nil || res.IsError {
		t.Fatalf("bob before: %v %+v", err, res)
	}
	if _, err := bob.ReadResource(ctx, &sdk.ReadResourceParams{URI: "mcpgw://stale/notes://readme"}); err != nil {
		t.Fatalf("bob read before: %v", err)
	}
	for _, ev := range w.allEvents() {
		b, _ := json.Marshal(ev)
		if strings.Contains(string(b), contentCanary) {
			t.Errorf("an audit row carries resource content: %s", b)
		}
	}

	refused := func(when string) {
		t.Helper()
		up.reset()
		res, err := w.call(bob, "stale.search", map[string]any{"q": "x"})
		if err == nil && !res.IsError {
			t.Errorf("%s: bob's call still succeeds", when)
		}
		if _, err := bob.ReadResource(ctx, &sdk.ReadResourceParams{URI: "mcpgw://stale/notes://readme"}); err == nil {
			t.Errorf("%s: bob's read still succeeds", when)
		}
		if n := len(up.requests()); n != 0 {
			t.Errorf("%s: the upstream received %d requests", when, n)
		}
	}
	// Unpublished on another replica.
	w.exec(`DELETE FROM mcp_server_roles WHERE server_id = $1`, s.ID)
	w.exec(`UPDATE mcp_servers SET audience = 'private' WHERE id = $1`, s.ID)
	refused("after an unpublish elsewhere")
	w.exec(`UPDATE mcp_servers SET audience = 'published' WHERE id = $1`, s.ID)
	w.exec(`INSERT INTO mcp_server_roles (server_id, owner_user_id, role_id) SELECT $1, owner_user_id, (SELECT id FROM roles WHERE name = $2) FROM mcp_servers WHERE id = $1`, s.ID, roleRestricted)
	if res, err := w.call(bob, "stale.search", map[string]any{"q": "x"}); err != nil || res.IsError {
		t.Fatalf("bob after republishing: %v %+v", err, res)
	}
	// Disabled on another replica.
	w.exec(`UPDATE mcp_servers SET status = 'disabled' WHERE id = $1`, s.ID)
	refused("after a disable elsewhere")
	w.exec(`UPDATE mcp_servers SET status = 'active' WHERE id = $1`, s.ID)
	// The tool disabled in the approved review on another replica (the
	// review column layout: {"format":2,"tools":{...},"content":{...}}).
	w.exec(`UPDATE mcp_server_snapshots SET review = jsonb_set(review, '{tools,search,enabled}', 'false') WHERE server_id = $1 AND status = 'approved'`, s.ID)
	up.reset()
	if res, err := w.call(bob, "stale.search", map[string]any{"q": "x"}); err == nil && !res.IsError {
		t.Error("a tool disabled elsewhere still runs")
	}
	if n := len(up.requests()); n != 0 {
		t.Errorf("the disabled tool reached the upstream (%d requests)", n)
	}
}
