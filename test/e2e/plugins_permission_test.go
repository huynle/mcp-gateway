//go:build integration || e2e

package e2e

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/permissions"
	"github.com/huynle/mcp-gateway/internal/store"
)

const askAdminForServers = "Ask an admin for a role that may add MCP servers"

// TestE2EPluginsAddServerNeedsPermission (Brain task ds5tjou2, decision
// bnneszc1): a member whose roles may not add MCP servers sees no Add
// server button, gets 403 from the add form (create and detect), is
// refused by the connector, and cannot switch on the gateway management
// tools. A permitted user switches them on (audited). Once an admin gives
// the member a role with "May add MCP servers" in the role editor, the
// member adds a server through the portal.
func TestE2EPluginsAddServerNeedsPermission(t *testing.T) {
	w := newWorld(t, options{federation: true})
	w.allowLoopback()
	s := sdk.NewServer(&sdk.Implementation{Name: "perm", Version: "1"}, nil)
	sdk.AddTool(s, &sdk.Tool{Name: "ping", Description: "Ping.", Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}},
		func(_ context.Context, _ *sdk.CallToolRequest, in echoIn) (*sdk.CallToolResult, any, error) {
			return textResult("pong " + in.Text), nil, nil
		})
	up := httptest.NewTLSServer(sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return s }, &sdk.StreamableHTTPOptions{Stateless: true, JSONResponse: true}))
	t.Cleanup(up.Close)
	form := url.Values{"name": {"bobs"}, "url_mode": {"https"}, "url": {up.URL + "/mcp"}, "auth_kind": {"none"}, "credential_mode": {"per_user"}}

	// Bob (member / restricted): no button, 403 everywhere a server is added.
	list := w.page(w.bob, "/servers")
	if list.status != http.StatusOK || strings.Contains(list.body, `href="/servers/new"`) || !strings.Contains(list.body, askAdminForServers) {
		t.Fatalf("bob's /servers = %d, Add server shown or no explanation:\n%s", list.status, snippet(list.body))
	}
	if p := w.page(w.bob, "/servers/new"); p.status != http.StatusForbidden || !strings.Contains(p.body, askAdminForServers) {
		t.Errorf("bob GET /servers/new = %d", p.status)
	}
	if p := w.submit(w.bob, "/servers/new", form); p.status != http.StatusForbidden {
		t.Errorf("bob POST /servers/new = %d %q", p.status, p.location)
	}
	detect := url.Values{"action": {"detect"}, "url_mode": {"https"}, "url": {up.URL + "/mcp"}}
	if p := w.submit(w.bob, "/servers/new", detect); p.status != http.StatusForbidden {
		t.Errorf("bob detect = %d", p.status)
	}
	if n := w.serverCount(); n != 0 {
		t.Fatalf("%d servers exist after bob's refused attempts", n)
	}
	// Defense in depth: the connector refuses too.
	err := w.fed.Manager.CreateServer(t.Context(), &store.MCPServer{Name: "direct", URL: up.URL + "/mcp", OwnerUserID: w.bob.id,
		CredentialMode: store.MCPCredentialPerUser, AuthKind: store.MCPAuthNone})
	if !errors.Is(err, permissions.ErrNotPermitted) {
		t.Errorf("Manager.CreateServer for bob = %v, want ErrNotPermitted", err)
	}
	// Bob's gateway management tools: shown disabled, cannot be switched on.
	acct := w.page(w.bob, "/account")
	if !strings.Contains(acct.body, "Gateway management tools") || !strings.Contains(acct.body, askAdminForServers) {
		t.Errorf("bob's account page lacks the disabled setting:\n%s", snippet(acct.body))
	}
	if p := w.submit(w.bob, "/account/gateway-tools", url.Values{"enabled": {"on"}}); p.status != http.StatusForbidden {
		t.Errorf("bob switches gateway tools on = %d", p.status)
	}
	if w.perms.GatewayToolsActive(t.Context(), w.bob.id) {
		t.Error("bob's gateway tools are active")
	}

	// Alice (granted a role that may add servers) switches them on and off.
	if p := w.submit(w.alice, "/account/gateway-tools", url.Values{"enabled": {"on"}}); p.status != http.StatusSeeOther {
		t.Fatalf("alice switches gateway tools on = %d\n%s", p.status, snippet(p.body))
	}
	if !w.perms.GatewayToolsActive(t.Context(), w.alice.id) {
		t.Error("alice's gateway tools are not active")
	}
	if p := w.page(w.alice, "/account"); !strings.Contains(p.body, `aria-describedby="gateway-tools-help" checked`) {
		t.Errorf("alice's switch is not shown on:\n%s", snippet(p.body))
	}
	if p := w.submit(w.alice, "/account/gateway-tools", url.Values{}); p.status != http.StatusSeeOther {
		t.Fatalf("alice switches gateway tools off = %d", p.status)
	}
	if on, err := w.perms.GatewayToolsEnabled(t.Context(), w.alice.id); err != nil || on {
		t.Errorf("alice's setting after off = %v, %v", on, err)
	}
	recs, err := w.rec.ListForUser(t.Context(), w.alice.id, audit.Filter{}, audit.Page{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	var toggles []string
	for _, r := range recs {
		if r.ResourceIdentity["action"] == permissions.ActionGatewayToolsToggled {
			toggles = append(toggles, r.ResourceIdentity["enabled"])
		}
	}
	if len(toggles) != 2 {
		t.Errorf("alice's toggle audit events = %v, want two", toggles)
	}

	// The admin creates a role that may add servers and gives it to bob.
	mustRedirect(t, "create role", w.submit(w.admin, "/admin/roles/new", url.Values{"name": {"builders"}, "may_add_servers": {"on"}}), "/admin/roles/builders")
	mustRedirect(t, "assign role", w.submit(w.admin, "/admin/users/"+w.bob.id+"/role", url.Values{"role": {"builders"}}), "/admin/users")
	if p := w.page(w.bob, "/servers"); !strings.Contains(p.body, `href="/servers/new"`) {
		t.Errorf("bob still has no Add server button:\n%s", snippet(p.body))
	}
	id := w.addServer(w.bob, form)
	if p := w.page(w.bob, "/servers/"+id); p.status != http.StatusOK {
		t.Errorf("bob's new server page = %d", p.status)
	}
}

// serverCount counts every server (bypass scope).
func (w *world) serverCount() int {
	w.t.Helper()
	var n int
	err := w.st.WithJobs(w.t.Context(), func(tx store.Tx) error {
		all, err := store.ListAllMCPServers(w.t.Context(), tx)
		n = len(all)
		return err
	})
	if err != nil {
		w.t.Fatal(err)
	}
	return n
}
