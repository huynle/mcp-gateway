//go:build integration || e2e

package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/federation/gatewaytools"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/store"
)

var gatewayToolNames = []string{"gateway.add_server", "gateway.connect_link", "gateway.delete_server", "gateway.detect_auth",
	"gateway.get_server", "gateway.get_tool_approvals", "gateway.list_servers", "gateway.refresh_server", "gateway.set_tool_approval"}

// gatewayTools returns the gateway.* names in a tools/list.
func gatewayTools(t *testing.T, cs *sdk.ClientSession) []string {
	t.Helper()
	var out []string
	for _, n := range toolNames(t, cs) {
		if strings.HasPrefix(n, gatewaytools.App+".") {
			out = append(out, n)
		}
	}
	return out
}

// gwJSON calls a gateway tool that must succeed and decodes its content.
func (w *world) gwJSON(cs *sdk.ClientSession, tool string, args map[string]any) map[string]any {
	w.t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(w.toolText(cs, tool, args)), &out); err != nil {
		w.t.Fatalf("%s: %v", tool, err)
	}
	return out
}

// assertUnknownTool: the call is answered exactly like a tool that does
// not exist.
func assertUnknownTool(t *testing.T, w *world, cs *sdk.ClientSession, tool string) {
	t.Helper()
	_, err := w.call(cs, tool, map[string]any{})
	je := rpcError(t, err, mcp.CodeToolNotFound)
	if je.Message != fmt.Sprintf("unknown tool %q", tool) {
		t.Errorf("%s answered %q, want the unknown-tool answer", tool, je.Message)
	}
}

// localPath turns an absolute portal link into the path the test server
// serves.
func localPath(t *testing.T, link string) string {
	t.Helper()
	if !strings.HasPrefix(link, baseURL+"/") {
		t.Fatalf("link %q is not an absolute portal link under %s", link, baseURL)
	}
	return strings.TrimPrefix(link, baseURL)
}

// TestE2EGatewayToolsManageServers (Brain task 99b5yzdb): the admin
// switches "Gateway management tools" on in My account and, through the
// official MCP client, lists, detects, adds a server (a fake TLS upstream),
// refreshes it, follows the review link to approve in the portal, and the
// new server's tools appear; deleting it needs an approval. A member
// without the permission never sees gateway.*; switching the tools off
// hides them at once.
func TestE2EGatewayToolsManageServers(t *testing.T) {
	w := newWorld(t, options{federation: true})
	w.allowLoopback()
	up := sdk.NewServer(&sdk.Implementation{Name: "pinger", Version: "1"}, nil)
	sdk.AddTool(up, &sdk.Tool{Name: "ping", Description: "Ping.", Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}},
		func(_ context.Context, _ *sdk.CallToolRequest, in echoIn) (*sdk.CallToolResult, any, error) {
			return textResult("pong " + in.Text), nil, nil
		})
	sdk.AddTool(up, &sdk.Tool{Name: "note", Description: "Write a note."},
		func(_ context.Context, _ *sdk.CallToolRequest, in echoIn) (*sdk.CallToolResult, any, error) {
			return textResult("noted " + in.Text), nil, nil
		})
	upSrv := newOpenUpstream(t, up)
	upURL := upSrv.URL + "/mcp"

	admin, bob := w.client(w.admin), w.client(w.bob)
	if got := gatewayTools(t, admin); len(got) != 0 {
		t.Fatalf("admin sees %v before switching the tools on", got)
	}

	// My account: the admin switches the tools on.
	if p := w.submit(w.admin, "/account/gateway-tools", url.Values{"enabled": {"on"}}); p.status != http.StatusSeeOther {
		t.Fatalf("admin switches gateway tools on = %d\n%s", p.status, snippet(p.body))
	}
	if got := strings.Join(gatewayTools(t, admin), ","); got != strings.Join(gatewayToolNames, ",") {
		t.Fatalf("admin's gateway tools = %s", got)
	}

	// List (nothing yet), detect, add.
	if list := w.gwJSON(admin, "gateway.list_servers", nil); len(list["servers"].([]any)) != 0 {
		t.Errorf("list before adding = %v", list)
	}
	det := w.gwJSON(admin, "gateway.detect_auth", map[string]any{"url": upURL})
	if fmt.Sprint(det["auth_kinds"]) != "[none]" {
		t.Errorf("detect = %v", det)
	}
	added := w.gwJSON(admin, "gateway.add_server", map[string]any{"name": "pinger", "url": upURL, "auth_kind": "none", "credential_mode": "per_user"})
	id, _ := added["server_id"].(string)
	if id == "" {
		t.Fatalf("add_server = %v", added)
	}
	if srv, _ := added["server"].(map[string]any); srv["audience"] != store.MCPAudiencePrivate || srv["approved_tools"] != float64(0) {
		t.Errorf("added server = %v", srv)
	}
	if p := w.page(w.admin, "/servers/"+id); p.status != http.StatusOK || !strings.Contains(p.body, "pinger") {
		t.Errorf("the new server's portal page = %d", p.status)
	}
	// A secret is refused (and never logged or audited), and so is a
	// reserved name.
	w.forbid("s3cr3t-e2e-value", "secret passed to add_server")
	if msg := w.toolError(admin, "gateway.add_server", map[string]any{"name": "other", "url": upURL, "auth_kind": "bearer",
		"credential_mode": "per_user", "token": "s3cr3t-e2e-value"}); !strings.Contains(msg, "browser") {
		t.Errorf("secret argument = %q", msg)
	}
	w.toolError(admin, "gateway.add_server", map[string]any{"name": "gateway", "url": upURL, "auth_kind": "none", "credential_mode": "per_user"})

	// Refresh: a diff and the review link, nothing approved.
	ref := w.gwJSON(admin, "gateway.refresh_server", map[string]any{"server": "pinger"})
	if a, _ := ref["added"].(map[string]any); a["count"] != float64(2) {
		t.Errorf("refresh diff = %v", ref)
	}
	if contains(toolNames(t, admin), "pinger.ping") {
		t.Fatal("pinger.ping is listed before anyone approved it")
	}
	review, _ := ref["review_link"].(string)

	// Follow the review link in the portal and approve ping.
	p := w.page(w.admin, localPath(t, review))
	if p.status != http.StatusOK {
		t.Fatalf("review link %s = %d", review, p.status)
	}
	w.approve(w.admin, id, p.body, "ping")
	w.eventually("pinger.ping listed", 5*time.Second, func() bool { return contains(toolNames(t, admin), "pinger.ping") })
	if got := w.toolText(admin, "pinger.ping", map[string]any{"text": "hi"}); got != "pong hi" {
		t.Errorf("pinger.ping = %q", got)
	}
	got := w.gwJSON(admin, "gateway.get_server", map[string]any{"server": id})
	if got["approved_tools"] != float64(1) || got["pending_review"] != false {
		t.Errorf("get_server after approval = %v", got)
	}

	// Bob (no permission) never sees gateway.*, even calling by name.
	if got := gatewayTools(t, bob); len(got) != 0 {
		t.Errorf("bob sees %v", got)
	}
	for _, name := range gatewayToolNames {
		assertUnknownTool(t, w, bob, name)
	}
	if p := w.submit(w.bob, "/account/gateway-tools", url.Values{"enabled": {"on"}}); p.status != http.StatusForbidden {
		t.Errorf("bob switches the tools on = %d", p.status)
	}
	if got := gatewayTools(t, bob); len(got) != 0 {
		t.Errorf("bob sees %v after a refused switch", got)
	}

	// Delete needs an approval; the server stays until it is granted.
	_, err := w.call(admin, "gateway.delete_server", map[string]any{"server": "pinger"})
	approvalID := approvalRequired(t, err)
	if w.serverCount() != 1 {
		t.Fatal("the server was deleted before the approval")
	}
	if code, _ := w.post(w.admin, "/approvals/"+approvalID+"/approve", true); code != http.StatusSeeOther {
		t.Fatalf("approve delete = %d", code)
	}
	del := w.gwJSON(admin, "gateway.delete_server", map[string]any{"server": "pinger", "approval_id": approvalID})
	if del["server_id"] != id || w.serverCount() != 0 {
		t.Errorf("delete = %v, servers left %d", del, w.serverCount())
	}
	w.eventually("pinger.ping gone", 5*time.Second, func() bool { return !contains(toolNames(t, admin), "pinger.ping") })
	if !w.hasAudit(w.admin, "gateway.add_server", "succeeded", "") || !w.hasAudit(w.admin, "gateway.delete_server", "succeeded", "") {
		t.Error("the gateway tool calls are not audited")
	}
	if op := w.opFor(w.admin, "gateway.delete_server", "succeeded"); op == nil {
		t.Error("delete_server has no ledger operation")
	}

	// Switching the tools off hides them at once.
	if p := w.submit(w.admin, "/account/gateway-tools", url.Values{}); p.status != http.StatusSeeOther {
		t.Fatalf("admin switches gateway tools off = %d", p.status)
	}
	if got := gatewayTools(t, admin); len(got) != 0 {
		t.Errorf("admin still sees %v after switching off", got)
	}
	assertUnknownTool(t, w, admin, "gateway.list_servers")
}

// TestE2EGatewayToolsRoleRemoved: alice (a role that may add servers)
// switches the tools on; once an admin takes the role away the tools
// disappear within seconds although the stored setting is still on.
func TestE2EGatewayToolsRoleRemoved(t *testing.T) {
	w := newWorld(t, options{federation: true})
	alice := w.client(w.alice)
	if p := w.submit(w.alice, "/account/gateway-tools", url.Values{"enabled": {"on"}}); p.status != http.StatusSeeOther {
		t.Fatalf("alice switches on = %d", p.status)
	}
	if got := gatewayTools(t, alice); len(got) != len(gatewayToolNames) {
		t.Fatalf("alice's gateway tools = %v", got)
	}
	w.exec(`DELETE FROM role_assignments WHERE user_id = $1 AND role_id = (SELECT id FROM roles WHERE name = $2)`, w.alice.id, roleServerBuilders)
	w.policy.Invalidate()
	w.eventually("alice's gateway tools hidden", 10*time.Second, func() bool { return len(gatewayTools(t, alice)) == 0 })
	if on, err := w.perms.GatewayToolsEnabled(t.Context(), w.alice.id); err != nil || !on {
		t.Errorf("stored setting = %v, %v; want still on", on, err)
	}
	assertUnknownTool(t, w, alice, "gateway.add_server")
}
