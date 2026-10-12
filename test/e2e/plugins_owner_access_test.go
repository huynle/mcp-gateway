//go:build integration || e2e

package e2e

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/policy"
)

type jotIn struct {
	Text string `json:"text"`
}

// newJotUpstream is a server without auth with one read tool (search)
// and one write tool (save, no readOnlyHint).
func newJotUpstream(t *testing.T) string {
	t.Helper()
	s := sdk.NewServer(&sdk.Implementation{Name: "notes", Version: "1"}, nil)
	sdk.AddTool(s, &sdk.Tool{Name: "search", Description: "Search notes.", Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}},
		func(_ context.Context, _ *sdk.CallToolRequest, in jotIn) (*sdk.CallToolResult, any, error) {
			return textResult("found " + in.Text), nil, nil
		})
	sdk.AddTool(s, &sdk.Tool{Name: "save", Description: "Save a note."},
		func(_ context.Context, _ *sdk.CallToolRequest, in jotIn) (*sdk.CallToolResult, any, error) {
			return textResult("saved " + in.Text), nil, nil
		})
	return newOpenUpstream(t, s).URL
}

// TestE2EPluginsOwnerKeepsAccessAfterPublish (Brain task fekckdrt,
// decision q7vbxlyk point 1): publishing a server shares it with the
// role; its owner keeps the owner layer (reads allow, writes confirm)
// without any role grant. A role deny still wins over the owner layer.
func TestE2EPluginsOwnerKeepsAccessAfterPublish(t *testing.T) {
	w := newWorld(t, options{federation: true})
	w.allowLoopback()
	id := w.addServer(w.alice, url.Values{"name": {"jot"}, "url_mode": {"https"}, "url": {newJotUpstream(t)},
		"auth_kind": {"none"}, "credential_mode": {"per_user"}})
	w.approve(w.alice, id, w.refresh(w.alice, id), "search", "save")

	// The admin page says what publishing does: the owner keeps access.
	if p := w.page(w.admin, "/admin/servers/"+id); p.status != http.StatusOK || !strings.Contains(p.body, "keeps access") {
		t.Errorf("admin server page does not say the owner keeps access (%d):\n%s", p.status, snippet(p.body))
	}
	p := w.submit(w.admin, "/admin/servers/"+id+"/publish", url.Values{"roles": {w.roleID(roleRestricted)}})
	mustRedirect(t, "publish", p, "/admin/servers/"+id+"?done=")
	if notice := w.page(w.admin, p.location); !strings.Contains(notice.body, "keeps access") {
		t.Errorf("publish notice does not say the owner keeps access:\n%s", snippet(notice.body))
	}

	// Published, no role grant: the owner still sees and uses both tools.
	alice := w.client(w.alice)
	names := toolNames(t, alice)
	if !contains(names, "jot.search") || !contains(names, "jot.save") {
		t.Fatalf("owner's tools after publish = %v", names)
	}
	if got := w.toolText(alice, "jot.search", map[string]any{"text": "x"}); got != "found x" {
		t.Errorf("owner's read after publish = %q", got)
	}
	_, err := w.call(alice, "jot.save", map[string]any{"text": "x"})
	_ = approvalRequired(t, err)

	// The role it is published to still needs a grant.
	if contains(toolNames(t, w.client(w.bob)), "jot.search") {
		t.Error("published tool visible to the role before any grant")
	}

	// A role deny on the owner's role wins over the owner layer: an
	// unconditional deny forbids listing too, so the tool is gone.
	w.grant(roleMember, policy.ToolRule{App: "jot", Tool: policy.Wildcard, Outcome: policy.OutcomeDeny})
	alice = w.client(w.alice)
	if names := toolNames(t, alice); contains(names, "jot.search") || contains(names, "jot.save") {
		t.Errorf("owner still lists the server's tools under a role deny: %v", names)
	}
	_, err = w.call(alice, "jot.search", map[string]any{"text": "x"})
	_ = rpcError(t, err, mcp.CodeToolNotFound)
}
