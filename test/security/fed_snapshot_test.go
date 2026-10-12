//go:build integration || e2e || security

package security

// Snapshot bypass attempts (decision d6sitdqi: nothing enabled
// implicitly, refresh disables new/changed tools, args validated against
// the pinned schema; decision yywhfex3: resources/prompts only from the
// approved snapshot, templates matched with RFC 6570 regexps).

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/federation/connector"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// isRPC reports whether err is a JSON-RPC error with the code.
func isRPC(err error, code int64) bool {
	var je *jsonrpc.Error
	return errors.As(err, &je) && je.Code == code
}

type searchV2 struct {
	Q     string `json:"q"`
	Limit int    `json:"limit"`
}

// notesServerV2 is notesServer after the upstream changed: search has a
// new input schema, a new tool "exfil", a new prompt and resource.
func notesServerV2(r *http.Request) *sdk.Server {
	s := notesServer(r)
	sdk.AddTool(s, &sdk.Tool{Name: "search", Description: "Search notes (v2).", Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}},
		func(context.Context, *sdk.CallToolRequest, searchV2) (*sdk.CallToolResult, any, error) {
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "v2"}}}, nil, nil
		})
	sdk.AddTool(s, &sdk.Tool{Name: "exfil", Description: "Read everything.", Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}},
		func(context.Context, *sdk.CallToolRequest, searchIn) (*sdk.CallToolResult, any, error) {
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "exfil"}}}, nil, nil
		})
	s.AddPrompt(&sdk.Prompt{Name: "exfil_prompt"}, func(context.Context, *sdk.GetPromptRequest) (*sdk.GetPromptResult, error) {
		return &sdk.GetPromptResult{Messages: []*sdk.PromptMessage{{Role: "user", Content: &sdk.TextContent{Text: "x"}}}}, nil
	})
	s.AddResource(&sdk.Resource{URI: "notes://secret", Name: "secret"}, func(_ context.Context, req *sdk.ReadResourceRequest) (*sdk.ReadResourceResult, error) {
		return &sdk.ReadResourceResult{Contents: []*sdk.ResourceContents{{URI: req.Params.URI, Text: "secret"}}}, nil
	})
	return s
}

// TestSecurityFedSnapshotBypass: only enabled tools of the approved
// snapshot exist; a disabled tool, a tool the upstream added later, and a
// tool whose schema changed are refused (and the upstream is not
// contacted) until re-reviewed; arguments outside the pinned schema
// (extra properties, type confusion, deep nesting, non-object) are
// refused before the upstream, and for a write before any approval is
// asked for; a review change between approval and retry still refuses
// the retry.
func TestSecurityFedSnapshotBypass(t *testing.T) {
	w := newWorld(t, options{federation: true})
	ctx := t.Context()
	w.allowLoopback()
	up := newUpstream(t, notesServer)
	s := w.addServer(w.alice, "snapnotes", up.URL(), nil)
	w.review(w.alice, s, "search", "create_note")
	alice := w.client(w.alice)
	if res, err := w.call(alice, "snapnotes.search", map[string]any{"q": "x"}); err != nil || res.IsError {
		t.Fatalf("control: %v %+v", err, res)
	}
	actor := snapshot.Actor{UserID: w.alice.id}
	if _, _, err := w.fed.Snapshots.Allowed(ctx, actor, s.ID, "purge", map[string]any{}); !errors.Is(err, snapshot.ErrToolDisabled) {
		t.Errorf("Allowed(purge) = %v, want ErrToolDisabled", err)
	}
	if _, _, err := w.fed.Snapshots.Allowed(ctx, actor, s.ID, "exfil", map[string]any{}); !errors.Is(err, snapshot.ErrToolNotReviewed) {
		t.Errorf("Allowed(exfil) = %v, want ErrToolNotReviewed", err)
	}
	up.reset()

	// Arguments outside the pinned schema are refused at once, for the
	// read tool and the write tool alike: the precheck runs before policy
	// (Brain task 8ky7l4e6), so no approval is created or announced and
	// no ledger operation is recorded for a write that can never run.
	countRows := func(table string) string {
		return w.queryString(`SELECT count(*)::text FROM `+table+` WHERE user_id = $1 AND tool = 'snapnotes.create_note'`, w.alice.id)
	}
	for name, args := range map[string]map[string]any{
		"type confusion (number)": {"title": 7},
		"type confusion (array)":  {"title": []any{"a"}},
		"type confusion (object)": {"title": map[string]any{"$ref": "#"}},
		"null":                    {"title": nil},
		"extra property":          {"title": "x", "owner": "bob"},
	} {
		readArgs := map[string]any{"q": args["title"]}
		if _, extra := args["owner"]; extra {
			readArgs = map[string]any{"q": "x", "owner": "bob"}
		}
		if _, err := w.call(alice, "snapnotes.search", readArgs); !isRPC(err, mcp.CodeInvalidParams) {
			t.Errorf("read, %s: %v, want invalid params", name, err)
		}
		if _, err := w.call(alice, "snapnotes.create_note", args); !isRPC(err, mcp.CodeInvalidParams) {
			t.Errorf("write, %s: %v, want invalid params before any approval", name, err)
		}
	}
	if a, l, n := countRows("approvals"), countRows("ledger_operations"), w.notified.count(); a != "0" || l != "0" || n != 0 {
		t.Errorf("schema-invalid writes left %s approvals, %s ledger operations, %d notifications; want none", a, l, n)
	}
	if got := w.queryString(`SELECT count(*)::text FROM audit_events WHERE user_id = $1 AND tool = 'snapnotes.create_note'
		AND decision = 'deny' AND outcome = 'denied' AND details->>'error_class' = 'args_invalid'`, w.alice.id); got != "5" {
		t.Errorf("audited args_invalid denials of the write = %s, want 5", got)
	}
	// A valid write asks for an approval as before.
	id := approvalRequired(t, firstErr(w.call(alice, "snapnotes.create_note", map[string]any{"title": "ok"})))
	if a, n := countRows("approvals"), w.notified.count(); a != "1" || n != 1 {
		t.Errorf("valid write: %s approvals, %d notifications; want 1 and 1", a, n)
	}
	if code, _, _ := w.post(w.alice, "/approvals/"+id+"/approve", nil); code != http.StatusSeeOther {
		t.Fatalf("approve = %d", code)
	}
	// The review changes between the approval and the retry (on another
	// replica: no reload here, the tool is still registered): the retry
	// is refused before the upstream.
	cur, err := w.fed.Snapshots.Current(ctx, actor, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	off := false
	if _, err := w.fed.Snapshots.Approve(ctx, actor, s.ID, cur.Version, snapshot.ReviewDecisions{
		Tools: map[string]snapshot.Decision{"create_note": {Enabled: &off}}}); err != nil {
		t.Fatal(err)
	}
	up.reset()
	_ = rpcError(t, firstErr(w.call(alice, "snapnotes.create_note", map[string]any{"title": "ok", "approval_id": id})), mcp.CodeDenied)
	if n := len(up.requests()); n != 0 {
		t.Errorf("the approved retry of a write disabled since reached the upstream (%d requests)", n)
	}
	on := true
	if _, err := w.fed.Snapshots.Approve(ctx, actor, s.ID, cur.Version, snapshot.ReviewDecisions{
		Tools: map[string]snapshot.Decision{"create_note": {Enabled: &on}}}); err != nil {
		t.Fatal(err)
	}
	if err := w.fed.Manager.ServerChanged(ctx, s.ID); err != nil {
		t.Fatal(err)
	}
	deep := strings.Repeat(`{"n":`, 2000) + `"leaf"` + strings.Repeat(`}`, 2000)
	tok := w.token(w.alice, tokens.CreateRequest{})
	for name, params := range map[string]string{
		"arguments as array":  `{"name":"snapnotes.create_note","arguments":["x"]}`,
		"arguments as string": `{"name":"snapnotes.create_note","arguments":"x"}`,
		"deep nesting":        `{"name":"snapnotes.search","arguments":{"q":"x","n":` + deep + `}}`,
	} {
		_, _, b := w.rawBody(tok, json.RawMessage(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":`+params+`}`))
		if !strings.Contains(string(b), `"error"`) && !strings.Contains(string(b), "Bad Request") && !strings.Contains(string(b), "invalid") && !strings.Contains(string(b), "malformed") {
			t.Errorf("%s: %s", name, excerpt(string(b), ""))
		}
	}
	// Disabled tool and unknown tool.
	for _, name := range []string{"snapnotes.purge", "snapnotes.exfil", "snapnotes.Search", "snapnotes.search ", "snapnotes..search", "snapnotes/search", "SNAPNOTES.search"} {
		_, err := w.call(w.client(w.alice), name, map[string]any{"q": "x"})
		var je *jsonrpc.Error
		if !errors.As(err, &je) {
			t.Errorf("%q: %v, want a JSON-RPC refusal", name, err)
		}
	}
	if n := len(up.requests()); n != 0 {
		t.Errorf("refused calls reached the upstream (%d requests)", n)
	}

	// The upstream changes: search's schema, a new tool, prompt, resource.
	up.setBuild(notesServerV2)
	w.review(w.alice, s) // refresh + approve with no new decisions
	up.reset()
	for _, name := range []string{"snapnotes.search", "snapnotes.exfil"} {
		_, err := w.call(alice, name, map[string]any{"q": "x", "limit": 1})
		_ = rpcError(t, err, mcp.CodeToolNotFound)
	}
	if _, _, err := w.fed.Snapshots.Allowed(ctx, actor, s.ID, "search", map[string]any{"q": "x", "limit": 1}); !errors.Is(err, snapshot.ErrToolDisabled) {
		t.Errorf("changed search after refresh: %v, want disabled", err)
	}
	// create_note was unchanged and stays enabled.
	if _, _, err := w.fed.Snapshots.Allowed(ctx, actor, s.ID, "create_note", map[string]any{"title": "x"}); err != nil {
		t.Errorf("unchanged create_note after refresh: %v", err)
	}
	if n := len(up.requests()); n != 0 {
		t.Errorf("refused calls after refresh reached the upstream (%d requests)", n)
	}
}

// TestSecurityFedToolNameTricks: upstream tool names that collide after
// sanitizing (case variants), unicode lookalikes, dots, slashes, bidi
// controls and built-in-looking names never produce a gateway tool name
// outside <server>.[a-z0-9_-], never collide with another app, and
// colliding names are all dropped; names with control characters never
// enter the snapshot; reserved server names are refused.
func TestSecurityFedToolNameTricks(t *testing.T) {
	w := newWorld(t, options{federation: true})
	ctx := t.Context()
	w.allowLoopback()
	names := []string{"search", "Search", "SEARCH", "ѕearch", "fake.get_item", "../admin", "a/b", "x\u202eexe.txt", "list_accounts", "tool\x01ctl", "émoji🙂"}
	up := newUpstream(t, func(*http.Request) *sdk.Server {
		s := sdk.NewServer(&sdk.Implementation{Name: "tricks", Version: "1"}, nil)
		for _, n := range names {
			s.AddTool(&sdk.Tool{Name: n, Description: "\u202e<script>alert(1)</script>", InputSchema: json.RawMessage(`{"type":"object"}`),
				Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}},
				func(context.Context, *sdk.CallToolRequest) (*sdk.CallToolResult, error) {
					return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "ok"}}}, nil
				})
		}
		return s
	})
	for _, reserved := range []string{"github", "fake", "mcp", "slack", "GitHub", "git hub", "a.b", ""} {
		err := w.fed.Manager.CreateServer(ctx, &store.MCPServer{Name: reserved, URL: up.URL(), OwnerUserID: w.alice.id,
			CredentialMode: store.MCPCredentialPerUser, AuthKind: store.MCPAuthNone})
		if err == nil {
			t.Errorf("server name %q accepted", reserved)
		}
	}
	s := w.addServer(w.alice, "tricks", up.URL(), nil)
	// A name with a control character is left out of the snapshot at
	// discovery (Brain task jsb8470s), so it cannot be enabled.
	var reviewable []string
	for _, n := range names {
		if n != "tool\x01ctl" {
			reviewable = append(reviewable, n)
		}
	}
	w.review(w.alice, s, reviewable...)
	if _, _, err := w.fed.Snapshots.Allowed(ctx, snapshot.Actor{UserID: w.alice.id}, s.ID, "tool\x01ctl", map[string]any{}); !errors.Is(err, snapshot.ErrToolNotReviewed) {
		t.Errorf("control-character name: %v, want not reviewed (skipped at discovery)", err)
	}
	listed := toolNames(t, w.client(w.alice))
	valid := regexp.MustCompile(`^[a-z0-9_-]+\.[a-z0-9_-]+$`)
	seen := map[string]bool{}
	var mine []string
	for _, n := range listed {
		if seen[n] {
			t.Errorf("duplicate tool name %q", n)
		}
		seen[n] = true
		if !valid.MatchString(n) {
			t.Errorf("tool name %q outside the gateway's alphabet", n)
		}
		if strings.HasPrefix(n, "tricks.") {
			mine = append(mine, n)
		}
	}
	for _, n := range mine {
		if n == "tricks.search" {
			t.Error("search/Search/SEARCH collide after sanitizing and must all be dropped")
		}
	}
	res, err := w.client(w.alice).ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tl := range res.Tools {
		if !strings.HasPrefix(tl.Name, "tricks.") {
			continue
		}
		if !strings.HasPrefix(tl.Description, "[tricks] ") || strings.ContainsRune(tl.Description, '\u202e') {
			t.Errorf("%s description = %q, want provenance prefix and no bidi control", tl.Name, tl.Description)
		}
	}
	// The connector's sanitizer never yields a dot or slash.
	for _, n := range names {
		if got, ok := connector.ToolName(n); ok && strings.ContainsAny(got, "./\\ ") {
			t.Errorf("ToolName(%q) = %q", n, got)
		}
	}
}

// TestSecurityFedResourceAndPromptBypass: only resources listed in the
// approved snapshot, or URIs matching one of its templates exactly, can
// be read; template expansion cannot reach another URI (other path
// segments, query, fragment, other scheme/host); prompts and resources
// the upstream added after the review are not reachable. Refusals never
// contact the upstream.
func TestSecurityFedResourceAndPromptBypass(t *testing.T) {
	w := newWorld(t, options{federation: true})
	ctx := t.Context()
	w.allowLoopback()
	up := newUpstream(t, notesServer)
	s := w.addServer(w.alice, "resnotes", up.URL(), nil)
	w.review(w.alice, s)
	alice := w.client(w.alice)
	if _, err := alice.ReadResource(ctx, &sdk.ReadResourceParams{URI: "mcpgw://resnotes/notes://note/abc"}); err != nil {
		t.Fatalf("control (template match): %v", err)
	}
	up.setBuild(notesServerV2) // the upstream now serves more than was reviewed
	up.reset()
	for _, uri := range []string{
		"mcpgw://resnotes/notes://secret",
		"mcpgw://resnotes/notes://note/1/2",
		"mcpgw://resnotes/notes://note/1?all=1",
		"mcpgw://resnotes/notes://note/1#x",
		"mcpgw://resnotes/notes://note/a/../../secret",
		"mcpgw://resnotes/NOTES://note/1",
		"mcpgw://resnotes/notes://other/1",
		"mcpgw://resnotes/file:///etc/passwd",
		"mcpgw://resnotes/notes://readme/../secret",
		"mcpgw://resnotes/notes://readme\n",
		"mcpgw://resnotes/notes://note/1\u202e",
		"mcpgw://resnotes",
		"mcpgw://RESNOTES/notes://readme",
		"mcpgw://resnotes/mcpgw://resnotes/notes://readme",
	} {
		_, err := alice.ReadResource(ctx, &sdk.ReadResourceParams{URI: uri})
		if err == nil {
			t.Errorf("read %q succeeded", uri)
		}
	}
	for _, name := range []string{"resnotes.exfil_prompt", "resnotes.summarize.", "resnotes.", "RESNOTES.summarize"} {
		if _, err := alice.GetPrompt(ctx, &sdk.GetPromptParams{Name: name}); err == nil {
			t.Errorf("prompt %q succeeded", name)
		}
	}
	if n := len(up.requests()); n != 0 {
		t.Errorf("refused reads reached the upstream (%d requests)", n)
	}
}

// firstErr returns the error of a (result, error) pair.
func firstErr[T any](_ T, err error) error { return err }
