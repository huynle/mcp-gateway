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
// refused before the upstream.
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

	// Arguments outside the pinned schema. For the read tool they are
	// refused at once; for the write tool the confirm stage asks for an
	// approval first (finding: validation happens at dispatch), and the
	// approved retry is refused before the upstream.
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
		_, err := w.call(alice, "snapnotes.create_note", args)
		if isRPC(err, mcp.CodeInvalidParams) {
			continue
		}
		id := approvalRequired(t, err)
		if code, _, _ := w.post(w.alice, "/approvals/"+id+"/approve", nil); code != http.StatusSeeOther {
			t.Fatalf("approve = %d", code)
		}
		retry := map[string]any{"approval_id": id}
		for k, v := range args {
			retry[k] = v
		}
		if _, err := w.call(alice, "snapnotes.create_note", retry); !isRPC(err, mcp.CodeInvalidParams) {
			t.Errorf("write, %s, approved retry: %v, want invalid params", name, err)
		}
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
// colliding names are all dropped; reserved server names are refused.
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
	w.review(w.alice, s, names...)
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
