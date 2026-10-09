package github_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
)

// --- tool metadata ----------------------------------------------------------

func TestWriteToolsMetadata(t *testing.T) {
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	tools := map[string]connectors.Tool{}
	var order []string
	for _, tool := range c.Tools() {
		tools[tool.Name] = tool
		if tool.Kind == connectors.KindWrite {
			order = append(order, tool.Name)
		}
	}
	wantOrder := []string{"create_issue", "add_issue_comment", "create_pull_request", "create_branch"}
	if strings.Join(order, ",") != strings.Join(wantOrder, ",") {
		t.Fatalf("write tools = %v, want %v", order, wantOrder)
	}
	type schema struct {
		Type       string                    `json:"type"`
		Properties map[string]map[string]any `json:"properties"`
		Required   []string                  `json:"required"`
		Additional *bool                     `json:"additionalProperties"`
	}
	cases := []struct {
		tool      string
		kind      connectors.ReconcileKind
		scopes    []string
		required  []string
		props     []string
		args      map[string]any
		identity  map[string]string
		resultIDs []string
	}{
		{
			tool: "create_issue", kind: connectors.ReconcileMarker, scopes: []string{"issues:write"},
			required: []string{"owner", "repo", "title"}, props: []string{"owner", "repo", "title", "body", "labels", "assignees"},
			args:     map[string]any{"owner": "Example-Org", "repo": "Widgets", "title": "secret title", "body": "secret body"},
			identity: map[string]string{"owner": "example-org", "repo": "example-org/widgets", "org": "example-org"},
		},
		{
			tool: "add_issue_comment", kind: connectors.ReconcileMarker, scopes: []string{"issues:write"},
			required: []string{"owner", "repo", "number", "body"}, props: []string{"owner", "repo", "number", "body"},
			args:     map[string]any{"owner": "example-org", "repo": "widgets", "number": 42, "body": "secret body"},
			identity: map[string]string{"owner": "example-org", "repo": "example-org/widgets", "org": "example-org", "number": "42"},
		},
		{
			tool: "create_pull_request", kind: connectors.ReconcileMarker, scopes: []string{"pull_requests:write"},
			required: []string{"owner", "repo", "title", "head", "base"}, props: []string{"owner", "repo", "title", "head", "base", "body", "draft"},
			args:     map[string]any{"owner": "example-org", "repo": "widgets", "title": "secret", "head": "Feature/Thing", "base": "main", "body": "secret body"},
			identity: map[string]string{"owner": "example-org", "repo": "example-org/widgets", "org": "example-org", "branch": "Feature/Thing", "base": "main"},
		},
		{
			tool: "create_branch", kind: connectors.ReconcileStableID, scopes: []string{"contents:write"},
			required: []string{"owner", "repo", "branch"}, props: []string{"owner", "repo", "branch", "from_branch"},
			args:     map[string]any{"owner": "example-org", "repo": "widgets", "branch": "Feature/Thing", "from_branch": "main"},
			identity: map[string]string{"owner": "example-org", "repo": "example-org/widgets", "org": "example-org", "branch": "Feature/Thing"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			tool, ok := tools[tc.tool]
			if !ok {
				t.Fatalf("tool %s not declared", tc.tool)
			}
			if tool.Kind != connectors.KindWrite {
				t.Errorf("Kind = %q, want write", tool.Kind)
			}
			if tool.Reconcile.Kind != tc.kind || tool.Reconcile.Check == nil {
				t.Errorf("Reconcile = kind %q check %v, want kind %q with a Check", tool.Reconcile.Kind, tool.Reconcile.Check != nil, tc.kind)
			}
			if tool.ResultIDs == nil {
				t.Error("ResultIDs is nil")
			}
			if strings.Join(tool.RequiredScopes, ",") != strings.Join(tc.scopes, ",") {
				t.Errorf("RequiredScopes = %v, want %v", tool.RequiredScopes, tc.scopes)
			}
			if tool.Bounds.MaxPageSize != 0 || tool.Bounds.MaxResultBytes <= 0 {
				t.Errorf("Bounds = %+v, want no page size and a result bound", tool.Bounds)
			}
			if strings.TrimSpace(tool.Description) == "" {
				t.Error("empty description")
			}
			var s schema
			if err := json.Unmarshal(tool.InputSchema, &s); err != nil {
				t.Fatalf("schema: %v", err)
			}
			if s.Type != "object" || s.Additional == nil || *s.Additional {
				t.Errorf("schema must be a closed object: %s", tool.InputSchema)
			}
			if strings.Join(s.Required, ",") != strings.Join(tc.required, ",") {
				t.Errorf("required = %v, want %v", s.Required, tc.required)
			}
			for _, p := range tc.props {
				if s.Properties[p] == nil {
					t.Errorf("property %q missing", p)
				} else if d, _ := s.Properties[p]["description"].(string); strings.TrimSpace(d) == "" {
					t.Errorf("property %q has no description", p)
				}
			}
			if len(s.Properties) != len(tc.props) {
				t.Errorf("properties = %d, want %d: %s", len(s.Properties), len(tc.props), tool.InputSchema)
			}
			got := tool.ResourceIdentity(tc.args)
			if len(got) != len(tc.identity) {
				t.Errorf("ResourceIdentity = %v, want %v", got, tc.identity)
			}
			for k, v := range tc.identity {
				if got[k] != v {
					t.Errorf("ResourceIdentity[%s] = %q, want %q (all: %v)", k, got[k], v, got)
				}
			}
			for _, v := range got {
				if strings.Contains(v, "secret") {
					t.Errorf("ResourceIdentity leaks argument content: %v", got)
				}
			}
			if id := tool.ResourceIdentity(nil); id == nil || len(id) != 0 {
				t.Errorf("ResourceIdentity(nil) = %v, want empty map", id)
			}
		})
	}
}
