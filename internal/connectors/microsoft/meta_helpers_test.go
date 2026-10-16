package microsoft_test

import (
	"context"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/microsoft"
)

// toolMeta is the declared contract of one tool: kind, reconciliation,
// scopes, required arguments, and the resource identity of sample
// arguments (which must never carry argument content marked "secret").
type toolMeta struct {
	tool      string
	kind      connectors.Kind
	reconcile connectors.ReconcileKind
	scopes    []string
	required  []string
	args      map[string]any
	identity  map[string]string
}

// checkMeta asserts every case against the connector's declarations.
func checkMeta(t *testing.T, cases []toolMeta) {
	t.Helper()
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			tool := toolNamed(t, c, tc.tool)
			if tool.Kind != tc.kind {
				t.Errorf("Kind = %q, want %q", tool.Kind, tc.kind)
			}
			if tool.Reconcile.Kind != tc.reconcile {
				t.Errorf("Reconcile.Kind = %q, want %q", tool.Reconcile.Kind, tc.reconcile)
			}
			if tc.kind == connectors.KindWrite && tool.ResultIDs == nil {
				t.Error("write without ResultIDs")
			}
			if !slices.Equal(tool.RequiredScopes, tc.scopes) {
				t.Errorf("RequiredScopes = %v, want %v", tool.RequiredScopes, tc.scopes)
			}
			var s struct {
				Properties map[string]map[string]any `json:"properties"`
				Required   []string                  `json:"required"`
				Additional *bool                     `json:"additionalProperties"`
			}
			if err := json.Unmarshal(tool.InputSchema, &s); err != nil {
				t.Fatal(err)
			}
			if s.Additional == nil || *s.Additional {
				t.Errorf("schema is not closed: %s", tool.InputSchema)
			}
			if !slices.Equal(s.Required, tc.required) {
				t.Errorf("required = %v, want %v", s.Required, tc.required)
			}
			for name, p := range s.Properties {
				if d, _ := p["description"].(string); strings.TrimSpace(d) == "" {
					t.Errorf("property %q has no description", name)
				}
			}
			got := tool.ResourceIdentity(tc.args)
			if len(got) != len(tc.identity) {
				t.Errorf("ResourceIdentity = %v, want %v", got, tc.identity)
			}
			for k, v := range tc.identity {
				if got[k] != v {
					t.Errorf("ResourceIdentity[%s] = %q, want %q", k, got[k], v)
				}
			}
			for _, v := range got {
				if strings.Contains(v, "secret") {
					t.Errorf("ResourceIdentity leaks argument content: %v", got)
				}
			}
		})
	}
}

// run calls a tool (a write under opID when write is true) against a
// fixture server with the given routes.
func run(t *testing.T, routes map[string]route, tool string, args map[string]any, isWrite bool) (*apiServer, connectors.Result, error) {
	t.Helper()
	srv := newAPIServer(t, routes)
	c, _ := newConnector(t, srv, connectors.Bounds{})
	cl := call(tool, args)
	if isWrite {
		cl = write(tool, args)
	}
	res, err := c.Call(context.Background(), cl)
	return srv, res, err
}

// mustRun is run that fails the test on an error.
func mustRun(t *testing.T, routes map[string]route, tool string, args map[string]any, isWrite bool) (*apiServer, connectors.Result) {
	t.Helper()
	srv, res, err := run(t, routes, tool, args, isWrite)
	if err != nil {
		t.Fatalf("%s: %v", tool, err)
	}
	return srv, res
}

// wantInvalid asserts the call is refused as invalid_argument before any
// request.
func wantInvalid(t *testing.T, tool string, args map[string]any, isWrite bool) {
	t.Helper()
	srv, _, err := run(t, nil, tool, args, isWrite)
	wantClass(t, err, microsoft.ClassInvalidArgument, 0)
	if n := len(srv.Requests()); n != 0 {
		t.Errorf("%d requests sent for invalid arguments", n)
	}
}

// check runs a tool's reconciliation Check against routes.
func check(t *testing.T, routes map[string]route, tool string, identity map[string]string) (connectors.ReconcileResult, error) {
	t.Helper()
	srv := newAPIServer(t, routes)
	c, _ := newConnector(t, srv, connectors.Bounds{})
	return toolNamed(t, c, tool).Reconcile.Check(context.Background(), reconcile(tool, identity))
}

// mustConnector is a connector without a fixture server, for
// declarations (ResultIDs, metadata).
func mustConnector(t *testing.T) *microsoft.Connector {
	t.Helper()
	c, _ := newConnector(t, newAPIServer(t, nil), connectors.Bounds{})
	return c
}

// contentTools return downloaded content and are bounded by the content
// cap instead of the default result size.
var contentTools = map[string]bool{"mail_get_attachment": true, "drive_get_file_content": true}
