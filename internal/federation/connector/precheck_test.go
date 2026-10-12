package connector

import (
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/store"
)

// precheck runs the Manager's pre-policy check for a registered tool.
func (f *fixture) precheck(t *testing.T, user, name string, args map[string]any) error {
	t.Helper()
	tool, ok := f.reg.Get(name)
	if !ok {
		t.Fatalf("%s not registered", name)
	}
	return f.m.Precheck().Precheck(t.Context(), tool, connectors.Call{Principal: connectors.Principal{UserID: user}, Tool: name, Args: args})
}

// The pre-policy check (Brain task 8ky7l4e6) refuses what the dispatch
// would refuse from the review, so a write that can never run gets no
// approval; it never contacts the upstream.
func TestManagerPrecheck(t *testing.T) {
	cases := []struct {
		name  string
		user  string
		tool  string
		args  map[string]any
		setup func(f *fixture)
		want  string
	}{
		{"valid write", alice, "notes.create_note", map[string]any{"title": "t"}, nil, ""},
		{"valid read", alice, "notes.search", map[string]any{"q": "x"}, nil, ""},
		{"write, type confusion", alice, "notes.create_note", map[string]any{"title": 7}, nil, "tool:args_invalid"},
		{"write, extra property", alice, "notes.create_note", map[string]any{"title": "t", "owner": "bob"}, nil, "tool:args_invalid"},
		{"write, null", alice, "notes.create_note", map[string]any{"title": nil}, nil, "tool:args_invalid"},
		{"write disabled since listing", alice, "notes.create_note", map[string]any{"title": "t"}, func(f *fixture) {
			f.snaps.setReview("create_note", snapshot.ToolReview{Enabled: false, Kind: snapshot.KindWrite})
		}, "tool:tool_disabled"},
		{"write gone from the approved snapshot", alice, "notes.create_note", map[string]any{"title": "t"}, func(f *fixture) {
			f.snaps.mu.Lock()
			r := *f.snaps.records[srvID]
			snap := &snapshot.Snapshot{}
			for _, tl := range r.Snapshot.Tools {
				if tl.Name != "create_note" {
					snap.Tools = append(snap.Tools, tl)
				}
			}
			r.Snapshot = snap
			f.snaps.records[srvID] = &r
			f.snaps.mu.Unlock()
		}, "tool:tool_not_reviewed"},
		{"read became write since listing", alice, "notes.broken", map[string]any{"q": "x"}, func(f *fixture) {
			f.snaps.setReview("broken", snapshot.ToolReview{Enabled: true, Kind: snapshot.KindWrite})
		}, "tool:tool_changed"},
		{"user cannot see the server", bob, "notes.create_note", map[string]any{"title": "t"}, nil, "tool:tool_not_found"},
		{"server disabled", alice, "notes.create_note", map[string]any{"title": "t"}, func(f *fixture) {
			s, _ := f.st.GetServer(t.Context(), srvID)
			s.Status = store.MCPServerDisabled
			f.st.put(*s)
		}, "tool:tool_not_found"},
		// Credentials are not the precheck's business: the dispatch
		// answers auth_required with the connect link.
		{"not connected", alice, "notes.create_note", map[string]any{"title": "t"}, func(f *fixture) {
			f.creds.errs[alice] = auth.ErrNotConnected
		}, ""},
		{"built-in tool", alice, "github.list_issues", map[string]any{"anything": 1}, nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFixture(t)
			f.up.reset()
			if tc.setup != nil {
				tc.setup(f)
			}
			err := f.precheck(t, tc.user, tc.tool, tc.args)
			if got := toolErrClass(err); got != tc.want {
				t.Errorf("precheck = %s, want %q (err %v)", got, tc.want, err)
			}
			if err != nil && (strings.Contains(err.Error(), "7") || strings.Contains(err.Error(), "bob")) {
				t.Errorf("message echoes an argument: %v", err)
			}
			if n := len(f.up.seen()); n != 0 {
				t.Errorf("precheck contacted the upstream (%d requests)", n)
			}
		})
	}
}

// The dispatch keeps its own check: a review that changes between the
// precheck (approval) and the retry is still refused before the upstream.
func TestManagerDispatchStillChecksAfterPrecheck(t *testing.T) {
	f := newFixture(t)
	if err := f.precheck(t, alice, "notes.create_note", map[string]any{"title": "t"}); err != nil {
		t.Fatalf("precheck: %v", err)
	}
	f.snaps.setReview("create_note", snapshot.ToolReview{Enabled: false, Kind: snapshot.KindWrite})
	f.up.reset()
	_, err := f.call(t, alice, "notes.create_note", map[string]any{"title": "t"})
	if got := toolErrClass(err); got != "tool:tool_disabled" {
		t.Errorf("dispatch after the review changed = %s", got)
	}
	if n := len(f.up.seen()); n != 0 {
		t.Errorf("dispatch contacted the upstream (%d requests)", n)
	}
}
