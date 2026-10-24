//go:build integration

package snapshot_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/federation/client"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/federation/tooldigest"
	"github.com/huynle/mcp-gateway/internal/machineclient"
	"github.com/huynle/mcp-gateway/internal/netguard"
	"github.com/huynle/mcp-gateway/internal/store"
)

// The digest the gateway computes from an approved snapshot (discovered
// through a real client session, stored as jsonb, read back) is the
// digest the upstream computes from its own definition: the machine
// actions server's ActionDigest, and tooldigest.Digest of a plain tool
// whose schema has numbers, escapes and keys jsonb reorders.
func TestIntegrationApprovedToolDigestMatchesTheServer(t *testing.T) {
	st := openTestStore(t)
	ctx := t.Context()
	svc := snapshot.NewService(st)
	ownerID := newUser(t, st, "digest-owner")
	owner := snapshot.Actor{UserID: ownerID}

	mc, err := machineclient.ParseConfig([]byte(`
actions:
  report:
    run: /bin/sh -c 'cat >/dev/null' {host} --port={port}
    secret: stdin
    description: "Weekly <report> & \"stats\" — ünïcode \\ backslash"
    params:
      host: '[a-z0-9.-]+'
      port: '[0-9]{2,5}'
`))
	if err != nil {
		t.Fatal(err)
	}
	actions := httptest.NewServer(machineclient.NewActionsHandler(mc.Actions, machineclient.ActionsOptions{Version: "test"}))
	t.Cleanup(actions.Close)

	plainSchema := json.RawMessage(`{"type":"object","properties":{"n":{"type":"number","minimum":1.0,"maximum":1e2,"default":0.50},` +
		`"s":{"type":"string","pattern":"^<a>&\u00e9$","enum":["\u2028","x"]}},"required":["n"],"additionalProperties":false}`)
	var plainIn map[string]any
	if err := json.Unmarshal(plainSchema, &plainIn); err != nil {
		t.Fatal(err)
	}
	plain := &mcp.Tool{Name: "plain", Description: "line one\nline <two>", InputSchema: plainIn}
	ps := mcp.NewServer(&mcp.Implementation{Name: "plain", Version: "1"}, nil)
	ps.AddTool(plain, func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		return &mcp.CallToolResult{}, nil
	})
	plainSrv := httptest.NewServer(mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return ps },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true}))
	t.Cleanup(plainSrv.Close)

	allow, _ := netguard.NewStaticAllowList("127.0.0.1")
	c, err := client.New(client.Options{HTTPClient: netguard.New(netguard.Options{AllowList: allow}).Client()})
	if err != nil {
		t.Fatal(err)
	}
	approved := func(name, url, tool string) snapshot.Tool {
		t.Helper()
		srv := newServer(t, st, ownerID, name)
		sess, err := c.Connect(ctx, client.Endpoint{URL: url})
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = sess.Close() }()
		rec, _, err := svc.Refresh(ctx, owner, srv, sess)
		if err != nil {
			t.Fatal(err)
		}
		if rec.Status == store.MCPSnapshotApproved {
			t.Fatal("a refresh must not approve")
		}
		if _, err := svc.Current(ctx, owner, srv); err == nil {
			t.Fatal("an approved snapshot exists before the review")
		}
		on := true
		if _, err := svc.Approve(ctx, owner, srv, rec.Version,
			snapshot.ReviewDecisions{Tools: map[string]snapshot.Decision{tool: {Enabled: &on}}}); err != nil {
			t.Fatal(err)
		}
		cur, err := svc.Current(ctx, owner, srv)
		if err != nil {
			t.Fatal(err)
		}
		got, ok := cur.Snapshot.Tool(tool)
		if !ok {
			t.Fatalf("%s not in the approved snapshot", tool)
		}
		return got
	}

	got := approved("digest-actions", actions.URL, "report")
	if d, want := tooldigest.Digest(got.Name, got.Description, got.InputSchema), machineclient.ActionDigest(mc.Actions["report"]); d != want {
		t.Fatalf("approved action digest %s, actions server %s\nstored schema %s", d, want, got.InputSchema)
	}

	got = approved("digest-plain", plainSrv.URL, "plain")
	if d, want := tooldigest.Digest(got.Name, got.Description, got.InputSchema), tooldigest.Digest(plain.Name, plain.Description, plainSchema); d != want {
		t.Fatalf("approved plain digest %s, upstream %s\nstored schema %s", d, want, got.InputSchema)
	}
}
