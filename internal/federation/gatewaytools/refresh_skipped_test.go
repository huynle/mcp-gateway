package gatewaytools

import (
	"testing"

	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/store"
)

func TestRefreshServerListsSkippedItems(t *testing.T) {
	w := newWorld(t)
	w.servers.add(store.MCPServer{Name: "notes", URL: "https://notes.example.com/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthNone})
	w.snaps.skipped = []snapshot.Skipped{{Kind: snapshot.SkippedTool, Name: "evil", Reason: snapshot.ReasonInvalidName}}
	out := w.ok(alice, ToolRefreshServer, map[string]any{"server": "notes"})
	if got := jsonString(out["skipped"]); got != `[{"kind":"tool","name":"evil","reason":"invalid name"}]` {
		t.Errorf("skipped = %s (refresh = %s)", got, jsonString(out))
	}
	// Nothing skipped: an empty list, never null.
	w.snaps.skipped = nil
	out = w.ok(alice, ToolRefreshServer, map[string]any{"server": "notes"})
	if got := jsonString(out["skipped"]); got != `[]` {
		t.Errorf("clean skipped = %s", got)
	}
}
