//go:build integration || e2e

package e2e

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/store"
)

// TestE2EPluginsIdenticalUpstreamCallsBothRun (quirk 47ab9sk7): a tool of
// a user-added server without readOnlyHint (here a Brain-like "recall")
// is a write to the gateway. Calling it twice with identical arguments
// reaches the upstream twice and returns its result both times, each call
// its own ledger operation; nothing answers "_ledger": "replayed".
func TestE2EPluginsIdenticalUpstreamCallsBothRun(t *testing.T) {
	var recalls atomic.Int32
	s := sdk.NewServer(&sdk.Implementation{Name: "mind", Version: "1"}, nil)
	sdk.AddTool(s, &sdk.Tool{Name: "recall", Description: "Recall an entry."},
		func(_ context.Context, _ *sdk.CallToolRequest, in jotIn) (*sdk.CallToolResult, any, error) {
			recalls.Add(1)
			return textResult("entry " + in.Text), nil, nil
		})
	w := newWorld(t, options{federation: true})
	w.allowLoopback()
	id := w.addServer(w.alice, url.Values{"name": {"mind"}, "url_mode": {"https"}, "url": {newOpenUpstream(t, s).URL},
		"auth_kind": {"none"}, "credential_mode": {"per_user"}})
	w.approve(w.alice, id, w.refresh(w.alice, id), "recall")

	// Run without asking, as owners do for tools they trust.
	p := w.page(w.alice, "/servers/"+id)
	version := versionRE.FindStringSubmatch(p.body)
	if p.status != http.StatusOK || version == nil {
		t.Fatalf("server page (%d):\n%s", p.status, snippet(p.body))
	}
	mustRedirect(t, "all auto", w.submit(w.alice, "/servers/"+id+"/approval", url.Values{"version": {version[1]}, "all": {"auto"}}),
		"/servers/"+id+"?modes=1")

	alice := w.client(w.alice)
	for i := range 2 {
		res, err := w.call(alice, "mind.recall", map[string]any{"text": "m5bgl1ye"})
		if err != nil || res.IsError {
			t.Fatalf("call %d: err=%v res=%+v", i+1, err, res)
		}
		if got := text(t, res); got != "entry m5bgl1ye" || strings.Contains(got, "replayed") {
			t.Errorf("call %d = %q, want the upstream's result", i+1, got)
		}
	}
	if n := recalls.Load(); n != 2 {
		t.Errorf("upstream calls = %d, want 2", n)
	}
	var ops int
	for _, row := range w.ops(w.alice) {
		if row.Tool == "mind.recall" {
			ops++
			if row.State != store.LedgerSucceeded || !strings.HasPrefix(row.IdempotencyKey, "call:") {
				t.Errorf("op = %s %s", row.State, row.IdempotencyKey)
			}
		}
	}
	if ops != 2 {
		t.Errorf("ledger operations = %d, want 2", ops)
	}
	for _, ev := range w.events(w.alice) {
		if ev.Tool == "mind.recall" && ev.ErrorClass == "replayed" {
			t.Errorf("audited as replayed: %+v", ev)
		}
	}
}
