//go:build integration || e2e || security

package security

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/mcp"
)

// TestSecurityScopeRequiredEnforcedInPipeline: a tool whose
// RequiredScopes the resolved account's recorded scopes do not cover is
// refused by the pipeline itself with a clear scope_required error
// before any connector code runs (the connectors' own checks stay as
// defence in depth). An account without recorded scopes (GitHub App user
// tokens carry none) is not blocked. tools/list stays per-principal: the
// tool is listed even for the under-scoped account, because visibility
// is decided before any account is known and a user may hold several
// accounts with different grants; the call answers scope_required with
// the account and the missing scopes so the harness can tell the user
// which account to re-grant.
func TestSecurityScopeRequiredEnforcedInPipeline(t *testing.T) {
	w := newWorld(t, options{})
	// bob's Slack account granted channels:read only; list_channels
	// needs channels:read and groups:read.
	w.exec(`UPDATE connections SET scopes = $1 WHERE id = $2`, []string{"channels:read"}, w.bobSlack)
	// alice's Slack account carries chat:write and both read scopes.
	w.exec(`UPDATE connections SET scopes = $1 WHERE id = $2`, []string{"channels:read", "groups:read", "chat:write"}, w.aliceSlack)

	bob, alice := w.client(w.bob), w.client(w.alice)
	if names := toolNames(t, bob); !contains(names, "slack.list_channels") {
		t.Fatalf("tools/list for bob lacks slack.list_channels: %v", names)
	}
	before := w.slack.count()
	_, err := w.call(bob, "slack.list_channels", map[string]any{})
	je := rpcError(t, err, mcp.CodeScopeRequired)
	if !strings.Contains(je.Message, "groups:read") || strings.Contains(je.Message, "channels:read") {
		t.Errorf("message = %q, want the missing scope only", je.Message)
	}
	var data map[string]any
	if err := json.Unmarshal(je.Data, &data); err != nil {
		t.Fatalf("error data %s: %v", je.Data, err)
	}
	if data["account"] != w.bobSlack || data["app"] != "slack" {
		t.Errorf("error data = %v", data)
	}
	missing, _ := data["missing_scopes"].([]any)
	if len(missing) != 1 || missing[0] != "groups:read" {
		t.Errorf("missing_scopes = %v", data["missing_scopes"])
	}
	if portal, _ := data["portal_url"].(string); !strings.HasPrefix(portal, baseURL+"/connections") {
		t.Errorf("portal_url = %v", data["portal_url"])
	}
	if w.slack.count() != before {
		t.Errorf("the vendor was called %d times for an under-scoped account", w.slack.count()-before)
	}
	var audited bool
	for _, ev := range w.events(w.bob) {
		if ev.Tool == "slack.list_channels" && ev.ErrorClass == "scope_required" && ev.Outcome == "failed" && ev.AccountID == w.bobSlack {
			audited = true
		}
	}
	if !audited {
		t.Errorf("no audit row with class scope_required for bob")
	}

	// alice: covered, the call reaches the stub.
	if res, err := w.call(alice, "slack.list_channels", map[string]any{}); err != nil || res.IsError {
		t.Fatalf("alice list_channels: err=%v res=%+v", err, res)
	}
	// Scopes compare case-insensitively (vendors differ in casing).
	w.exec(`UPDATE connections SET scopes = $1 WHERE id = $2`, []string{"Channels:Read", "GROUPS:READ"}, w.bobSlack)
	if res, err := w.call(bob, "slack.list_channels", map[string]any{}); err != nil || res.IsError {
		t.Fatalf("bob list_channels with differently cased scopes: err=%v res=%+v", err, res)
	}
	// No recorded scopes: not blocked (the vendor decides).
	w.exec(`UPDATE connections SET scopes = NULL WHERE id = $1`, w.bobSlack)
	if res, err := w.call(bob, "slack.list_channels", map[string]any{}); err != nil || res.IsError {
		t.Fatalf("bob list_channels without recorded scopes: err=%v res=%+v", err, res)
	}
}
