//go:build integration || e2e || security

package security

import (
	"testing"

	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/store"
)

// TestSecurityFedURLSwapNeverCarriesOtherUsersCredentials: the owner of a
// published server may still edit its URL (RLS mcp_servers_owner_update,
// column grant on url). Other users' per-user API keys and the shared
// credential an admin set must never follow the server to the new
// address: the owner would harvest them. After the swap the stored
// credentials are unusable (reconnect / not configured) and the new
// upstream sees none of them.
func TestSecurityFedURLSwapNeverCarriesOtherUsersCredentials(t *testing.T) {
	w := newWorld(t, options{federation: true})
	ctx := t.Context()
	w.allowLoopback()
	const aliceKey, bobKey, sharedKey = "alice-notes-key-swap-1", "bob-notes-key-swap-2", "shared-wiki-key-swap-3"
	for _, k := range []string{aliceKey, bobKey, sharedKey} {
		w.forbid(k, "upstream API key")
	}
	legit := newUpstream(t, notesServer)
	legit.setGate(requireKey(aliceKey, bobKey, sharedKey))
	evil := newUpstream(t, notesServer) // the owner's capture server: accepts anything

	// Per-user credentials: alice publishes "notes"; bob stores his key.
	notes := w.addServer(w.alice, "notes", legit.URL(), apiKeyServer)
	if err := w.fed.Auth.SetUserCredential(ctx, w.alice.id, notes.ID, auth.Credential{APIKey: aliceKey}); err != nil {
		t.Fatal(err)
	}
	w.review(w.alice, notes, "search")
	w.publish(notes, []policy.ToolRule{{App: "notes", Tool: "search", Outcome: policy.OutcomeAllow}}, roleRestricted)
	if err := w.fed.Auth.SetUserCredential(ctx, w.bob.id, notes.ID, auth.Credential{APIKey: bobKey}); err != nil {
		t.Fatal(err)
	}
	bob := w.client(w.bob)
	res, err := w.call(bob, "notes.search", map[string]any{"q": "x"})
	if err != nil || text(t, res) != "results for "+bobKey {
		t.Fatalf("bob before the swap: %v %+v", err, res)
	}

	// Shared credential: alice's "wiki", published, credential set by an admin.
	wiki := w.addServer(w.alice, "wiki", legit.URL(), func(s *store.MCPServer) {
		apiKeyServer(s)
		s.CredentialMode = store.MCPCredentialShared
	})
	if err := w.fed.Auth.SetSharedCredential(ctx, auth.Actor{UserID: w.admin.id, Admin: true}, wiki.ID, auth.Credential{APIKey: sharedKey}); err != nil {
		t.Fatal(err)
	}
	w.reviewAs(w.admin, true, wiki, "search")
	w.publish(wiki, []policy.ToolRule{{App: "wiki", Tool: "search", Outcome: policy.OutcomeAllow}}, roleRestricted)
	res, err = w.call(bob, "wiki.search", map[string]any{"q": "x"})
	if err != nil || text(t, res) != "results for "+sharedKey {
		t.Fatalf("bob on wiki before the swap: %v %+v", err, res)
	}

	// The owner points both servers at her capture server.
	for _, s := range []*store.MCPServer{notes, wiki} {
		s.URL = evil.URL()
		if err := w.fed.Manager.UpdateServer(ctx, w.alice.id, s); err != nil {
			t.Fatalf("owner URL change of %s: %v", s.Name, err)
		}
	}
	_, errNotes := w.call(bob, "notes.search", map[string]any{"q": "after"})
	_, errWiki := w.call(bob, "wiki.search", map[string]any{"q": "after"})
	// Alice (owner) holds no role granting the published tools (no owner
	// layer once published), so her call never resolves; it must not
	// leak her stored key either way.
	_, _ = w.call(w.client(w.alice), "notes.search", map[string]any{"q": "after"})
	if evil.sawValue(bobKey) {
		t.Error("bob's per-user API key reached the URL the owner switched to")
	}
	if evil.sawValue(sharedKey) {
		t.Error("the admin-set shared credential reached the URL the owner switched to")
	}
	if evil.sawValue(aliceKey) {
		t.Error("alice's stored key followed the URL change without being entered again")
	}
	_ = rpcError(t, errNotes, mcp.CodeNoAccount)
	_ = rpcError(t, errWiki, mcp.CodeNoAccount)
}
