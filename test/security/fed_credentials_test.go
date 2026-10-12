//go:build integration || e2e || security

package security

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	fedadmin "github.com/huynle/mcp-gateway/internal/federation/admin"
	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/store"
)

// TestSecurityFedURLSwapNeverCarriesOtherUsersCredentials: the address
// of a published server decides where every user's arguments and
// credentials go.
//
//   - The owner may not move a published server (medium finding of task
//     rvrfpzzj, fixed by Brain task mpszh6h0: portal 422, schema 17
//     trigger); bob keeps reaching the reviewed upstream.
//   - An admin may move it; the approved snapshot is withdrawn, so its
//     tools disappear for everyone and nothing reaches the new address
//     until an admin re-reviews it.
//   - Even after the re-review, other users' per-user API keys and the
//     shared credential an admin set never follow the server to the new
//     address (credentials are sealed to the URL, decision 4l6dik46):
//     they are unusable (reconnect / not configured) and the new upstream
//     sees none of them.
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
	evil := newUpstream(t, notesServer) // the new address: accepts anything

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

	// 1. The owner tries to point both servers at another address: refused
	// on the service path (database trigger) and on the portal (422).
	for _, s := range []*store.MCPServer{notes, wiki} {
		moved := *s
		moved.URL = evil.URL()
		if err := w.fed.Manager.UpdateServer(ctx, w.alice.id, &moved); !errors.Is(err, store.ErrMCPServerLocked) {
			t.Fatalf("owner URL change of published %s = %v, want ErrMCPServerLocked", s.Name, err)
		}
		code, _, body := w.post(w.alice, "/servers/"+s.ID+"/edit", url.Values{"url_mode": {"https"}, "url": {evil.URL()},
			"auth_kind": {store.MCPAuthAPIKey}, "credential_mode": {s.CredentialMode}, "shared_api_key": {"owner-key"}})
		if code != http.StatusUnprocessableEntity || !strings.Contains(body, "This server is shared; ask an admin to change its address or sign-in settings.") {
			t.Fatalf("owner portal edit of published %s: %d", s.Name, code)
		}
		if got := w.queryString(`SELECT url FROM mcp_servers WHERE id = $1`, s.ID); got != legit.URL() {
			t.Fatalf("%s url = %q after the refused edits", s.Name, got)
		}
	}
	res, err = w.call(bob, "notes.search", map[string]any{"q": "still"})
	if err != nil || text(t, res) != "results for "+bobKey {
		t.Fatalf("bob after the refused owner edits: %v %+v", err, res)
	}
	if n := len(evil.requests()); n != 0 {
		t.Fatalf("the owner's address received %d requests", n)
	}

	// 2. An admin moves both servers: the approval is withdrawn, the tools
	// disappear and nothing reaches the new address.
	// (The test upstreams are plain http on loopback, which the admin
	// page refuses, so the change goes through the page's store and hook.)
	as := fedadmin.NewStore(w.st)
	for _, s := range []*store.MCPServer{notes, wiki} {
		if err := as.UpdateAddress(ctx, s.ID, evil.URL()); err != nil {
			t.Fatalf("admin address change of %s: %v", s.Name, err)
		}
		if err := w.fed.Manager.ServerChanged(ctx, s.ID); err != nil {
			t.Fatal(err)
		}
		code, _, page := w.get(w.admin, "/admin/servers/"+s.ID)
		if code != http.StatusOK || !strings.Contains(page, "Re-review required") || !strings.Contains(page, "/admin/servers/"+s.ID+"/review") {
			t.Errorf("admin page of %s does not ask for a re-review: %d", s.Name, code)
		}
	}
	for _, name := range toolNames(t, bob) {
		if name == "notes.search" || name == "wiki.search" {
			t.Errorf("tools/list still offers %s after the address change", name)
		}
	}
	if _, err := w.call(bob, "notes.search", map[string]any{"q": "moved"}); err == nil {
		t.Error("bob's call of notes.search succeeded before the re-review")
	}
	if _, err := w.call(bob, "wiki.search", map[string]any{"q": "moved"}); err == nil {
		t.Error("bob's call of wiki.search succeeded before the re-review")
	}
	if n := len(evil.requests()); n != 0 {
		t.Fatalf("the new address received %d requests before the re-review", n)
	}

	// 3. The admin re-approves the snapshots: the tools are back, but no
	// stored credential follows the server to the new address.
	for _, s := range []*store.MCPServer{notes, wiki} {
		admin := snapshot.Actor{UserID: w.admin.id, Admin: true}
		latest, err := w.fed.Snapshots.Latest(ctx, admin, s.ID)
		if err != nil {
			t.Fatal(err)
		}
		on := true
		if _, err := w.fed.Snapshots.Approve(ctx, admin, s.ID, latest.Version,
			snapshot.ReviewDecisions{Tools: map[string]snapshot.Decision{"search": {Enabled: &on}}}); err != nil {
			t.Fatalf("re-approve %s: %v", s.Name, err)
		}
		if err := w.fed.Manager.ServerChanged(ctx, s.ID); err != nil {
			t.Fatal(err)
		}
	}
	if names := toolNames(t, bob); !contains(names, "notes.search") || !contains(names, "wiki.search") {
		t.Fatalf("tools after the re-review: %v", names)
	}
	_, errNotes := w.call(bob, "notes.search", map[string]any{"q": "after"})
	_, errWiki := w.call(bob, "wiki.search", map[string]any{"q": "after"})
	// Alice (owner) keeps the owner layer on her published server (task
	// fekckdrt), so her call resolves; her stored key must still not
	// follow the server to the new URL.
	_, _ = w.call(w.client(w.alice), "notes.search", map[string]any{"q": "after"})
	if evil.sawValue(bobKey) {
		t.Error("bob's per-user API key reached the server's new URL")
	}
	if evil.sawValue(sharedKey) {
		t.Error("the admin-set shared credential reached the server's new URL")
	}
	if evil.sawValue(aliceKey) {
		t.Error("alice's stored key followed the URL change without being entered again")
	}
	_ = rpcError(t, errNotes, mcp.CodeNoAccount)
	_ = rpcError(t, errWiki, mcp.CodeNoAccount)
}
