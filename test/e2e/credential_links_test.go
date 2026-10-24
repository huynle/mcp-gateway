//go:build integration || e2e

package e2e

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/store"
)

// credentialLink asserts err is a -32042 credential link with url (in
// data.url, one elicitation and the message) for the notes server.
func credentialLink(t *testing.T, err error, url string) {
	t.Helper()
	je := rpcError(t, err, -32042)
	var data map[string]any
	if err := json.Unmarshal(je.Data, &data); err != nil {
		t.Fatalf("error data %s: %v", je.Data, err)
	}
	list, _ := data["elicitations"].([]any)
	if data["url"] != url || data["server"] != "notes" || len(list) != 1 {
		t.Fatalf("data = %v, want url %s, server notes, one elicitation", data, url)
	}
	e, _ := list[0].(map[string]any)
	if e["mode"] != "url" || e["url"] != url || !strings.HasPrefix(e["elicitationId"].(string), "gwc_") {
		t.Fatalf("elicitation = %v", e)
	}
	if !strings.Contains(je.Message, url) {
		t.Fatalf("message %q does not carry the link", je.Message)
	}
}

// TestE2ECredentialLinks (GATEWAY_CREDENTIAL_LINKS_ENABLED, plan 1 of
// docs/plans/2026-10-23-credential-links-and-elicitation-relay-design.md),
// through the official SDK client:
//
//  1. a per-user API key server without the caller's connection answers
//     -32042 with <base>/servers/<id>#connection (class no_account in the
//     audit row, as before); once the user sets their key the retry runs;
//  2. the owner declares a per-user header: a call without the user's
//     value answers -32042 user_header_missing with the same link, and
//     nothing reaches the upstream; once set, the retry runs and the
//     upstream sees the value.
func TestE2ECredentialLinks(t *testing.T) {
	w := newWorld(t, options{federation: true, credentialLinks: true})
	ctx := t.Context()
	for k := range notesKeys {
		w.forbid(k, "upstream API key")
	}
	up := newNotesUpstream(t)
	err := w.st.WithJobs(ctx, func(tx store.Tx) error {
		return store.CreateNetguardAllowHost(ctx, tx, &store.NetguardAllowHost{Pattern: "127.0.0.1", Note: "e2e upstream"})
	})
	if err != nil {
		t.Fatal(err)
	}
	server := &store.MCPServer{
		Name: "notes", URL: up.srv.URL, OwnerUserID: w.alice.id,
		CredentialMode: store.MCPCredentialPerUser, AuthKind: store.MCPAuthAPIKey,
		AuthConfig: []byte(`{"api_key":{"header":"X-Notes-Key"}}`),
	}
	if err := w.fed.Manager.CreateServer(ctx, server); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	key := auth.Credential{APIKey: "alice-notes-key-e2e"}
	if err := w.fed.Auth.SetUserCredential(ctx, w.alice.id, server.ID, key); err != nil {
		t.Fatal(err)
	}
	review(t, w, w.alice, server, false, map[string]bool{"search": true})
	alice := w.client(w.alice)
	connection := baseURL + "/servers/" + server.ID + "#connection"

	// 1. No connection: the account stage answers with the link.
	if err := w.fed.Auth.Disconnect(ctx, w.alice.id, server.ID); err != nil {
		t.Fatal(err)
	}
	_, err = w.call(alice, "notes.search", map[string]any{"q": "x"})
	credentialLink(t, err, connection)
	found := false
	for _, ev := range w.events(w.alice) {
		found = found || (ev.Tool == "notes.search" && ev.ErrorClass == "no_account" && ev.Outcome == "failed")
	}
	if !found {
		t.Error("no audit row with class no_account for the linked answer")
	}
	if err := w.fed.Auth.SetUserCredential(ctx, w.alice.id, server.ID, key); err != nil {
		t.Fatal(err)
	}
	res, err := w.call(alice, "notes.search", map[string]any{"q": "x"})
	if err != nil || text(t, res) != "results for alice" {
		t.Fatalf("retry after connecting: %v %+v", err, res)
	}

	// 2. A declared per-user header without the user's value.
	server.HeaderConfig = []byte(`{"per_user":["X-Notes-Project"]}`)
	if err := w.fed.Manager.UpdateServer(ctx, w.alice.id, server); err != nil {
		t.Fatalf("UpdateServer: %v", err)
	}
	before := len(up.allHeaders())
	_, err = w.call(alice, "notes.search", map[string]any{"q": "x"})
	credentialLink(t, err, connection)
	if n := len(up.allHeaders()); n != before {
		t.Errorf("the upstream was called %d times without the per-user header", n-before)
	}
	found = false
	for _, ev := range w.events(w.alice) {
		found = found || (ev.Tool == "notes.search" && ev.ErrorClass == "user_header_missing")
	}
	if !found {
		t.Error("no audit row with class user_header_missing")
	}
	key.Headers = map[string]string{"X-Notes-Project": "e2e-project"}
	if err := w.fed.Auth.SetUserCredential(ctx, w.alice.id, server.ID, key); err != nil {
		t.Fatal(err)
	}
	res, err = w.call(alice, "notes.search", map[string]any{"q": "x"})
	if err != nil || text(t, res) != "results for alice" {
		t.Fatalf("retry after setting the header: %v %+v", err, res)
	}
	hs := up.allHeaders()
	if got := hs[len(hs)-1].Get("X-Notes-Project"); got != "e2e-project" {
		t.Errorf("upstream saw X-Notes-Project = %q", got)
	}
}
