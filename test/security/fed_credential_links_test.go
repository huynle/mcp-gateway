//go:build integration || e2e || security

package security

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// credentialLinksWorld publishes alice's shared-key server "wiki" to bob's
// role, then removes its shared credential, and returns the raw wire
// answers of a wiki.search by bob and by alice (the owner).
func credentialLinksWorld(t *testing.T, on bool) (w *world, wiki *store.MCPServer, bobBody, aliceBody []byte) {
	t.Helper()
	w = newWorld(t, options{federation: true, credentialLinks: on})
	ctx := t.Context()
	w.allowLoopback()
	const sharedKey = "shared-wiki-key-links-1"
	w.forbid(sharedKey, "upstream API key")
	up := newUpstream(t, notesServer)
	up.setGate(requireKey(sharedKey))
	wiki = w.addServer(w.alice, "wiki", up.URL(), func(s *store.MCPServer) {
		apiKeyServer(s)
		s.CredentialMode = store.MCPCredentialShared
	})
	if err := w.fed.Auth.SetSharedCredential(ctx, auth.Actor{UserID: w.alice.id}, wiki.ID, auth.Credential{APIKey: sharedKey}); err != nil {
		t.Fatal(err)
	}
	w.review(w.alice, wiki, "search")
	w.publish(wiki, []policy.ToolRule{{App: "wiki", Tool: "search", Outcome: policy.OutcomeAllow}}, roleRestricted)
	w.exec(`DELETE FROM mcp_server_shared_secrets WHERE server_id = $1`, wiki.ID)
	bobTok := w.token(w.bob, tokens.CreateRequest{Name: "bob-links"})
	aliceTok := w.token(w.alice, tokens.CreateRequest{Name: "alice-links"})
	_, _, bobBody = w.rawCall(bobTok, "wiki.search", map[string]any{"q": "x"})
	_, _, aliceBody = w.rawCall(aliceTok, "wiki.search", map[string]any{"q": "x"})
	return w, wiki, bobBody, aliceBody
}

// TestSecurityFedCredentialLinksOwnerOnly: with credential links on, a
// shared server's missing credential is the owner's to fix. Only the
// owner's answer carries the edit link; everyone else gets the answer the
// gateway gave before the flag, byte for byte (no edit link, no hint of
// the cause), and the class stays server_not_configured.
func TestSecurityFedCredentialLinksOwnerOnly(t *testing.T) {
	_, _, bobOff, aliceOff := credentialLinksWorld(t, false)
	w, wiki, bobOn, aliceOn := credentialLinksWorld(t, true)
	if !bytes.Equal(bobOn, bobOff) {
		t.Errorf("non-owner answer changed with credential links:\n on: %s\noff: %s", bobOn, bobOff)
	}
	if !bytes.Contains(bobOff, []byte(`"code":-32031`)) || !bytes.Contains(bobOff, []byte("ask its owner")) {
		t.Errorf("non-owner answer = %s, want today's -32031 server_not_configured", bobOff)
	}
	for _, leak := range []string{"/edit", "elicitation", "-32042", "shared credential is missing", wiki.ID} {
		if bytes.Contains(bobOn, []byte(leak)) {
			t.Errorf("non-owner answer leaks %q: %s", leak, bobOn)
		}
	}
	if !bytes.Contains(aliceOff, []byte(`"code":-32031`)) {
		t.Errorf("owner answer without the flag = %s", aliceOff)
	}
	var msg struct {
		Error struct {
			Code int64          `json:"code"`
			Data map[string]any `json:"data"`
		} `json:"error"`
	}
	if err := json.Unmarshal(aliceOn, &msg); err != nil {
		t.Fatalf("owner answer %s: %v", aliceOn, err)
	}
	if msg.Error.Code != -32042 || msg.Error.Data["url"] != baseURL+"/servers/"+wiki.ID+"/edit" {
		t.Errorf("owner answer = %s, want -32042 with the edit link", aliceOn)
	}
	for _, ev := range w.allEvents() {
		if ev.Tool == "wiki.search" && ev.ErrorClass != "server_not_configured" {
			t.Errorf("audit class = %q, want server_not_configured", ev.ErrorClass)
		}
	}
}

// TestSecurityFedCredentialLinksPerUser: on a published per-user server
// each user without a connection gets their own link: the connection
// section of the server (never the owner's edit page) and an elicitation
// id that differs from every other user's and carries no ids.
func TestSecurityFedCredentialLinksPerUser(t *testing.T) {
	w := newWorld(t, options{federation: true, credentialLinks: true})
	ctx := t.Context()
	w.allowLoopback()
	const aliceKey = "alice-notes-key-links-2"
	w.forbid(aliceKey, "upstream API key")
	up := newUpstream(t, notesServer)
	up.setGate(requireKey(aliceKey))
	notes := w.addServer(w.alice, "notes", up.URL(), apiKeyServer)
	if err := w.fed.Auth.SetUserCredential(ctx, w.alice.id, notes.ID, auth.Credential{APIKey: aliceKey}); err != nil {
		t.Fatal(err)
	}
	w.review(w.alice, notes, "search")
	w.publish(notes, []policy.ToolRule{{App: "notes", Tool: "search", Outcome: policy.OutcomeAllow}}, roleRestricted)
	if err := w.fed.Auth.Disconnect(ctx, w.alice.id, notes.ID); err != nil {
		t.Fatal(err)
	}
	ids := map[string]string{}
	for _, u := range []user{w.alice, w.bob} {
		_, _, body := w.rawCall(w.token(u, tokens.CreateRequest{Name: "links-" + u.id}), "notes.search", map[string]any{"q": "x"})
		var msg struct {
			Error struct {
				Code    int64  `json:"code"`
				Message string `json:"message"`
				Data    struct {
					URL          string `json:"url"`
					Elicitations []struct {
						ID string `json:"elicitationId"`
					} `json:"elicitations"`
				} `json:"data"`
			} `json:"error"`
		}
		if err := json.Unmarshal(body, &msg); err != nil {
			t.Fatalf("%s: %s: %v", u.id, body, err)
		}
		e := msg.Error
		if e.Code != -32042 || e.Data.URL != baseURL+"/servers/"+notes.ID+"#connection" || len(e.Data.Elicitations) != 1 {
			t.Fatalf("%s answer = %s, want -32042 with the connection link", u.id, body)
		}
		id := e.Data.Elicitations[0].ID
		if !strings.HasPrefix(id, "gwc_") || strings.Contains(id, u.id) || strings.Contains(id, notes.ID) {
			t.Errorf("elicitation id %q", id)
		}
		if strings.Contains(string(body), "/edit") {
			t.Errorf("%s got the edit link: %s", u.id, body)
		}
		ids[u.id] = id
	}
	if ids[w.alice.id] == ids[w.bob.id] {
		t.Errorf("alice and bob share an elicitation id: %v", ids)
	}
}
