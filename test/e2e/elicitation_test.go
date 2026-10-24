//go:build integration || e2e

package e2e

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/store"
)

// The upstream's elicitation, as it asks for it. The fake upstream runs on
// 127.0.0.1, which has no registrable domain, so the server's owner lists
// the page's origin (elicitation_origins) — the documented way for servers
// without a DNS name (tunnels, IPs) — instead of resolving a test hostname.
const (
	linkedOrigin  = "https://connect.linked.example"
	linkedURL     = linkedOrigin + "/connect?x=1"
	linkedMessage = "Paste your Linked API token <script>alert(1)</script>"
	linkedUpID    = "linked-upstream-elicitation-1"
)

// linkedUpstream is a per-user server whose sync tool needs a second
// credential the user gives on the upstream's own page: until connect
// flips its state for a user, sync answers -32042 with linkedURL.
type linkedUpstream struct {
	srv       *httptest.Server
	mu        sync.Mutex
	connected map[string]bool
	paths     []string
}

func newLinkedUpstream(t *testing.T) *linkedUpstream {
	t.Helper()
	u := &linkedUpstream{connected: map[string]bool{}}
	s := sdk.NewServer(&sdk.Implementation{Name: "linked", Version: "1"}, nil)
	sdk.AddTool(s, &sdk.Tool{Name: "sync", Description: "Sync the Linked account.", Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}},
		func(_ context.Context, req *sdk.CallToolRequest, _ struct{}) (*sdk.CallToolResult, any, error) {
			who := notesKeys[req.Extra.Header.Get("X-Notes-Key")]
			u.mu.Lock()
			ok := u.connected[who]
			u.mu.Unlock()
			if !ok {
				return nil, nil, sdk.URLElicitationRequiredError([]*sdk.ElicitParams{{
					Mode: "url", ElicitationID: linkedUpID, URL: linkedURL, Message: linkedMessage,
				}})
			}
			return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "synced for " + who}}}, nil, nil
		})
	h := sdk.NewStreamableHTTPHandler(func(*http.Request) *sdk.Server { return s }, &sdk.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
	u.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.paths = append(u.paths, r.URL.Path)
		u.mu.Unlock()
		if _, ok := notesKeys[r.Header.Get("X-Notes-Key")]; !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(u.srv.Close)
	return u
}

// connect is the user finishing on the upstream's own page.
func (u *linkedUpstream) connect(who string) {
	u.mu.Lock()
	u.connected[who] = true
	u.mu.Unlock()
}

// TestE2EUpstreamElicitationRelay (GATEWAY_UPSTREAM_ELICITATION_ENABLED,
// plan 2 of docs/plans/2026-10-23-credential-links-and-elicitation-relay-design.md),
// through the official SDK client:
//
//  1. a per-user server answers -32042 with its own page: the harness gets
//     the gateway's <base>/elicit/<id> link, a gwe_ id and a fixed message,
//     never the upstream URL, id or message;
//  2. the owner opens the link: the interstitial shows the server, the full
//     URL and its domain, and the upstream message as inert text;
//  3. Continue without the CSRF token is refused; with it, 303 to exactly
//     the upstream URL (the gateway never fetched it);
//  4. the user completes on the upstream's page and the retry succeeds;
//  5. the upstream URL and message are nowhere in logs or audit rows.
func TestE2EUpstreamElicitationRelay(t *testing.T) {
	w := newWorld(t, options{federation: true, upstreamElicitation: true})
	ctx := t.Context()
	w.forbid(linkedURL, "upstream elicitation URL")
	w.forbid("connect.linked.example", "upstream elicitation host")
	w.forbid(linkedMessage, "upstream elicitation message")
	w.forbid("Paste your Linked", "upstream elicitation message")
	w.forbid(linkedUpID, "upstream elicitation id")
	for k := range notesKeys {
		w.forbid(k, "upstream API key")
	}
	up := newLinkedUpstream(t)
	err := w.st.WithJobs(ctx, func(tx store.Tx) error {
		return store.CreateNetguardAllowHost(ctx, tx, &store.NetguardAllowHost{Pattern: "127.0.0.1", Note: "e2e upstream"})
	})
	if err != nil {
		t.Fatal(err)
	}
	server := &store.MCPServer{
		Name: "linked", URL: up.srv.URL, OwnerUserID: w.alice.id,
		CredentialMode: store.MCPCredentialPerUser, AuthKind: store.MCPAuthAPIKey,
		AuthConfig: []byte(`{"api_key":{"header":"X-Notes-Key"}}`),
	}
	if err := w.fed.Manager.CreateServer(ctx, server); err != nil {
		t.Fatalf("CreateServer: %v", err)
	}
	if err := w.fed.Auth.SetUserCredential(ctx, w.alice.id, server.ID, auth.Credential{APIKey: "alice-notes-key-e2e"}); err != nil {
		t.Fatal(err)
	}
	review(t, w, w.alice, server, false, map[string]bool{"sync": true})
	// The owner lists the page's origin (what the server's edit form
	// saves; the form itself is covered by the servers portal's tests).
	err = w.st.WithUser(ctx, w.alice.id, func(tx store.Tx) error {
		return store.SetMCPServerElicitationOrigins(ctx, tx, server.ID, []string{linkedOrigin})
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := w.fed.Manager.ServerChanged(ctx, server.ID); err != nil {
		t.Fatal(err)
	}
	alice := w.client(w.alice)

	// 1. The relayed -32042.
	_, err = w.call(alice, "linked.sync", nil)
	je := rpcError(t, err, -32042)
	wire, _ := json.Marshal(je)
	for _, leak := range []string{"connect.linked.example", "x=1", "Paste your", "script", linkedUpID} {
		if strings.Contains(string(wire)+je.Message, leak) {
			t.Errorf("harness answer carries upstream text %q: %s", leak, wire)
		}
	}
	var data struct {
		URL          string `json:"url"`
		Server       string `json:"server"`
		Elicitations []struct {
			Mode, ElicitationID, URL, Message string
		} `json:"elicitations"`
	}
	if err := json.Unmarshal(je.Data, &data); err != nil {
		t.Fatalf("data %s: %v", je.Data, err)
	}
	if len(data.Elicitations) != 1 || data.Server != "linked" {
		t.Fatalf("data = %s", je.Data)
	}
	e := data.Elicitations[0]
	if e.Mode != "url" || !strings.HasPrefix(e.URL, baseURL+"/elicit/") || e.URL != data.URL ||
		!strings.HasPrefix(e.ElicitationID, "gwe_") || e.Message != "linked asks you to open a page" || !strings.Contains(je.Message, e.URL) {
		t.Fatalf("elicitation = %+v (message %q)", e, je.Message)
	}
	path := strings.TrimPrefix(e.URL, baseURL)
	w.forbid(strings.TrimPrefix(path, "/elicit/"), "elicitation link id")
	found := false
	for _, ev := range w.events(w.alice) {
		found = found || (ev.Tool == "linked.sync" && ev.ErrorClass == "upstream_elicitation_required" && ev.Outcome == "failed")
	}
	if !found {
		t.Error("no audit row with class upstream_elicitation_required")
	}

	// 2. The interstitial.
	p := w.page(w.alice, path)
	if p.status != http.StatusOK {
		t.Fatalf("interstitial = %d:\n%s", p.status, snippet(p.body))
	}
	for _, want := range []string{"linked", "https://connect.linked.example/connect?x=1", "linked.example", "&lt;script&gt;alert(1)&lt;/script&gt;"} {
		if !strings.Contains(p.body, want) {
			t.Errorf("interstitial lacks %q:\n%s", want, snippet(p.body))
		}
	}
	if strings.Contains(p.body, "<script>alert(1)") {
		t.Error("the upstream message renders as markup")
	}

	// 3. Continue: CSRF required, then exactly the upstream URL.
	if code, _ := w.post(w.alice, path, false); code != http.StatusForbidden {
		t.Errorf("Continue without CSRF = %d, want 403", code)
	}
	p = w.submit(w.alice, path, url.Values{"action": {"continue"}})
	if p.status != http.StatusSeeOther || p.location != linkedURL {
		t.Fatalf("Continue = %d %q, want 303 to %s", p.status, p.location, linkedURL)
	}
	up.mu.Lock()
	paths := append([]string(nil), up.paths...)
	up.mu.Unlock()
	for _, path := range paths {
		if path == "/connect" {
			t.Error("the gateway fetched the upstream page")
		}
	}

	// 4. The user completes on the upstream's page; the retry runs.
	up.connect("alice")
	res, err := w.call(alice, "linked.sync", nil)
	if err != nil || text(t, res) != "synced for alice" {
		t.Fatalf("retry = %v, %+v", err, res)
	}
}
