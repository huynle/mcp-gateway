package portal

import (
	"net/url"
	"testing"

	"github.com/huynle/mcp-gateway/internal/store"
)

// Published servers are admin-governed (Brain task mpszh6h0, decision
// q7vbxlyk point 3): their owner may not change the address or sign-in
// settings, which the admin reviewed for everyone the server is shared
// with.

const lockedNote = "This server is shared; ask an admin to change its address or sign-in settings."

func publishedBearerServer(e *env) *store.MCPServer {
	s := e.st.add(store.MCPServer{Name: "wiki", URL: "https://wiki.example/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthBearer,
		CredentialMode: store.MCPCredentialShared, Audience: store.MCPAudiencePublished,
		AuthConfig: []byte(`{}`), HeaderConfig: []byte(`{"static":{"X-Client":"gateway"}}`)}, bob)
	e.st.creds[s.ID] = CredentialInfo{SharedSecret: true, SharedKeys: []string{"bearer"}}
	return s
}

func TestPublishedServerEditFormIsReadOnlyForOwner(t *testing.T) {
	e := newEnv(t)
	s := publishedBearerServer(e)
	r := e.get("/servers/"+s.ID+"/edit", alice)
	if r.code != 200 {
		t.Fatalf("edit page: %d", r.code)
	}
	mustContain(t, r.body, lockedNote, "https://wiki.example/mcp", "X-Client: gateway")
	// No editable address or sign-in fields.
	mustNotContain(t, r.body, `name="url"`, `name="auth_kind"`, `name="credential_mode"`, `name="static_headers"`,
		`name="per_user_headers"`, `name="scopes"`, `name="client_id"`, `name="tunnel_id"`)
}

func TestPublishedServerOwnerEditsRefused(t *testing.T) {
	e := newEnv(t)
	s := publishedBearerServer(e)
	before := *e.serverByName("wiki")
	for name, form := range map[string]url.Values{
		"new URL": addForm("url", "https://attacker.example/mcp", "auth_kind", "bearer", "credential_mode", "shared",
			"static_headers", "X-Client: gateway", "shared_bearer", "tok"),
		"new auth kind":      addForm("url", "https://wiki.example/mcp", "auth_kind", "none", "static_headers", "X-Client: gateway"),
		"new static headers": addForm("url", "https://wiki.example/mcp", "auth_kind", "bearer", "credential_mode", "shared", "static_headers", "X-Route: evil"),
		"per-user mode": addForm("url", "https://wiki.example/mcp", "auth_kind", "bearer", "credential_mode", "per_user",
			"static_headers", "X-Client: gateway"),
		"tunnel": {"url_mode": {"tunnel"}, "tunnel_id": {"5e000000-0000-4000-8000-000000000999"}},
	} {
		r := e.post("/servers/"+s.ID+"/edit", alice, form)
		if r.code != 422 {
			t.Errorf("%s: %d, want 422", name, r.code)
			continue
		}
		mustContain(t, r.body, lockedNote)
	}
	if got := *e.serverByName("wiki"); got.URL != before.URL || got.AuthKind != before.AuthKind ||
		got.CredentialMode != before.CredentialMode || string(got.HeaderConfig) != string(before.HeaderConfig) {
		t.Errorf("server changed: %+v", got)
	}
	if len(e.auth.shared) != 0 || len(e.auth.clients) != 0 {
		t.Errorf("credentials written on a refused edit: %+v %v", e.auth.shared, e.auth.clients)
	}
	if len(e.hook.changed) != 0 {
		t.Errorf("hook told about a refused edit: %v", e.hook.changed)
	}
}

// Rotating the shared secret does not change where calls go: the owner
// may still do it (the admin can too).
func TestPublishedServerOwnerMayRotateSharedSecret(t *testing.T) {
	e := newEnv(t)
	s := publishedBearerServer(e)
	r := e.post("/servers/"+s.ID+"/edit", alice, url.Values{"shared_bearer": {"tok2"}})
	if r.code != 303 {
		t.Fatalf("rotate: %d %s", r.code, r.body)
	}
	if len(e.auth.shared) != 1 || e.auth.shared[0].c.Bearer != "tok2" {
		t.Errorf("shared = %+v", e.auth.shared)
	}
	if got := e.serverByName("wiki"); got.URL != s.URL {
		t.Errorf("URL changed: %q", got.URL)
	}
}

// A store refusal (the server was published between loading and saving:
// schema 17 trigger) is the same 422.
func TestStoreLockRefusalIsTheLockedMessage(t *testing.T) {
	e := newEnv(t)
	s := e.st.add(store.MCPServer{Name: "mine", URL: "https://m.example/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthNone})
	e.st.updateErr = store.ErrMCPServerLocked
	r := e.post("/servers/"+s.ID+"/edit", alice, addForm("url", "https://m2.example/mcp", "auth_kind", "none"))
	if r.code != 422 {
		t.Fatalf("locked by the store: %d", r.code)
	}
	mustContain(t, r.body, lockedNote)
}
