package portal

import (
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/federation/client"
	"github.com/huynle/mcp-gateway/internal/store"
)

func addForm(kv ...string) url.Values {
	v := url.Values{"url_mode": {"https"}, "credential_mode": {"per_user"}}
	for i := 0; i+1 < len(kv); i += 2 {
		v.Set(kv[i], kv[i+1])
	}
	return v
}

func (e *env) serverByName(name string) *store.MCPServer {
	e.t.Helper()
	e.st.mu.Lock()
	defer e.st.mu.Unlock()
	for _, s := range e.st.servers {
		if s.Name == name {
			c := *s
			return &c
		}
	}
	return nil
}

func TestNewFormOffersMyTunnels(t *testing.T) {
	e := newEnv(t)
	mine, _, _ := e.tun.CreateTunnel(t.Context(), alice, "laptop")
	theirs, _, _ := e.tun.CreateTunnel(t.Context(), bob, "bobs-box")
	r := e.get("/servers/new", alice)
	if r.code != 200 {
		t.Fatalf("status %d", r.code)
	}
	mustContain(t, r.body, `name="name"`, `name="url"`, `value="`+mine.ID+`"`, "laptop", `name="_csrf" value="csrf-`+alice+`"`)
	mustNotContain(t, r.body, theirs.ID, "bobs-box")
}

func TestDetectPreselectsOAuthForBrainShapedServer(t *testing.T) {
	e := newEnv(t)
	e.auth.detect = &auth.DetectResult{
		AuthKinds:    []string{store.MCPAuthOAuth, store.MCPAuthAPIKey, store.MCPAuthBearer, store.MCPAuthHeaders},
		SupportsDCR:  true,
		SupportsS256: true,
		Scopes:       []string{"brain:read"},
		Blocked:      []string{"10.0.0.1: private <b>address</b>"},
	}
	r := e.post("/servers/new", alice, addForm("action", "detect", "name", "brain", "url", "https://brain.example/mcp", "auth_kind", "none"))
	if r.code != 200 {
		t.Fatalf("status %d: %s", r.code, r.body)
	}
	if len(e.auth.detected) != 1 || e.auth.detected[0] != "https://brain.example/mcp" {
		t.Fatalf("detected %v", e.auth.detected)
	}
	mustContain(t, r.body, `value="brain"`, `value="https://brain.example/mcp"`,
		`value="oauth" checked`, "OAuth", "dynamic client registration", "private &lt;b&gt;address&lt;/b&gt;")
	mustNotContain(t, r.body, `value="none" checked`, "<b>address")
	if e.serverByName("brain") != nil {
		t.Error("detect created the server")
	}
}

func TestDetectErrorsShownAsClasses(t *testing.T) {
	e := newEnv(t)
	e.auth.detectErr = &client.Error{Class: client.ClassBlocked, Op: "connect", Reason: "private_address"}
	r := e.post("/servers/new", alice, addForm("action", "detect", "name", "x", "url", "https://169.254.169.254/mcp"))
	mustContain(t, r.body, "blocked by the gateway&#39;s network policy (SSRF protection)")
	e.auth.detectErr = &client.Error{Class: client.ClassUnreachable}
	r = e.post("/servers/new", alice, addForm("action", "detect", "name", "x", "url", "https://down.example/mcp"))
	mustContain(t, r.body, "could not be reached")
	// Tunnel servers cannot be probed from here.
	tun, _, _ := e.tun.CreateTunnel(t.Context(), alice, "laptop")
	r = e.post("/servers/new", alice, addForm("action", "detect", "name", "x", "url_mode", "tunnel", "tunnel_id", tun.ID))
	mustContain(t, r.body, "Detection is not available for tunnel servers")
	if len(e.auth.detected) != 2 {
		t.Errorf("detected %v", e.auth.detected)
	}
}

func TestReservedAndInvalidNamesRefused(t *testing.T) {
	e := newEnv(t)
	for _, name := range []string{"github", "slack", "atlassian", "jira", "confluence", "google", "calendar", "tasks", "gmail",
		"drive", "docs", "sheets", "contacts", "microsoft", "fake"} {
		r := e.post("/servers/new", alice, addForm("action", "create", "name", name, "url", "https://x.example/mcp", "auth_kind", "none"))
		if r.code != 422 {
			t.Errorf("%s: status %d", name, r.code)
		}
		mustContain(t, r.body, "is reserved for a built-in app")
	}
	for _, name := range []string{"Bad", "has space", "", strings.Repeat("a", 64), "dot.name"} {
		r := e.post("/servers/new", alice, addForm("action", "create", "name", name, "url", "https://x.example/mcp", "auth_kind", "none"))
		if r.code != 422 {
			t.Errorf("%q: status %d", name, r.code)
		}
		mustContain(t, r.body, "lowercase letters, digits")
	}
	if len(e.st.servers) != 0 {
		t.Error("a refused server was created")
	}
}

func TestCreateRefusesBadURLsAndCombinations(t *testing.T) {
	e := newEnv(t)
	bobsTunnel, _, _ := e.tun.CreateTunnel(t.Context(), bob, "b")
	cases := map[string]url.Values{
		"must be an https URL":                  addForm("action", "create", "name", "a", "url", "http://x.example/mcp", "auth_kind", "none"),
		"must be an https URL ":                 addForm("action", "create", "name", "a", "url", "https://user:pw@x.example/mcp", "auth_kind", "none"),
		"Choose one of your tunnels":            addForm("action", "create", "name", "a", "url_mode", "tunnel", "tunnel_id", bobsTunnel.ID, "auth_kind", "none"),
		"Shared OAuth tokens are not supported": addForm("action", "create", "name", "a", "url", "https://x.example/mcp", "auth_kind", "oauth", "credential_mode", "shared"),
		"Enter the shared bearer token":         addForm("action", "create", "name", "a", "url", "https://x.example/mcp", "auth_kind", "bearer", "credential_mode", "shared"),
		"Choose an authentication kind":         addForm("action", "create", "name", "a", "url", "https://x.example/mcp", "auth_kind", "magic"),
		"Header lines must look like":           addForm("action", "create", "name", "a", "url", "https://x.example/mcp", "auth_kind", "none", "static_headers", "nonsense"),
		"is not a valid header name":            addForm("action", "create", "name", "a", "url", "https://x.example/mcp", "auth_kind", "none", "per_user_headers", "Bad Header"),
		"either a header or a query parameter":  addForm("action", "create", "name", "a", "url", "https://x.example/mcp", "auth_kind", "api_key", "api_key_in", "cookie", "api_key_name", "k"),
	}
	for want, form := range cases {
		form.Set("shared_api_key", "never-echo-me")
		r := e.post("/servers/new", alice, form)
		if r.code != 422 {
			t.Errorf("%s: status %d", want, r.code)
		}
		mustContain(t, r.body, strings.TrimSpace(want))
		mustNotContain(t, r.body, "never-echo-me")
	}
	if len(e.st.servers) != 0 {
		t.Error("a refused server was created")
	}
}

func TestCreateStoresPrivateServerAndSharedSecret(t *testing.T) {
	e := newEnv(t)
	r := e.post("/servers/new", alice, addForm("action", "create", "name", "notes", "url", "https://notes.example/mcp",
		"auth_kind", "api_key", "credential_mode", "shared", "api_key_in", "header", "api_key_name", "X-Api-Key",
		"shared_api_key", "sekrit", "static_headers", "X-Team: core\n\n", "per_user_headers", "X-Brain-Project\r\nX-Other"))
	if r.code != 303 {
		t.Fatalf("status %d: %s", r.code, r.body)
	}
	s := e.serverByName("notes")
	if s == nil {
		t.Fatal("server not created")
	}
	if got := r.hdr.Get("Location"); got != "/servers/"+s.ID+"?created=1" {
		t.Errorf("Location %q", got)
	}
	if s.OwnerUserID != alice || s.Audience != store.MCPAudiencePrivate || s.URL != "https://notes.example/mcp" ||
		s.AuthKind != store.MCPAuthAPIKey || s.CredentialMode != store.MCPCredentialShared || s.Transport != store.MCPTransportAuto {
		t.Errorf("stored %+v", s)
	}
	var ac authConfig
	var hc headerConfig
	_ = json.Unmarshal(s.AuthConfig, &ac)
	_ = json.Unmarshal(s.HeaderConfig, &hc)
	if ac.APIKey == nil || ac.APIKey.Header != "X-Api-Key" || ac.APIKey.Query != "" {
		t.Errorf("auth config %s", s.AuthConfig)
	}
	if hc.Static["X-Team"] != "core" || strings.Join(hc.PerUser, ",") != "X-Brain-Project,X-Other" {
		t.Errorf("header config %s", s.HeaderConfig)
	}
	if strings.Contains(string(s.AuthConfig)+string(s.HeaderConfig), "sekrit") {
		t.Error("secret stored in the non-secret config")
	}
	if len(e.auth.shared) != 1 || e.auth.shared[0].c.APIKey != "sekrit" || e.auth.shared[0].actor != (auth.Actor{UserID: alice}) ||
		e.auth.shared[0].serverID != s.ID {
		t.Errorf("shared credential calls %+v", e.auth.shared)
	}
	if len(e.hook.changed) != 1 || e.hook.changed[0] != s.ID {
		t.Errorf("hook %v", e.hook.changed)
	}
	// The name is taken now.
	r = e.post("/servers/new", alice, addForm("action", "create", "name", "notes", "url", "https://n2.example/mcp", "auth_kind", "none"))
	if r.code != 422 || !strings.Contains(r.body, "already taken") {
		t.Errorf("duplicate: %d", r.code)
	}
}

func TestCreateOAuthWithStaticClientAndTunnelURL(t *testing.T) {
	e := newEnv(t)
	tun, _, _ := e.tun.CreateTunnel(t.Context(), alice, "laptop")
	r := e.post("/servers/new", alice, addForm("action", "create", "name", "local", "url_mode", "tunnel", "tunnel_id", tun.ID,
		"tunnel_path", "/mcp", "auth_kind", "oauth", "client_id", "cid", "client_secret", "csec", "client_issuer", "https://as.example",
		"scopes", "read  write"))
	if r.code != 303 {
		t.Fatalf("status %d: %s", r.code, r.body)
	}
	s := e.serverByName("local")
	if s.URL != "tunnel://"+tun.ID+"/mcp" || s.AuthKind != store.MCPAuthOAuth || s.CredentialMode != store.MCPCredentialPerUser {
		t.Errorf("stored %+v", s)
	}
	if ac := parseAuthConfig(s.AuthConfig); strings.Join(ac.Scopes, ",") != "read,write" {
		t.Errorf("scopes %v", ac.Scopes)
	}
	if len(e.auth.clients) != 1 || e.auth.clients[0] != s.ID+"|cid|csec|https://as.example" {
		t.Errorf("static client %v", e.auth.clients)
	}
	if len(e.auth.shared) != 0 {
		t.Error("per-user server got a shared credential")
	}
}

func TestEditAndDeleteAreOwnerOnly(t *testing.T) {
	e := newEnv(t)
	pub := e.st.add(store.MCPServer{Name: "wiki", URL: "https://wiki.example/mcp", OwnerUserID: bob, AuthKind: store.MCPAuthNone,
		Audience: store.MCPAudiencePublished}, alice)
	if r := e.get("/servers/"+pub.ID+"/edit", alice); r.code != 404 {
		t.Errorf("edit of a published server by a viewer: %d", r.code)
	}
	if r := e.post("/servers/"+pub.ID+"/delete", alice, nil); r.code != 404 || len(e.st.deleted) != 0 {
		t.Errorf("delete by a viewer: %d", r.code)
	}

	mine := e.st.add(store.MCPServer{Name: "mine", URL: "https://m.example/mcp", OwnerUserID: alice, AuthKind: store.MCPAuthBearer,
		CredentialMode: store.MCPCredentialShared})
	e.st.creds[mine.ID] = CredentialInfo{SharedSecret: true, SharedKeys: []string{"bearer"}}
	r := e.get("/servers/"+mine.ID+"/edit", alice)
	if r.code != 200 {
		t.Fatalf("edit: %d", r.code)
	}
	mustContain(t, r.body, `value="https://m.example/mcp"`, "a secret is stored", `value="bearer" checked`)
	mustNotContain(t, r.body, `name="name"`) // the name (tool prefix) is fixed

	// Saving without a new secret keeps the stored one while the URL is
	// unchanged.
	r = e.post("/servers/"+mine.ID+"/edit", alice, addForm("url", "https://m.example/mcp", "auth_kind", "bearer", "credential_mode", "shared", "scopes", "read"))
	if r.code != 303 {
		t.Fatalf("save: %d %s", r.code, r.body)
	}
	if len(e.auth.shared) != 0 {
		t.Error("blank secret overwrote the stored one")
	}
	// A new URL needs the secret again: the stored one is sealed to the old
	// URL (security task rvrfpzzj) and must never be sent to the new one.
	r = e.post("/servers/"+mine.ID+"/edit", alice, addForm("url", "https://m2.example/mcp", "auth_kind", "bearer", "credential_mode", "shared"))
	if r.code != 422 || !strings.Contains(r.body, "Enter the shared bearer token") {
		t.Fatalf("URL change without a new secret: %d", r.code)
	}
	if s := e.serverByName("mine"); s.URL != "https://m.example/mcp" {
		t.Errorf("URL changed without the secret: %+v", s)
	}
	r = e.post("/servers/"+mine.ID+"/edit", alice, addForm("url", "https://m2.example/mcp", "auth_kind", "bearer", "credential_mode", "shared", "shared_bearer", "tok2"))
	if r.code != 303 || len(e.auth.shared) != 1 || e.auth.shared[0].c.Bearer != "tok2" {
		t.Errorf("new secret: %d %+v", r.code, e.auth.shared)
	}
	if s := e.serverByName("mine"); s.URL != "https://m2.example/mcp" || s.Name != "mine" {
		t.Errorf("after save %+v", s)
	}

	r = e.post("/servers/"+mine.ID+"/delete", alice, nil)
	if r.code != 303 || r.hdr.Get("Location") != "/servers?deleted=1" {
		t.Errorf("delete: %d %q", r.code, r.hdr.Get("Location"))
	}
	if e.serverByName("mine") != nil {
		t.Error("not deleted")
	}
	if n := len(e.hook.changed); n != 3 || e.hook.changed[n-1] != mine.ID {
		t.Errorf("hook %v", e.hook.changed)
	}
}

// The tunnel picker pre-selects an online tunnel over an offline one, lists
// online tunnels first and shows a short id so same-named tunnels differ.
func TestFormTunnelPickerPrefersOnline(t *testing.T) {
	e := newEnv(t)
	online, _, _ := e.tun.CreateTunnel(t.Context(), alice, "laptop")
	offline, _, _ := e.tun.CreateTunnel(t.Context(), alice, "box")
	e.tun.online[online.ID] = true
	body := e.get("/servers/new", alice).body
	sel := body[strings.Index(body, `name="tunnel_id"`):]
	sel = sel[:strings.Index(sel, "</select>")]
	iOn, iOff := strings.Index(sel, online.ID), strings.Index(sel, offline.ID)
	if iOn < 0 || iOff < 0 || iOn > iOff {
		t.Fatalf("online tunnel not listed first:\n%s", sel)
	}
	mustContain(t, sel, `value="`+online.ID+`" selected`, "laptop · "+online.ID[:8]+" (online)", "box · "+offline.ID[:8]+" (offline)")
}
