//go:build integration || e2e || security

package security

// Header injection and token isolation for user-added servers: static
// headers, per-user header values and API-key header names cannot smuggle
// CRLF or set transport/credential headers; the gateway's own bearer,
// session cookie and CSRF token never reach an upstream; per-user
// credentials go only with their user's calls; shared credentials and
// client secrets are never rendered.

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/federation/auth"
	"github.com/huynle/mcp-gateway/internal/federation/client"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/store"
	"github.com/huynle/mcp-gateway/internal/tokens"
)

// TestSecurityFedHeaderInjection: the servers portal refuses CR/LF and
// control characters in header values, invalid header names, transport
// headers (Host, Content-Length, Transfer-Encoding, Mcp-*, Proxy-*) and
// credential headers as static headers; the auth service refuses the same
// in stored credentials; the federation client refuses them in endpoint
// headers. Nothing is stored for a refused form.
func TestSecurityFedHeaderInjection(t *testing.T) {
	w := newWorld(t, options{federation: true})
	ctx := t.Context()
	base := url.Values{"name": {"hdr"}, "url_mode": {"https"}, "url": {"https://mcp.example.com/mcp"}, "auth_kind": {"none"}}
	with := func(kv ...string) url.Values {
		v := url.Values{}
		for k, vs := range base {
			v[k] = vs
		}
		for i := 0; i+1 < len(kv); i += 2 {
			v.Set(kv[i], kv[i+1])
		}
		return v
	}
	for name, form := range map[string]url.Values{
		"static CR in value":          with("static_headers", "X-A: v\rX-Injected: 1"),
		"static NUL in value":         with("static_headers", "X-A: v\x00"),
		"static name with space":      with("static_headers", "X A: v"),
		"static Authorization":        with("static_headers", "Authorization: Bearer stolen"),
		"static authorization (case)": with("static_headers", "aUtHoRiZaTiOn: Bearer stolen"),
		"static Cookie":               with("static_headers", "Cookie: session=1"),
		"static X-Api-Key":            with("static_headers", "x-api-key: k"),
		"static Host":                 with("static_headers", "Host: internal"),
		"static Content-Length":       with("static_headers", "Content-Length: 0"),
		"static Transfer-Encoding":    with("static_headers", "Transfer-Encoding: chunked"),
		"static Mcp-Session-Id":       with("static_headers", "Mcp-Session-Id: fixed"),
		"static Proxy-Authorization":  with("static_headers", "Proxy-Authorization: Basic x"),
		"static non-ASCII name":       with("static_headers", "X-Ä: v"),
		"per-user Host":               with("per_user_headers", "Host"),
		"per-user Mcp-Protocol":       with("per_user_headers", "Mcp-Protocol-Version"),
		"per-user CRLF name":          with("per_user_headers", "X-A\rX-B"),
		"api key header Host":         with("auth_kind", "api_key", "api_key_in", "header", "api_key_name", "Host"),
		"api key header CR":           with("auth_kind", "api_key", "api_key_in", "header", "api_key_name", "X-Key\rX-B"),
		"api key header Content-Type": with("auth_kind", "api_key", "api_key_in", "header", "api_key_name", "Content-Type"),
		"api key query injection":     with("auth_kind", "api_key", "api_key_in", "query", "api_key_name", "k&admin=1"),
		"shared header CR":            with("auth_kind", "headers", "credential_mode", "shared", "shared_headers", "X-Token: a\rX-B: c"),
		"shared header Host":          with("auth_kind", "headers", "credential_mode", "shared", "shared_headers", "Host: internal"),
	} {
		code, _, body := w.post(w.alice, "/servers/new", form)
		if code != http.StatusUnprocessableEntity {
			t.Errorf("%s: create = %d (%q)", name, code, excerpt(body, "error"))
		}
	}
	if got := w.queryString(`SELECT count(*)::text FROM mcp_servers`); got != "0" {
		t.Errorf("%s servers stored from refused forms", got)
	}

	// Stored credentials (per-user and shared) through the auth service.
	s := w.addServer(w.alice, "hdrsrv", "https://mcp.example.com/mcp", func(s *store.MCPServer) {
		s.AuthKind, s.HeaderConfig = store.MCPAuthHeaders, []byte(`{"per_user":["X-User"]}`)
	})
	for name, c := range map[string]auth.Credential{
		"CRLF value":        {Headers: map[string]string{"X-Token": "a\r\nX-Injected: 1"}},
		"LF value":          {Headers: map[string]string{"X-Token": "a\nb"}},
		"Host":              {Headers: map[string]string{"Host": "internal"}},
		"Mcp-Session-Id":    {Headers: map[string]string{"Mcp-Session-Id": "x"}},
		"Proxy-":            {Headers: map[string]string{"Proxy-Authorization": "x"}},
		"Transfer-Encoding": {Headers: map[string]string{"Transfer-Encoding": "chunked"}},
		"name with space":   {Headers: map[string]string{"X Token": "a"}},
		"api key CRLF":      {APIKey: "k\r\nX-Injected: 1"},
	} {
		if err := w.fed.Auth.SetUserCredential(ctx, w.alice.id, s.ID, c); !errors.Is(err, auth.ErrInvalidCredential) {
			t.Errorf("per-user %s: %v, want ErrInvalidCredential", name, err)
		}
		if err := w.fed.Auth.SetSharedCredential(ctx, auth.Actor{UserID: w.alice.id}, s.ID, c); !errors.Is(err, auth.ErrInvalidCredential) {
			t.Errorf("shared %s: %v, want ErrInvalidCredential", name, err)
		}
	}
	// Per-user header values through the portal credential form.
	code, _, _ := w.post(w.alice, "/servers/"+s.ID+"/credential", url.Values{"headers": {"X-Token: a\rX-B: c"}, "header:X-User": {"v\rX-Evil: 1"}})
	if code == http.StatusSeeOther {
		t.Error("credential form with CR accepted")
	}
	// The federation client refuses bad endpoint headers outright.
	c, err := client.New(client.Options{HTTPClient: w.fed.Guard.Client()})
	if err != nil {
		t.Fatal(err)
	}
	for name, h := range map[string]map[string]string{
		"CRLF value": {"X-A": "v\r\nX-Injected: 1"}, "Host": {"Host": "internal"}, "Mcp-Session-Id": {"Mcp-Session-Id": "x"},
		"Content-Length": {"Content-Length": "0"}, "bad name": {"X A": "v"}, "Proxy-Authorization": {"Proxy-Authorization": "x"},
	} {
		if _, err := c.Connect(ctx, client.Endpoint{URL: "https://mcp.example.com/mcp", Headers: h}); !errors.Is(err, client.ErrInvalidEndpoint) {
			t.Errorf("endpoint header %s: %v, want ErrInvalidEndpoint", name, err)
		}
	}
}

// TestSecurityFedTokenIsolation: a capturing upstream never sees the
// gateway's harness token, the portal session cookie, the CSRF token, any
// Cookie or Authorization header it did not configure, or another user's
// per-user credential; each user's call carries only their own key.
func TestSecurityFedTokenIsolation(t *testing.T) {
	w := newWorld(t, options{federation: true})
	ctx := t.Context()
	w.allowLoopback()
	const aliceKey, bobKey = "alice-iso-key-1", "bob-iso-key-2"
	w.forbid(aliceKey, "upstream API key")
	w.forbid(bobKey, "upstream API key")
	open := newUpstream(t, notesServer) // auth none: captures everything
	keyed := newUpstream(t, notesServer)
	keyed.setGate(requireKey(aliceKey, bobKey))
	o := w.addServer(w.alice, "isoopen", open.URL(), nil)
	k := w.addServer(w.alice, "isokeyed", keyed.URL(), apiKeyServer)
	if err := w.fed.Auth.SetUserCredential(ctx, w.alice.id, k.ID, auth.Credential{APIKey: aliceKey}); err != nil {
		t.Fatal(err)
	}
	w.review(w.alice, o, "search")
	w.review(w.alice, k, "search")
	w.publish(k, []policy.ToolRule{{App: "isokeyed", Tool: "search", Outcome: policy.OutcomeAllow}}, roleMember, roleRestricted)
	if err := w.fed.Auth.SetUserCredential(ctx, w.bob.id, k.ID, auth.Credential{APIKey: bobKey}); err != nil {
		t.Fatal(err)
	}
	aliceTok, bobTok := w.token(w.alice, tokens.CreateRequest{}), w.token(w.bob, tokens.CreateRequest{})
	alice, bob := w.clientWith(aliceTok), w.clientWith(bobTok)
	keyed.reset()
	for i := range 3 {
		if res, err := w.call(alice, "isoopen.search", map[string]any{"q": "x"}); err != nil || res.IsError {
			t.Fatalf("alice open %d: %v %+v", i, err, res)
		}
		res, err := w.call(alice, "isokeyed.search", map[string]any{"q": "x"})
		if err != nil || text(t, res) != "results for "+aliceKey {
			t.Fatalf("alice keyed: %v %+v", err, res)
		}
		res, err = w.call(bob, "isokeyed.search", map[string]any{"q": "x"})
		if err != nil || text(t, res) != "results for "+bobKey {
			t.Fatalf("bob keyed: %v %+v", err, res)
		}
	}
	// Portal-driven upstream contact with the session cookie.
	if code, _, _ := w.post(w.alice, "/servers/"+o.ID+"/resources/read", url.Values{"uri": {"notes://readme"}}); code != http.StatusOK {
		t.Errorf("portal read = %d", code)
	}
	if code, _, _ := w.post(w.alice, "/servers/"+o.ID+"/refresh", nil); code >= 400 {
		t.Errorf("portal refresh = %d", code)
	}
	gatewaySecrets := []string{aliceTok, bobTok, w.alice.cookie.Value, w.bob.cookie.Value, w.alice.csrf, w.bob.csrf}
	for _, u := range []*upstream{open, keyed} {
		for _, r := range u.requests() {
			if r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("X-Csrf-Token") != "" {
				t.Errorf("upstream got gateway headers: %v", r.Header)
			}
			for _, sec := range gatewaySecrets {
				if strings.Contains(r.Body, sec) || strings.Contains(r.RawQuery, sec) || headerHas(r.Header, sec) {
					t.Error("a gateway token, cookie or CSRF token reached an upstream")
				}
			}
		}
	}
	// Each keyed request carries exactly one user's key, and the right one
	// for its caller (the body names it, the gate admitted it).
	for _, r := range keyed.requests() {
		got := r.Header.Values("X-Notes-Key")
		if len(got) != 1 || (got[0] != aliceKey && got[0] != bobKey) {
			t.Errorf("keyed request carries %v", got)
		}
	}
}

func headerHas(h http.Header, v string) bool {
	for _, vals := range h {
		for _, x := range vals {
			if strings.Contains(x, v) {
				return true
			}
		}
	}
	return false
}

// TestSecurityFedSecretsNeverRendered: a shared credential and a static
// OAuth client secret, set by the owner or an admin, never appear on any
// portal or admin page (detail, edit, review, list, a re-rendered form
// after a validation error, error pages), nor in the log or audit rows
// (the world's leak scan).
func TestSecurityFedSecretsNeverRendered(t *testing.T) {
	w := newWorld(t, options{federation: true})
	w.allowLoopback()
	const ownerShared, adminShared, clientSecret, rejected = "owner-shared-key-render-1", "admin-shared-key-render-2", "static-client-secret-render-3", "rejected-shared-key-render-4"
	for _, s := range []string{ownerShared, adminShared, clientSecret, rejected} {
		w.forbid(s, "write-only secret")
	}
	up := newUpstream(t, notesServer)
	up.setGate(requireKey(ownerShared, adminShared))
	https := strings.Replace(up.URL(), "http://", "https://", 1) + "/mcp"
	code, hdr, body := w.post(w.alice, "/servers/new", url.Values{
		"name": {"render"}, "url_mode": {"https"}, "url": {https}, "auth_kind": {"api_key"},
		"credential_mode": {"shared"}, "api_key_in": {"header"}, "api_key_name": {"X-Notes-Key"}, "shared_api_key": {ownerShared},
	})
	if code != http.StatusSeeOther {
		t.Fatalf("create = %d %s", code, excerpt(body, "error"))
	}
	id := strings.TrimPrefix(strings.Split(hdr.Get("Location"), "?")[0], "/servers/")
	// An admin replaces it and sets a static client on an OAuth server.
	if code, _, body := w.post(w.admin, "/admin/servers/"+id+"/shared-credential", url.Values{"api_key": {adminShared}}); code >= 400 {
		t.Fatalf("admin shared credential = %d %s", code, excerpt(body, "error"))
	}
	code, hdr, body = w.post(w.alice, "/servers/new", url.Values{
		"name": {"renderoauth"}, "url_mode": {"https"}, "url": {https}, "auth_kind": {"oauth"},
		"client_id": {"static-client"}, "client_secret": {clientSecret},
	})
	if code != http.StatusSeeOther {
		t.Fatalf("create oauth = %d %s", code, excerpt(body, "error"))
	}
	oid := strings.TrimPrefix(strings.Split(hdr.Get("Location"), "?")[0], "/servers/")
	// A validation error re-renders the edit form with a new secret typed.
	_, _, reRendered := w.post(w.alice, "/servers/"+id+"/edit", url.Values{
		"url_mode": {"https"}, "url": {"not a url"}, "auth_kind": {"api_key"}, "credential_mode": {"shared"}, "shared_api_key": {rejected},
	})
	pages := map[string]string{"re-rendered edit form": reRendered}
	for _, p := range []string{"/servers", "/servers/" + id, "/servers/" + id + "/edit", "/servers/" + oid, "/servers/" + oid + "/edit"} {
		_, _, b := w.get(w.alice, p)
		pages["owner "+p] = b
	}
	for _, p := range []string{"/admin/servers", "/admin/servers/" + id, "/admin/servers/" + oid, "/admin/servers/reviews"} {
		_, _, b := w.get(w.admin, p)
		pages["admin "+p] = b
	}
	_, _, pages["bob 404"] = w.get(w.bob, "/servers/"+id)
	for where, b := range pages {
		for _, s := range []string{ownerShared, adminShared, clientSecret, rejected} {
			if strings.Contains(b, s) {
				t.Errorf("%s renders a write-only secret", where)
			}
		}
	}
	if !strings.Contains(pages["owner /servers/"+id+"/edit"], "X-Notes-Key") {
		t.Error("control: the edit page should show the (non-secret) header name")
	}
}
