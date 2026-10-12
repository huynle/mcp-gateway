//go:build integration || e2e || security

package security

// OAuth attacks on user-added servers (decision 6xeknoet: sealed one-use
// state bound to user and server, RFC 9207 iss check, token bundle pinned
// to the issuer / token endpoint / client at connect time, refresh under
// the row lock per user).

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	fedadmin "github.com/huynle/mcp-gateway/internal/federation/admin"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/mcp"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/store"
)

// oauthUpstream is an MCP server protected by its own authorization
// server on the same origin (PRM, RFC 8414 metadata, DCR, PKCE S256, iss
// parameter, refresh rotation). Codes are minted by the test for a user
// label, as if that person had signed in at the AS.
type oauthUpstream struct {
	t   *testing.T
	srv *httptest.Server
	mcp *upstream // the protected MCP endpoint's captures

	mu         sync.Mutex
	base       string
	tokenURL   string            // advertised token_endpoint (swappable by the "owner")
	codes      map[string]string // code -> who|challenge
	access     map[string]string // access token -> who
	refresh    map[string]string // refresh token -> who
	seq        int
	tokenCalls []url.Values
}

func newOAuthUpstream(t *testing.T) *oauthUpstream {
	t.Helper()
	o := &oauthUpstream{t: t, codes: map[string]string{}, access: map[string]string{}, refresh: map[string]string{}}
	o.mcp = newUpstream(t, func(r *http.Request) *sdk.Server {
		who := o.whoFor(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		s := sdk.NewServer(&sdk.Implementation{Name: "oauthnotes", Version: "1"}, nil)
		sdk.AddTool(s, &sdk.Tool{Name: "search", Annotations: &sdk.ToolAnnotations{ReadOnlyHint: true}},
			func(context.Context, *sdk.CallToolRequest, searchIn) (*sdk.CallToolResult, any, error) {
				return &sdk.CallToolResult{Content: []sdk.Content{&sdk.TextContent{Text: "results for " + who}}}, nil, nil
			})
		return s
	})
	o.mcp.setGate(func(w http.ResponseWriter, r *http.Request) bool {
		if o.whoFor(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")) != "" {
			return false
		}
		w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+o.base+`/.well-known/oauth-protected-resource/mcp"`)
		w.WriteHeader(http.StatusUnauthorized)
		return true
	})
	mux := http.NewServeMux()
	mux.Handle("/mcp", o.mcp.srv.Config.Handler)
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		writeJSONBody(w, map[string]any{"resource": o.base + "/mcp", "authorization_servers": []string{o.base}})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server", func(w http.ResponseWriter, r *http.Request) {
		o.mu.Lock()
		tokenURL := o.tokenURL
		o.mu.Unlock()
		writeJSONBody(w, map[string]any{
			"issuer": o.base, "authorization_endpoint": o.base + "/authorize", "token_endpoint": tokenURL,
			"registration_endpoint": o.base + "/register", "code_challenge_methods_supported": []string{"S256"},
			"token_endpoint_auth_methods_supported":          []string{"none"},
			"authorization_response_iss_parameter_supported": true,
		})
	})
	mux.HandleFunc("POST /register", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusCreated)
		writeJSONBody(w, map[string]any{"client_id": "dcr-client-1"})
	})
	mux.HandleFunc("POST /token", o.token)
	o.srv = httptest.NewServer(mux)
	o.base = o.srv.URL
	o.tokenURL = o.base + "/token"
	t.Cleanup(o.srv.Close)
	return o
}

func (o *oauthUpstream) whoFor(tok string) string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.access[tok]
}

// mint issues an authorization code for who bound to the PKCE challenge
// of the authorize URL the gateway redirected to.
func (o *oauthUpstream) mint(who string, authorize *url.URL) string {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.seq++
	code := fmt.Sprintf("code-%s-%d", who, o.seq)
	o.codes[code] = who + "|" + authorize.Query().Get("code_challenge")
	return code
}

func (o *oauthUpstream) token(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	o.mu.Lock()
	defer o.mu.Unlock()
	o.tokenCalls = append(o.tokenCalls, r.PostForm)
	var who string
	switch r.PostForm.Get("grant_type") {
	case "authorization_code":
		entry, ok := o.codes[r.PostForm.Get("code")]
		delete(o.codes, r.PostForm.Get("code"))
		whoPart, challenge, _ := strings.Cut(entry, "|")
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != challenge {
			w.WriteHeader(http.StatusBadRequest)
			writeJSONBody(w, map[string]any{"error": "invalid_grant"})
			return
		}
		who = whoPart
	case "refresh_token":
		var ok bool
		who, ok = o.refresh[r.PostForm.Get("refresh_token")]
		delete(o.refresh, r.PostForm.Get("refresh_token"))
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			writeJSONBody(w, map[string]any{"error": "invalid_grant"})
			return
		}
	default:
		w.WriteHeader(http.StatusBadRequest)
		writeJSONBody(w, map[string]any{"error": "unsupported_grant_type"})
		return
	}
	o.seq++
	at, rt := fmt.Sprintf("at-%s-%d-secret", who, o.seq), fmt.Sprintf("rt-%s-%d-secret", who, o.seq)
	o.access[at], o.refresh[rt] = who, who
	writeJSONBody(w, map[string]any{"access_token": at, "token_type": "Bearer", "expires_in": 3600, "refresh_token": rt})
}

// revokeAccess invalidates every access token of who (the next call gets a
// 401 and the gateway must refresh).
func (o *oauthUpstream) revokeAccess(who string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	for k, v := range o.access {
		if v == who {
			delete(o.access, k)
		}
	}
}

func (o *oauthUpstream) tokens() []url.Values {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]url.Values(nil), o.tokenCalls...)
}

// startConnect runs GET /servers/{id}/connect as u and returns the
// authorize URL and the state.
func (w *world) startConnect(u user, serverID string) (*url.URL, string) {
	w.t.Helper()
	code, hdr, body := w.get(u, "/servers/"+serverID+"/connect")
	if code != http.StatusFound {
		w.t.Fatalf("connect = %d %s", code, body)
	}
	loc, err := url.Parse(hdr.Get("Location"))
	if err != nil {
		w.t.Fatal(err)
	}
	return loc, loc.Query().Get("state")
}

// callback runs the OAuth callback as u.
func (w *world) callback(u user, q url.Values) (int, string) {
	w.t.Helper()
	code, _, body := w.get(u, "/servers/oauth/callback?"+q.Encode())
	return code, body
}

// connectOAuth completes a whole connect flow for u.
func (w *world) connectOAuth(o *oauthUpstream, u user, label, serverID string) {
	w.t.Helper()
	authz, state := w.startConnect(u, serverID)
	code, body := w.callback(u, url.Values{"state": {state}, "code": {o.mint(label, authz)}, "iss": {o.base}})
	if code >= 400 {
		w.t.Fatalf("callback for %s = %d %s", label, code, body)
	}
}

func oauthServer(s *store.MCPServer) {
	s.CredentialMode, s.AuthKind = store.MCPCredentialPerUser, store.MCPAuthOAuth
}

// TestSecurityFedOAuthStateAttacks: the connect-flow state is bound to the
// user and server and used once. Another user's state, a tampered state,
// a state moved to another server, a replay, a wrong or missing iss (the
// AS advertises RFC 9207) and an AS error are all refused, and none of
// them stores a connection.
func TestSecurityFedOAuthStateAttacks(t *testing.T) {
	w := newWorld(t, options{federation: true})
	w.allowLoopback()
	o := newOAuthUpstream(t)
	s := w.addServer(w.alice, "oauthnotes", o.base+"/mcp", oauthServer)
	other := w.addServer(w.alice, "oauthother", o.base+"/mcp", oauthServer)

	authz, state := w.startConnect(w.alice, s.ID)
	sid, body, _ := strings.Cut(state, ".")
	tampered := sid + "." + body[:len(body)-2] + flip(body[len(body)-2:])
	moved := base64.RawURLEncoding.EncodeToString([]byte(other.ID)) + "." + body
	for _, tc := range []struct {
		name string
		as   user
		q    url.Values
	}{
		{"another user's state", w.bob, url.Values{"state": {state}, "code": {o.mint("bob", authz)}, "iss": {o.base}}},
		{"tampered state", w.alice, url.Values{"state": {tampered}, "code": {o.mint("alice", authz)}, "iss": {o.base}}},
		{"state moved to another server", w.alice, url.Values{"state": {moved}, "code": {o.mint("alice", authz)}, "iss": {o.base}}},
		{"garbage state", w.alice, url.Values{"state": {"x.y"}, "code": {"c"}, "iss": {o.base}}},
		{"issuer mix-up", w.alice, url.Values{"state": {state}, "code": {o.mint("alice", authz)}, "iss": {"https://evil.example"}}},
	} {
		code, out := w.callback(tc.as, tc.q)
		if code != http.StatusBadRequest {
			t.Errorf("%s: callback = %d %q, want 400", tc.name, code, out)
		}
	}
	// The mix-up attempt consumed the state (one use); a fresh flow with
	// no iss at all is refused too (the AS advertises RFC 9207).
	authz, state = w.startConnect(w.alice, s.ID)
	if code, out := w.callback(w.alice, url.Values{"state": {state}, "code": {o.mint("alice", authz)}}); code != http.StatusBadRequest {
		t.Errorf("missing iss: callback = %d %q", code, out)
	}
	_, state = w.startConnect(w.alice, s.ID)
	if code, out := w.callback(w.alice, url.Values{"state": {state}, "error": {"access_denied"}}); code != http.StatusBadRequest {
		t.Errorf("AS error: callback = %d %q", code, out)
	}
	if n := len(o.tokens()); n != 0 {
		t.Fatalf("%d token requests for refused callbacks", n)
	}
	// A good flow, then its replay.
	authz, state = w.startConnect(w.alice, s.ID)
	q := url.Values{"state": {state}, "code": {o.mint("alice", authz)}, "iss": {o.base}}
	if code, out := w.callback(w.alice, q); code >= 400 {
		t.Fatalf("good callback = %d %q", code, out)
	}
	q.Set("code", o.mint("alice", authz))
	if code, out := w.callback(w.alice, q); code != http.StatusBadRequest || !strings.Contains(out, "invalid") {
		t.Errorf("replayed state = %d %q", code, out)
	}
	if n := len(o.tokens()); n != 1 {
		t.Errorf("%d token requests, want exactly the good one", n)
	}
	var bobConns string
	err := w.st.WithJobs(t.Context(), func(tx store.Tx) error {
		return tx.QueryRow(t.Context(), `SELECT count(*)::text FROM mcp_server_user_connections WHERE user_id = $1`, w.bob.id).Scan(&bobConns)
	})
	if err != nil || bobConns != "0" {
		t.Errorf("bob's connections = %s (%v), want none", bobConns, err)
	}
}

func flip(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] == 'A' {
			b[i] = 'B'
		} else {
			b[i] = 'A'
		}
	}
	return string(b)
}

// TestSecurityFedOAuthPinnedEndpointAndRefreshIsolation: alice publishes
// an OAuth server, bob and alice connect their own accounts. The owner
// then makes the AS metadata advertise another token endpoint; bob's
// refresh still goes to the endpoint pinned when he connected, with his
// own refresh token only, and each user keeps getting their own identity.
func TestSecurityFedOAuthPinnedEndpointAndRefreshIsolation(t *testing.T) {
	w := newWorld(t, options{federation: true})
	w.allowLoopback()
	o := newOAuthUpstream(t)
	evilToken := newUpstream(t, notesServer)
	s := w.addServer(w.alice, "oauthnotes", o.base+"/mcp", oauthServer)
	w.connectOAuth(o, w.alice, "alice", s.ID)
	w.review(w.alice, s, "search")
	w.publish(s, []policy.ToolRule{{App: "oauthnotes", Tool: "search", Outcome: policy.OutcomeAllow}}, roleMember, roleRestricted)
	w.connectOAuth(o, w.bob, "bob", s.ID)
	alice, bob := w.client(w.alice), w.client(w.bob)
	for _, c := range []struct {
		cs   *sdk.ClientSession
		want string
	}{{alice, "alice"}, {bob, "bob"}} {
		res, err := w.call(c.cs, "oauthnotes.search", map[string]any{"q": "x"})
		if err != nil || text(t, res) != "results for "+c.want {
			t.Fatalf("%s: %v %+v", c.want, err, res)
		}
	}

	// The owner's upstream now advertises a token endpoint she controls.
	o.mu.Lock()
	o.tokenURL = evilToken.URL() + "/token"
	o.mu.Unlock()
	o.revokeAccess("bob")
	before := len(o.tokens())
	res, err := w.call(bob, "oauthnotes.search", map[string]any{"q": "after"})
	if err != nil || text(t, res) != "results for bob" {
		t.Fatalf("bob after refresh: %v %+v", err, res)
	}
	if n := len(evilToken.requests()); n != 0 {
		t.Errorf("the swapped token endpoint received %d requests", n)
	}
	calls := o.tokens()[before:]
	if len(calls) != 1 || calls[0].Get("grant_type") != "refresh_token" || !strings.HasPrefix(calls[0].Get("refresh_token"), "rt-bob-") {
		t.Errorf("refresh requests = %v, want one with bob's refresh token", calls)
	}
	res, err = w.call(alice, "oauthnotes.search", map[string]any{"q": "after"})
	if err != nil || text(t, res) != "results for alice" {
		t.Errorf("alice after bob's refresh: %v %+v", err, res)
	}
}

// TestSecurityFedOAuthConnectFlowSurvivesNoURLChange: a connect flow that
// started before the server's URL changed must not finish: the token was
// minted for the old resource and would be sent to the new address on the
// next call. Since schema 17 only an admin can move a published server
// (the owner's attempt is refused); the admin's move, even once the
// server is re-reviewed, must not complete the flow either.
func TestSecurityFedOAuthConnectFlowSurvivesNoURLChange(t *testing.T) {
	w := newWorld(t, options{federation: true})
	ctx := t.Context()
	w.allowLoopback()
	o := newOAuthUpstream(t)
	evil := newUpstream(t, notesServer)
	s := w.addServer(w.alice, "oauthnotes", o.base+"/mcp", oauthServer)
	w.connectOAuth(o, w.alice, "alice", s.ID)
	w.review(w.alice, s, "search")
	w.publish(s, []policy.ToolRule{{App: "oauthnotes", Tool: "search", Outcome: policy.OutcomeAllow}}, roleRestricted)

	authz, state := w.startConnect(w.bob, s.ID) // bob is at the AS sign-in page...
	moved := *s                                 // ...while the server is repointed:
	moved.URL = evil.URL() + "/mcp"
	if err := w.fed.Manager.UpdateServer(ctx, w.alice.id, &moved); !errors.Is(err, store.ErrMCPServerLocked) {
		t.Fatalf("owner URL change of a published server = %v, want ErrMCPServerLocked", err)
	}
	// by an admin, who then re-approves the snapshot.
	if err := fedadmin.NewStore(w.st).UpdateAddress(ctx, s.ID, moved.URL); err != nil {
		t.Fatal(err)
	}
	adminActor := snapshot.Actor{UserID: w.admin.id, Admin: true}
	latest, err := w.fed.Snapshots.Latest(ctx, adminActor, s.ID)
	if err != nil {
		t.Fatal(err)
	}
	on := true
	if _, err := w.fed.Snapshots.Approve(ctx, adminActor, s.ID, latest.Version,
		snapshot.ReviewDecisions{Tools: map[string]snapshot.Decision{"search": {Enabled: &on}}}); err != nil {
		t.Fatal(err)
	}
	if err := w.fed.Manager.ServerChanged(ctx, s.ID); err != nil {
		t.Fatal(err)
	}
	code, out := w.callback(w.bob, url.Values{"state": {state}, "code": {o.mint("bob", authz)}, "iss": {o.base}})
	bob := w.client(w.bob)
	_, err = w.call(bob, "oauthnotes.search", map[string]any{"q": "x"})
	if evil.sawValue("at-bob-") {
		t.Errorf("bob's access token (minted for the old resource) reached the owner's new URL (callback %d %q)", code, out)
	}
	if code != http.StatusBadRequest {
		t.Errorf("callback after the URL change = %d %q, want 400", code, out)
	}
	_ = rpcError(t, err, mcp.CodeNoAccount)
}
