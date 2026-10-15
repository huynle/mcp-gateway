package microsoft_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/microsoft"
)

// testToken is the bearer every fixture server expects; nothing else is
// accepted so a request without the account's token is caught.
const testToken = "test-graph-token"

const (
	alice = "user-alice"
	acct  = "0b7f7a2e-1c7e-4c2a-9a39-2d2a6c0f9b11"
)

// route is one canned answer of the fixture server: a status, optional
// headers and a body (a testdata file name, or inline JSON when it starts
// with "{" or "["). delay holds the answer back (past the connector's
// timeout when needed); pages, when set, picks the answer by the
// "$skiptoken" query value (missing = "1").
type route struct {
	status  int
	headers map[string]string
	body    string
	delay   time.Duration
	pages   map[string]route
}

// recorded is one request the fixture server saw, with its body.
type recorded struct {
	*http.Request
	Body string
}

// apiServer is an httptest Graph answering "METHOD /v1.0/path" (query
// string excluded) from a route table, recording every request it saw.
type apiServer struct {
	*httptest.Server
	mu       sync.Mutex
	routes   map[string]route
	requests []recorded
}

func newAPIServer(t *testing.T, routes map[string]route) *apiServer {
	t.Helper()
	s := &apiServer{routes: routes}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.requests = append(s.requests, recorded{Request: r.Clone(r.Context()), Body: string(body)})
		s.mu.Unlock()
		if got := r.Header.Get("Authorization"); got != "Bearer "+testToken {
			t.Errorf("%s %s: Authorization = %q, want Bearer %s", r.Method, r.URL.Path, got, testToken)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(fixture(t, "error_invalid_token.json")))
			return
		}
		rt, ok := routes[r.Method+" "+r.URL.Path]
		if !ok {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(fixture(t, "error_item_not_found.json")))
			return
		}
		if rt.pages != nil {
			page := r.URL.Query().Get("$skiptoken")
			if page == "" {
				page = "1"
			}
			if rt, ok = rt.pages[page]; !ok {
				t.Errorf("unexpected page %s of %s %s", page, r.Method, r.URL.Path)
				w.WriteHeader(http.StatusNotFound)
				return
			}
		}
		if rt.delay > 0 {
			select {
			case <-time.After(rt.delay):
			case <-r.Context().Done():
				return
			}
		}
		for k, v := range rt.headers {
			w.Header().Set(k, v)
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(rt.status)
		_, _ = w.Write([]byte(s.body(t, rt.body)))
	}))
	t.Cleanup(s.Close)
	return s
}

// body returns a route body with the fixture server's own URL in place
// of the fixtures' next-link host, so paging stays on the stub.
func (s *apiServer) body(t *testing.T, name string) string {
	t.Helper()
	return strings.ReplaceAll(fixture(t, name), "https://graph.example.test", s.URL)
}

// fixture returns the body: inline JSON as is, else the testdata file.
func fixture(t *testing.T, body string) string {
	t.Helper()
	if body == "" || strings.HasPrefix(body, "{") || strings.HasPrefix(body, "[") {
		return body
	}
	b, err := os.ReadFile(filepath.Join("testdata", body))
	if err != nil {
		t.Fatalf("fixture %s: %v", body, err)
	}
	return string(b)
}

// Requests returns the requests the server saw so far.
func (s *apiServer) Requests() []recorded {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]recorded(nil), s.requests...)
}

// Last returns the last request to "METHOD /path", failing when none.
func (s *apiServer) Last(t *testing.T, methodPath string) recorded {
	t.Helper()
	reqs := s.Requests()
	for i := len(reqs) - 1; i >= 0; i-- {
		if reqs[i].Method+" "+reqs[i].URL.Path == methodPath {
			return reqs[i]
		}
	}
	t.Fatalf("no request %s (saw %d requests)", methodPath, len(reqs))
	return recorded{}
}

// Count returns how many requests to "METHOD /path" the server saw.
func (s *apiServer) Count(methodPath string) int {
	n := 0
	for _, r := range s.Requests() {
		if r.Method+" "+r.URL.Path == methodPath {
			n++
		}
	}
	return n
}

// tokens is the TokenSourceFunc of the tests: every call records who asked
// for which connection and gets the fixture token, unless fail is set.
type tokens struct {
	calls []string
	fail  error
}

func (tk *tokens) source(_ context.Context, userID, connectionID string) oauth2.TokenSource {
	tk.calls = append(tk.calls, userID+"/"+connectionID)
	if tk.fail != nil {
		return failingSource{err: tk.fail}
	}
	return oauth2.StaticTokenSource(&oauth2.Token{AccessToken: testToken})
}

type failingSource struct{ err error }

func (f failingSource) Token() (*oauth2.Token, error) { return nil, f.err }

// workScopes is every scope the tools need, as a work account that
// granted everything carries them.
var workScopes = []string{
	"User.Read", "offline_access", "openid",
	"Mail.Read", "Mail.Send", "Calendars.ReadWrite", "Files.ReadWrite.All",
	"Team.ReadBasic.All", "Channel.ReadBasic.All", "ChannelMessage.Read.All", "ChannelMessage.Send",
	"Mail.ReadWrite", "Calendars.Read.Shared", "Chat.Read", "ChatMessage.Send", "Tasks.ReadWrite",
	"Contacts.Read", "People.Read", "User.ReadBasic.All",
}

// newConnector builds a connector against the fixture server whose
// account source knows acct as a work account with every scope.
func newConnector(t *testing.T, srv *apiServer, bounds connectors.Bounds) (*microsoft.Connector, *tokens) {
	t.Helper()
	return newConnectorWithScopes(t, srv, bounds, workScopes)
}

// newConnectorWithScopes is newConnector with the account's scopes.
func newConnectorWithScopes(t *testing.T, srv *apiServer, bounds connectors.Bounds, scopes []string) (*microsoft.Connector, *tokens) {
	t.Helper()
	tk := &tokens{}
	src := connectors.NewStaticAccountSource()
	src.Add(alice, connectors.Account{ID: acct, App: microsoft.App, Label: connectors.LabelCompany, DisplayName: "alice@example.test", Scopes: scopes})
	c, err := microsoft.New(microsoft.Options{Tokens: tk.source, Accounts: src, BaseURL: srv.URL + "/v1.0/", Bounds: bounds})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, tk
}

func call(tool string, args map[string]any) connectors.Call {
	if args == nil {
		args = map[string]any{}
	}
	return connectors.Call{Principal: connectors.Principal{UserID: alice, TokenID: "tok"}, Tool: "microsoft." + tool, Account: acct, Args: args}
}

// decode marshals a result's content and decodes it into v.
func decode(t *testing.T, res connectors.Result, v any) {
	t.Helper()
	raw, err := json.Marshal(res.Content)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("decode %s: %v", raw, err)
	}
}

func wantClass(t *testing.T, err error, class string, status int) {
	t.Helper()
	var msErr *microsoft.Error
	if !errors.As(err, &msErr) {
		t.Fatalf("err = %v (%T), want *microsoft.Error class %s", err, err, class)
	}
	if msErr.Class != class || msErr.Status != status {
		t.Fatalf("err = class %s status %d (%v), want class %s status %d", msErr.Class, msErr.Status, err, class, status)
	}
}

// query returns the query of the last request to path.
func query(t *testing.T, srv *apiServer, path string) url.Values {
	t.Helper()
	reqs := srv.Requests()
	for i := len(reqs) - 1; i >= 0; i-- {
		if reqs[i].URL.Path == path {
			return reqs[i].URL.Query()
		}
	}
	t.Fatalf("no request to %s (saw %d requests)", path, len(reqs))
	return nil
}
