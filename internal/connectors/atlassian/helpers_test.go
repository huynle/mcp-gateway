package atlassian_test

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
	"github.com/huynle/mcp-gateway/internal/connectors/atlassian"
)

// Fixture identities: a user, a connection and the site it is bound to.
const (
	testToken = "test-access-token"
	alice     = "user-alice"
	acct      = "0b7f7a2e-1c7e-4c2a-9a39-2d2a6c0f9b11"
	cloudID   = "11111111-2222-4333-8444-555555555555"
	siteURL   = "https://example-site.atlassian.example.test"
	jiraBase  = "/ex/jira/" + cloudID + "/rest/api/3"
	wikiBase  = "/ex/confluence/" + cloudID + "/wiki"
)

// route is one canned answer of the fixture server: a status, optional
// headers and a body (a testdata file name, or inline JSON when it starts
// with "{" or "["). delay holds the answer back (until the client gives
// up when it exceeds the connector's timeout); pages, when set, picks the
// answer by the value of the pageParam query parameter ("" when absent).
type route struct {
	status    int
	headers   map[string]string
	body      string
	delay     time.Duration
	pageParam string
	pages     map[string]route
}

// recorded is one request the fixture server saw, with its body.
type recorded struct {
	*http.Request
	Body string
}

// apiServer is an httptest server answering "METHOD /path" (query string
// excluded) from a route table, recording every request it saw.
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
			http.Error(w, `{"message":"Unauthorized"}`, http.StatusUnauthorized)
			return
		}
		rt, ok := routes[r.Method+" "+r.URL.Path]
		if !ok {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.Error(w, `{"errorMessages":["not found"]}`, http.StatusNotFound)
			return
		}
		if rt.pages != nil {
			page := r.URL.Query().Get(rt.pageParam)
			if rt, ok = rt.pages[page]; !ok {
				t.Errorf("unexpected page %q of %s %s", page, r.Method, r.URL.Path)
				http.Error(w, `{"errorMessages":["not found"]}`, http.StatusNotFound)
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
		_, _ = w.Write([]byte(fixture(t, rt.body)))
	}))
	t.Cleanup(s.Close)
	return s
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

// sites is the SiteSourceFunc of the tests: every connection is bound to
// the fixture site, unless fail is set.
type sites struct {
	calls []string
	fail  error
	site  atlassian.Site
}

func (s *sites) source(_ context.Context, userID, connectionID string) (atlassian.Site, error) {
	s.calls = append(s.calls, userID+"/"+connectionID)
	if s.fail != nil {
		return atlassian.Site{}, s.fail
	}
	if s.site.CloudID != "" {
		return s.site, nil
	}
	return atlassian.Site{CloudID: cloudID, URL: siteURL}, nil
}

// newConnector builds a connector for app against the fixture server.
func newConnector(t *testing.T, app string, srv *apiServer, bounds connectors.Bounds) (*atlassian.Connector, *tokens) {
	t.Helper()
	tk := &tokens{}
	c, err := atlassian.New(app, atlassian.Options{Tokens: tk.source, Sites: (&sites{}).source, BaseURL: srv.URL, Bounds: bounds})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, tk
}

func newJira(t *testing.T, srv *apiServer, bounds connectors.Bounds) (*atlassian.Connector, *tokens) {
	t.Helper()
	return newConnector(t, atlassian.JiraApp, srv, bounds)
}

func newConfluence(t *testing.T, srv *apiServer, bounds connectors.Bounds) (*atlassian.Connector, *tokens) {
	t.Helper()
	return newConnector(t, atlassian.ConfluenceApp, srv, bounds)
}

// call builds a read call of "<app>.<tool>" for the fixture account.
func call(app, tool string, args map[string]any) connectors.Call {
	if args == nil {
		args = map[string]any{}
	}
	return connectors.Call{Principal: connectors.Principal{UserID: alice, TokenID: "tok"}, Tool: app + "." + tool, Account: acct, Args: args}
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
	var aErr *atlassian.Error
	if !errors.As(err, &aErr) {
		t.Fatalf("err = %v (%T), want *atlassian.Error class %s", err, err, class)
	}
	if aErr.Class != class || aErr.Status != status {
		t.Fatalf("err = class %s status %d (%v), want class %s status %d", aErr.Class, aErr.Status, err, class, status)
	}
}

// toolNamed returns the connector's tool by short name.
func toolNamed(t *testing.T, c *atlassian.Connector, name string) connectors.Tool {
	t.Helper()
	for _, tool := range c.Tools() {
		if tool.Name == name {
			return tool
		}
	}
	t.Fatalf("tool %s not declared", name)
	return connectors.Tool{}
}

// jsonBody decodes a recorded request body.
func jsonBody(t *testing.T, r recorded) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(r.Body), &m); err != nil {
		t.Fatalf("request body %q: %v", r.Body, err)
	}
	return m
}
