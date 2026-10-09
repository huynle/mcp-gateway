package google_test

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
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// testToken is the bearer every fixture server expects; nothing else is
// accepted so a request without the account's token is caught.
const testToken = "test-access-token"

const (
	alice = "user-alice"
	acct  = "0b7f7a2e-1c7e-4c2a-9a39-2d2a6c0f9b11"
)

// route is one canned answer of the fixture server: a status, optional
// headers and a body (a testdata file name, or inline JSON when it starts
// with "{" or "["). delay holds the answer back (until the client gives
// up when it exceeds the connector's timeout); pages, when set, picks the
// answer by the "pageToken" query value (missing token = "1"); byQuery,
// when set, picks the answer by the "q" query value.
type route struct {
	status  int
	headers map[string]string
	body    string
	delay   time.Duration
	pages   map[string]route
	byQuery map[string]route
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
			http.Error(w, fixture(t, "error_unauthorized.json"), http.StatusUnauthorized)
			return
		}
		rt, ok := routes[r.Method+" "+r.URL.Path]
		if !ok {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.Error(w, fixture(t, "error_not_found.json"), http.StatusNotFound)
			return
		}
		if rt.pages != nil {
			page := r.URL.Query().Get("pageToken")
			if page == "" {
				page = "1"
			}
			if rt, ok = rt.pages[page]; !ok {
				t.Errorf("unexpected pageToken %s of %s %s", page, r.Method, r.URL.Path)
				http.Error(w, fixture(t, "error_not_found.json"), http.StatusNotFound)
				return
			}
		}
		if rt.byQuery != nil {
			q := r.URL.Query().Get("q")
			if rt, ok = rt.byQuery[q]; !ok {
				t.Errorf("unexpected q %q of %s %s", q, r.Method, r.URL.Path)
				http.Error(w, fixture(t, "error_not_found.json"), http.StatusNotFound)
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

// newConnector builds a connector against the fixture server.
func newConnector(t *testing.T, srv *apiServer, bounds connectors.Bounds) (*google.Connector, *tokens) {
	t.Helper()
	tk := &tokens{}
	c, err := google.New(google.Options{Tokens: tk.source, BaseURL: srv.URL + "/", Bounds: bounds})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, tk
}

// appOf returns the app connector named app.
func appOf(t *testing.T, c *google.Connector, app string) *google.App {
	t.Helper()
	for _, a := range c.Apps() {
		if a.App() == app {
			return a
		}
	}
	t.Fatalf("no app %s", app)
	return nil
}

// toolOf returns the declared tool "app.name".
func toolOf(t *testing.T, c *google.Connector, full string) connectors.Tool {
	t.Helper()
	app, name, _ := strings.Cut(full, ".")
	for _, tool := range appOf(t, c, app).Tools() {
		if tool.Name == name {
			return tool
		}
	}
	t.Fatalf("no tool %s", full)
	return connectors.Tool{}
}

// call builds a read call of "app.tool".
func call(full string, args map[string]any) connectors.Call {
	if args == nil {
		args = map[string]any{}
	}
	return connectors.Call{Principal: connectors.Principal{UserID: alice, TokenID: "tok"}, Tool: full, Account: acct, Args: args}
}

// write builds a write call of "app.tool" under a fixed operation id.
func write(full string, args map[string]any) connectors.Call {
	c := call(full, args)
	c.OperationID = opID
	return c
}

// opID is the ledger operation id the write tests run under.
const opID = "3f9c2b4e-8d1a-4e5f-9b7c-0a1b2c3d4e5f"

// run dispatches a call to the app named by its tool.
func run(t *testing.T, c *google.Connector, cl connectors.Call) (connectors.Result, error) {
	t.Helper()
	app, _, _ := strings.Cut(cl.Tool, ".")
	return appOf(t, c, app).Call(context.Background(), cl)
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
	var gerr *google.Error
	if !errors.As(err, &gerr) {
		t.Fatalf("err = %v (%T), want *google.Error class %s", err, err, class)
	}
	if gerr.Class != class || gerr.Status != status {
		t.Fatalf("err = class %s status %d (%v), want class %s status %d", gerr.Class, gerr.Status, err, class, status)
	}
}

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

// readErrorCases are the vendor answers every read maps the same way.
func readErrorCases() []struct {
	name        string
	rt          route
	class       string
	status      int
	unavailable bool
	rateLim     bool
} {
	return []struct {
		name        string
		rt          route
		class       string
		status      int
		unavailable bool
		rateLim     bool
	}{
		{name: "404 not found", rt: route{status: 404, body: "error_not_found.json"}, class: google.ClassNotFound, status: 404},
		{name: "401 reconnect", rt: route{status: 401, body: "error_unauthorized.json"}, class: google.ClassReconnectRequired, status: 401},
		{name: "403 forbidden", rt: route{status: 403, body: "error_forbidden.json"}, class: google.ClassForbidden, status: 403},
		{name: "403 insufficient scope", rt: route{status: 403, body: "error_insufficient_scope.json"}, class: google.ClassScopeRequired, status: 403},
		{name: "400 invalid", rt: route{status: 400, body: "error_bad_request.json"}, class: google.ClassInvalidArgument, status: 400},
		{name: "403 rate limited", rt: route{status: 403, body: "error_rate_limit_403.json"}, rateLim: true},
		{name: "429 rate limited", rt: route{status: 429, body: "error_rate_limit_429.json", headers: map[string]string{"Retry-After": "7"}}, rateLim: true},
		{name: "500 unavailable", rt: route{status: 500, body: "error_server.json"}, unavailable: true},
		{name: "503 unavailable", rt: route{status: 503, body: "error_server.json"}, unavailable: true},
	}
}

// checkReadError asserts the outcome of one readErrorCases entry.
func checkReadError(t *testing.T, tc struct {
	name        string
	rt          route
	class       string
	status      int
	unavailable bool
	rateLim     bool
}, res connectors.Result, err error) {
	t.Helper()
	switch {
	case tc.unavailable:
		if err != nil || !res.Unavailable || res.Content != nil {
			t.Fatalf("res = %+v, err = %v; want Unavailable without content", res, err)
		}
	case tc.rateLim:
		var rl *connectors.RateLimited
		if !errors.As(err, &rl) || rl.App != google.Vendor || rl.RetryAfter <= 0 {
			t.Fatalf("err = %v (%T), want *connectors.RateLimited for %s", err, err, google.Vendor)
		}
		if tc.rt.headers["Retry-After"] == "7" && rl.RetryAfter != 7*time.Second {
			t.Errorf("RetryAfter = %s, want 7s from the header", rl.RetryAfter)
		}
	default:
		wantClass(t, err, tc.class, tc.status)
	}
	if err != nil && strings.Contains(err.Error(), testToken) {
		t.Errorf("error message leaks the token: %q", err.Error())
	}
}
