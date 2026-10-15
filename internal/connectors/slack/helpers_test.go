package slack_test

import (
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
)

// Tokens the fixture server accepts: the user token every tool call
// sends, and the bot token a Slack OAuth v2 exchange puts at the top
// level of its answer (the binder must never identify the account with
// it when a user token is present).
const (
	testToken = "xoxp-test-user-token"
	botToken  = "xoxb-test-bot-token"
)

// route is one canned answer of the fixture server: a status, optional
// headers and a body (a testdata file name, or inline JSON when it starts
// with "{"). delay holds the answer back (until the client gives up when
// it exceeds the connector's timeout); byCursor, when set, picks the
// answer by the "cursor" form value (missing cursor = ""); byPage does
// the same by "page" (missing = "1"); byToken by the "token" form value.
type route struct {
	status   int
	headers  map[string]string
	body     string
	delay    time.Duration
	byCursor map[string]route
	byPage   map[string]route
	byToken  map[string]route
	// raw sends body as is (a file download), never as a fixture name.
	raw bool
}

// recorded is one request the fixture server saw, with its decoded form.
type recorded struct {
	Method string
	Path   string
	Form   url.Values
	Header http.Header
	Body   []byte
}

// apiServer is an httptest server answering Slack Web API methods
// ("auth.test", "conversations.history", ...) from a route table under
// /api/, recording every request it saw. slack-go sends the token as the
// "token" form field; the server rejects anything but the fixture
// tokens so a request without the account's token is caught.
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
		form, _ := url.ParseQuery(string(body))
		if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") && form.Get("token") == "" {
			form.Set("token", strings.TrimPrefix(auth, "Bearer "))
		}
		for k, v := range r.URL.Query() {
			if _, ok := form[k]; !ok {
				form[k] = v
			}
		}
		method := strings.TrimPrefix(r.URL.Path, "/api/")
		s.mu.Lock()
		s.requests = append(s.requests, recorded{Method: method, Path: r.URL.Path, Form: form, Header: r.Header.Clone(), Body: body})
		s.mu.Unlock()
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		tok := form.Get("token")
		if tok != testToken && tok != botToken {
			t.Errorf("%s: token = %q, want one of the fixture tokens", method, tok)
			_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
			return
		}
		rt, ok := routes[method]
		if !ok {
			t.Errorf("unexpected request %s (form %v)", method, redactForm(form))
			_, _ = w.Write([]byte(`{"ok":false,"error":"unknown_method"}`))
			return
		}
		if rt.byToken != nil {
			if rt, ok = rt.byToken[tok]; !ok {
				t.Errorf("unexpected token for %s", method)
				_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
				return
			}
		}
		if rt.byCursor != nil {
			cursor := form.Get("cursor")
			if rt, ok = rt.byCursor[cursor]; !ok {
				t.Errorf("unexpected cursor %q for %s", cursor, method)
				_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_cursor"}`))
				return
			}
		}
		if rt.byPage != nil {
			page := form.Get("page")
			if page == "" {
				page = "1"
			}
			if rt, ok = rt.byPage[page]; !ok {
				t.Errorf("unexpected page %q for %s", page, method)
				_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_page"}`))
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
		status := rt.status
		if status == 0 {
			status = http.StatusOK
		}
		w.WriteHeader(status)
		if rt.raw {
			_, _ = w.Write([]byte(rt.body))
			return
		}
		_, _ = w.Write([]byte(fixture(t, rt.body)))
	}))
	t.Cleanup(s.Close)
	return s
}

// redactForm hides the token in test failure output.
func redactForm(form url.Values) url.Values {
	out := url.Values{}
	for k, v := range form {
		if k == "token" {
			out[k] = []string{"<redacted>"}
			continue
		}
		out[k] = v
	}
	return out
}

// fixture returns the body: inline JSON as is, else the testdata file.
func fixture(t *testing.T, body string) string {
	t.Helper()
	if body == "" || strings.HasPrefix(body, "{") || strings.HasPrefix(body, "<") {
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

// Last returns the last request to method, failing when none.
func (s *apiServer) Last(t *testing.T, method string) recorded {
	t.Helper()
	reqs := s.Requests()
	for i := len(reqs) - 1; i >= 0; i-- {
		if reqs[i].Method == method {
			return reqs[i]
		}
	}
	t.Fatalf("no request %s (saw %d requests)", method, len(reqs))
	return recorded{}
}

// Count returns how many requests to method the server saw.
func (s *apiServer) Count(method string) int {
	n := 0
	for _, r := range s.Requests() {
		if r.Method == method {
			n++
		}
	}
	return n
}

// API returns the Web API root the connector and binder point at.
func (s *apiServer) API() string { return s.URL + "/api/" }
