package github_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// testToken is the bearer every fixture server expects; nothing else is
// accepted so a request without the account's token is caught.
const testToken = "test-access-token"

// route is one canned answer of the fixture server: a status, optional
// headers and a body (a testdata file name, or inline JSON when it starts
// with "{" or "[").
type route struct {
	status  int
	headers map[string]string
	body    string
}

// apiServer is an httptest server answering "METHOD /path" (query string
// excluded) from a route table, recording every request it saw.
type apiServer struct {
	*httptest.Server
	mu       sync.Mutex
	routes   map[string]route
	requests []*http.Request
}

func newAPIServer(t *testing.T, routes map[string]route) *apiServer {
	t.Helper()
	s := &apiServer{routes: routes}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		s.requests = append(s.requests, r.Clone(r.Context()))
		s.mu.Unlock()
		if got := r.Header.Get("Authorization"); got != "Bearer "+testToken {
			t.Errorf("%s %s: Authorization = %q, want Bearer %s", r.Method, r.URL.Path, got, testToken)
			http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
			return
		}
		rt, ok := routes[r.Method+" "+r.URL.Path]
		if !ok {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
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
func (s *apiServer) Requests() []*http.Request {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]*http.Request(nil), s.requests...)
}
