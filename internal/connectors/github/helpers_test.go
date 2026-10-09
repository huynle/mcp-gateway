package github_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// testToken is the bearer every fixture server expects; nothing else is
// accepted so a request without the account's token is caught.
const testToken = "test-access-token"

// route is one canned answer of the fixture server: a status, optional
// headers and a body (a testdata file name, or inline JSON when it starts
// with "{" or "["). delay holds the answer back (until the client gives
// up when it exceeds the connector's timeout); pages, when set, picks the
// answer by the "page" query value (missing page = "1").
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
			http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
			return
		}
		rt, ok := routes[r.Method+" "+r.URL.Path]
		if !ok {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
			return
		}
		if rt.pages != nil {
			page := r.URL.Query().Get("page")
			if page == "" {
				page = "1"
			}
			if rt, ok = rt.pages[page]; !ok {
				t.Errorf("unexpected page %s of %s %s", page, r.Method, r.URL.Path)
				http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
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
