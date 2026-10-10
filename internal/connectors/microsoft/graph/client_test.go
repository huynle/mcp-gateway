package graph_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/huynle/mcp-gateway/internal/connectors/microsoft/graph"
)

const testToken = "test-graph-token"

// stub is an httptest Graph that answers "METHOD /path" from a handler
// table and records every request (with its body).
type stub struct {
	*httptest.Server
	mu       sync.Mutex
	handlers map[string]http.HandlerFunc
	requests []recorded
}

type recorded struct {
	Method, Path, Query, Body string
	Header                    http.Header
}

func newStub(t *testing.T, handlers map[string]http.HandlerFunc) *stub {
	t.Helper()
	s := &stub{handlers: handlers}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.mu.Lock()
		s.requests = append(s.requests, recorded{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Body: string(body), Header: r.Header.Clone()})
		s.mu.Unlock()
		if got := r.Header.Get("Authorization"); got != "Bearer "+testToken {
			t.Errorf("%s %s: Authorization = %q", r.Method, r.URL.Path, got)
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":"InvalidAuthenticationToken","message":"Access token is empty."}}`))
			return
		}
		h, ok := handlers[r.Method+" "+r.URL.Path]
		if !ok {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":"ResourceNotFound","message":"nope"}}`))
			return
		}
		h(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *stub) Requests() []recorded {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]recorded(nil), s.requests...)
}

func jsonAnswer(status int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}
}

func newClient(t *testing.T, s *stub) *graph.Client {
	t.Helper()
	c, err := graph.New(graph.Options{
		BaseURL: s.URL + "/v1.0/",
		Token:   oauth2.StaticTokenSource(&oauth2.Token{AccessToken: testToken}),
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestNewValidatesOptions(t *testing.T) {
	if _, err := graph.New(graph.Options{}); err == nil {
		t.Error("New without a token source succeeded")
	}
	if _, err := graph.New(graph.Options{Token: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "x"}), BaseURL: "not a url"}); err == nil {
		t.Error("New with a bad BaseURL succeeded")
	}
	c, err := graph.New(graph.Options{Token: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "x"})})
	if err != nil {
		t.Fatal(err)
	}
	if c.BaseURL() != graph.DefaultBaseURL {
		t.Errorf("BaseURL() = %q, want %q", c.BaseURL(), graph.DefaultBaseURL)
	}
}

func TestGetSendsBearerAndDecodes(t *testing.T) {
	s := newStub(t, map[string]http.HandlerFunc{
		"GET /v1.0/me": jsonAnswer(200, `{"id":"oid-1","userPrincipalName":"alice@example.test"}`),
	})
	c := newClient(t, s)
	var me struct {
		ID  string `json:"id"`
		UPN string `json:"userPrincipalName"`
	}
	if err := c.Get(context.Background(), "me", url.Values{"$select": {"id,userPrincipalName"}}, &me); err != nil {
		t.Fatalf("Get: %v", err)
	}
	if me.ID != "oid-1" || me.UPN != "alice@example.test" {
		t.Errorf("me = %+v", me)
	}
	req := s.Requests()[0]
	if req.Query != "%24select=id%2CuserPrincipalName" {
		t.Errorf("query = %q", req.Query)
	}
	if ua := req.Header.Get("User-Agent"); !strings.Contains(ua, "mcp-gateway") {
		t.Errorf("User-Agent = %q", ua)
	}
	if got := req.Header.Get("Accept"); got != "application/json" {
		t.Errorf("Accept = %q", got)
	}
}

func TestPathsJoinUnderTheBase(t *testing.T) {
	s := newStub(t, map[string]http.HandlerFunc{
		"GET /v1.0/me/messages/AAMk":              jsonAnswer(200, `{"id":"AAMk"}`),
		"GET /v1.0/me/drive/root/search(q='a b')": jsonAnswer(200, `{"value":[]}`),
	})
	c := newClient(t, s)
	var out map[string]any
	// Leading slash or not, the path lands under /v1.0/.
	for _, p := range []string{"me/messages/AAMk", "/me/messages/AAMk"} {
		if err := c.Get(context.Background(), p, nil, &out); err != nil {
			t.Errorf("Get(%q): %v", p, err)
		}
	}
	// Function segments keep their parentheses and quotes.
	if err := c.Get(context.Background(), "me/drive/root/search(q='a b')", nil, &out); err != nil {
		t.Errorf("Get(search): %v", err)
	}
}

func TestPostSendsJSONAndReadsStatus(t *testing.T) {
	s := newStub(t, map[string]http.HandlerFunc{
		"POST /v1.0/me/sendMail": func(w http.ResponseWriter, r *http.Request) {
			if ct := r.Header.Get("Content-Type"); ct != "application/json" {
				t.Errorf("Content-Type = %q", ct)
			}
			w.WriteHeader(http.StatusAccepted)
		},
		"POST /v1.0/me/events": jsonAnswer(201, `{"id":"evt-1"}`),
	})
	c := newClient(t, s)
	status, err := c.Post(context.Background(), "me/sendMail", map[string]any{"message": map[string]any{"subject": "hi"}}, nil)
	if err != nil || status != http.StatusAccepted {
		t.Fatalf("Post sendMail = %d, %v", status, err)
	}
	body := s.Requests()[0].Body
	if !strings.Contains(body, `"subject":"hi"`) {
		t.Errorf("body = %q", body)
	}
	var evt struct {
		ID string `json:"id"`
	}
	status, err = c.Post(context.Background(), "me/events", map[string]any{"subject": "x"}, &evt)
	if err != nil || status != http.StatusCreated || evt.ID != "evt-1" {
		t.Fatalf("Post events = %d, %v, %+v", status, err, evt)
	}
}

func TestHeadersAreSent(t *testing.T) {
	s := newStub(t, map[string]http.HandlerFunc{
		"GET /v1.0/me/messages/x": jsonAnswer(200, `{"id":"x"}`),
	})
	c := newClient(t, s)
	var out map[string]any
	_, err := c.Do(context.Background(), graph.Request{Method: http.MethodGet, Path: "me/messages/x", Header: http.Header{"Prefer": {`outlook.body-content-type="text"`}}}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if got := s.Requests()[0].Header.Get("Prefer"); got != `outlook.body-content-type="text"` {
		t.Errorf("Prefer = %q", got)
	}
}

func TestErrorEnvelope(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
		code   string
		msg    string
	}{
		{"401 invalid token", 401, `{"error":{"code":"InvalidAuthenticationToken","message":"Access token has expired.","innerError":{"date":"2026-10-08T00:00:00","request-id":"r1"}}}`, "InvalidAuthenticationToken", "Access token has expired."},
		{"404 item", 404, `{"error":{"code":"ErrorItemNotFound","message":"The specified object was not found in the store."}}`, "ErrorItemNotFound", "The specified object was not found in the store."},
		{"403 denied", 403, `{"error":{"code":"Authorization_RequestDenied","message":"Insufficient privileges to complete the operation."}}`, "Authorization_RequestDenied", "Insufficient privileges to complete the operation."},
		{"500 no envelope", 500, `<html>bad gateway</html>`, "", ""},
		{"400 empty body", 400, ``, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newStub(t, map[string]http.HandlerFunc{"GET /v1.0/me": jsonAnswer(tc.status, tc.body)})
			c := newClient(t, s)
			var out map[string]any
			err := c.Get(context.Background(), "me", nil, &out)
			var ge *graph.Error
			if !errors.As(err, &ge) {
				t.Fatalf("err = %v (%T), want *graph.Error", err, err)
			}
			if ge.Status != tc.status || ge.Code != tc.code || ge.Message != tc.msg {
				t.Errorf("err = %+v, want status %d code %q message %q", ge, tc.status, tc.code, tc.msg)
			}
			if !strings.Contains(ge.Error(), fmt.Sprint(tc.status)) {
				t.Errorf("Error() = %q should name the status", ge.Error())
			}
			if strings.Contains(ge.Error(), testToken) {
				t.Errorf("Error() leaks the token: %q", ge.Error())
			}
		})
	}
}

func TestThrottling(t *testing.T) {
	cases := []struct {
		name       string
		status     int
		retryAfter string
		throttled  bool
		wait       time.Duration
	}{
		{"429 with seconds", 429, "37", true, 37 * time.Second},
		{"429 without header", 429, "", true, 0},
		{"503 with Retry-After", 503, "5", true, 5 * time.Second},
		{"503 without Retry-After", 503, "", false, 0},
		{"429 with http date", 429, time.Now().Add(90 * time.Second).UTC().Format(http.TimeFormat), true, 90 * time.Second},
		{"500", 500, "", false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newStub(t, map[string]http.HandlerFunc{"GET /v1.0/me": func(w http.ResponseWriter, _ *http.Request) {
				if tc.retryAfter != "" {
					w.Header().Set("Retry-After", tc.retryAfter)
				}
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{"error":{"code":"TooManyRequests","message":"slow down"}}`))
			}})
			c := newClient(t, s)
			var out map[string]any
			err := c.Get(context.Background(), "me", nil, &out)
			var ge *graph.Error
			if !errors.As(err, &ge) {
				t.Fatalf("err = %v (%T)", err, err)
			}
			if ge.Throttled() != tc.throttled {
				t.Errorf("Throttled() = %v, want %v", ge.Throttled(), tc.throttled)
			}
			if d := ge.RetryAfter - tc.wait; d < -2*time.Second || d > 2*time.Second {
				t.Errorf("RetryAfter = %s, want about %s", ge.RetryAfter, tc.wait)
			}
		})
	}
}

func TestTransportFailureIsNotAGraphError(t *testing.T) {
	s := newStub(t, nil)
	c := newClient(t, s)
	s.Close()
	var out map[string]any
	err := c.Get(context.Background(), "me", nil, &out)
	var ge *graph.Error
	if err == nil || errors.As(err, &ge) {
		t.Fatalf("err = %v, want a transport error, not *graph.Error", err)
	}
}

func TestTokenSourceFailure(t *testing.T) {
	s := newStub(t, nil)
	want := errors.New("needs reconnect")
	c, err := graph.New(graph.Options{BaseURL: s.URL + "/v1.0/", Token: failingSource{want}})
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := c.Get(context.Background(), "me", nil, &out); !errors.Is(err, want) {
		t.Fatalf("err = %v, want the token source's error", err)
	}
	if n := len(s.Requests()); n != 0 {
		t.Errorf("%d requests sent without a token", n)
	}
}

type failingSource struct{ err error }

func (f failingSource) Token() (*oauth2.Token, error) { return nil, f.err }

func TestBodyIsBounded(t *testing.T) {
	huge := strings.Repeat("x", graph.MaxResponseBytes+10)
	s := newStub(t, map[string]http.HandlerFunc{"GET /v1.0/me": jsonAnswer(200, `{"id":"`+huge+`"}`)})
	c := newClient(t, s)
	var out map[string]any
	if err := c.Get(context.Background(), "me", nil, &out); err == nil {
		t.Fatal("a response over MaxResponseBytes decoded without error")
	}
}

// --- paging ------------------------------------------------------------------

type item struct {
	ID string `json:"id"`
}

func pageBody(next string, ids ...string) string {
	var items []item
	for _, id := range ids {
		items = append(items, item{ID: id})
	}
	page := map[string]any{"value": items}
	if next != "" {
		page["@odata.nextLink"] = next
	}
	b, _ := json.Marshal(page)
	return string(b)
}

func TestListFollowsNextLink(t *testing.T) {
	var s *stub
	s = newStub(t, map[string]http.HandlerFunc{
		"GET /v1.0/me/messages": func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Query().Get("$skiptoken") {
			case "":
				jsonAnswer(200, pageBody(s.URL+"/v1.0/me/messages?%24skiptoken=p2&%24top=2", "m1", "m2"))(w, r)
			case "p2":
				jsonAnswer(200, pageBody(s.URL+"/v1.0/me/messages?%24skiptoken=p3", "m3", "m4"))(w, r)
			case "p3":
				jsonAnswer(200, pageBody("", "m5"))(w, r)
			default:
				t.Errorf("unexpected skiptoken %q", r.URL.Query().Get("$skiptoken"))
			}
		},
	})
	c := newClient(t, s)
	items, more, err := graph.Collect[item](context.Background(), c, "me/messages", url.Values{"$top": {"2"}}, graph.ListOptions{MaxItems: 10, MaxPages: 5})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := ids(items); got != "m1,m2,m3,m4,m5" || more {
		t.Errorf("items = %s more = %v, want all five and no more", got, more)
	}
	if n := len(s.Requests()); n != 3 {
		t.Errorf("requests = %d, want 3 pages", n)
	}
	// The next link is followed as given (its own query), not re-rooted.
	if q := s.Requests()[1].Query; !strings.Contains(q, "skiptoken=p2") || !strings.Contains(q, "top=2") {
		t.Errorf("second request query = %q", q)
	}
}

func TestListStopsAtMaxItems(t *testing.T) {
	var s *stub
	s = newStub(t, map[string]http.HandlerFunc{
		"GET /v1.0/me/messages": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("$skiptoken") == "" {
				jsonAnswer(200, pageBody(s.URL+"/v1.0/me/messages?%24skiptoken=p2", "m1", "m2", "m3"))(w, r)
				return
			}
			jsonAnswer(200, pageBody("", "m4"))(w, r)
		},
	})
	c := newClient(t, s)
	items, more, err := graph.Collect[item](context.Background(), c, "me/messages", nil, graph.ListOptions{MaxItems: 2, MaxPages: 5})
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(items); got != "m1,m2" || !more {
		t.Errorf("items = %s more = %v, want the first two and more", got, more)
	}
	if n := len(s.Requests()); n != 1 {
		t.Errorf("requests = %d, want 1 (no page fetched past the item cap)", n)
	}
}

func TestListStopsAtMaxPages(t *testing.T) {
	var s *stub
	s = newStub(t, map[string]http.HandlerFunc{
		"GET /v1.0/me/messages": func(w http.ResponseWriter, r *http.Request) {
			jsonAnswer(200, pageBody(s.URL+"/v1.0/me/messages?%24skiptoken=again", "m"))(w, r)
		},
	})
	c := newClient(t, s)
	items, more, err := graph.Collect[item](context.Background(), c, "me/messages", nil, graph.ListOptions{MaxItems: 100, MaxPages: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 || !more {
		t.Errorf("items = %d more = %v, want 3 (one per page) and more", len(items), more)
	}
	if n := len(s.Requests()); n != 3 {
		t.Errorf("requests = %d, want 3", n)
	}
}

func TestListRefusesForeignNextLink(t *testing.T) {
	s := newStub(t, map[string]http.HandlerFunc{
		"GET /v1.0/me/messages": jsonAnswer(200, pageBody("https://evil.example.test/steal?x=1", "m1")),
	})
	c := newClient(t, s)
	_, _, err := graph.Collect[item](context.Background(), c, "me/messages", nil, graph.ListOptions{MaxItems: 10, MaxPages: 5})
	if err == nil {
		t.Fatal("a next link on another host was followed")
	}
	if n := len(s.Requests()); n != 1 {
		t.Errorf("requests = %d, want 1", n)
	}
}

func TestListErrorMidWay(t *testing.T) {
	var s *stub
	s = newStub(t, map[string]http.HandlerFunc{
		"GET /v1.0/me/messages": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("$skiptoken") == "" {
				jsonAnswer(200, pageBody(s.URL+"/v1.0/me/messages?%24skiptoken=p2", "m1"))(w, r)
				return
			}
			w.Header().Set("Retry-After", "3")
			jsonAnswer(429, `{"error":{"code":"TooManyRequests","message":"x"}}`)(w, r)
		},
	})
	c := newClient(t, s)
	items, _, err := graph.Collect[item](context.Background(), c, "me/messages", nil, graph.ListOptions{MaxItems: 10, MaxPages: 5})
	var ge *graph.Error
	if !errors.As(err, &ge) || !ge.Throttled() {
		t.Fatalf("err = %v, want the throttling error of page 2", err)
	}
	if len(items) != 1 {
		t.Errorf("items = %d, want the first page kept with the error", len(items))
	}
}

func TestEscapeQuotes(t *testing.T) {
	if got := graph.Quote("it's"); got != "'it''s'" {
		t.Errorf("Quote = %q", got)
	}
	if got := graph.Quote(""); got != "''" {
		t.Errorf("Quote(empty) = %q", got)
	}
}

func ids(items []item) string {
	var out []string
	for _, it := range items {
		out = append(out, it.ID)
	}
	return strings.Join(out, ",")
}
