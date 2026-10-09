//go:build integration || e2e || security

package security

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// override lets a test take over the stub: it returns true when it
// answered the request itself.
type override func(w http.ResponseWriter, r *http.Request) bool

// --- GitHub ---------------------------------------------------------------------

// stubGitHub serves GET /user, GET /search/issues, POST
// /repos/{o}/{r}/issues (the REST calls the registered tools make) and
// checks the bearer; a test can install an override to answer with any
// status and body.
type stubGitHub struct {
	srv    *httptest.Server
	mu     sync.Mutex
	over   override
	issues []stubIssue
	nextID int64
	hits   int
}

type stubIssue struct {
	ID     int64  `json:"id"`
	Number int    `json:"number"`
	Title  string `json:"title"`
	Body   string `json:"body"`
	State  string `json:"state"`
	URL    string `json:"html_url"`
	repo   string
}

var issuesRE = regexp.MustCompile(`^/repos/([^/]+)/([^/]+)/issues$`)

func newStubGitHub(t *testing.T) *stubGitHub {
	t.Helper()
	s := &stubGitHub{nextID: 5000}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *stubGitHub) URL() string { return s.srv.URL + "/" }

// setOverride installs (or with nil removes) the override.
func (s *stubGitHub) setOverride(o override) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.over = o
}

// created returns the issues of repo ("owner/name").
func (s *stubGitHub) created(repo string) []stubIssue {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []stubIssue
	for _, is := range s.issues {
		if is.repo == repo {
			out = append(out, is)
		}
	}
	return out
}

// count returns how many requests reached the stub.
func (s *stubGitHub) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits
}

func (s *stubGitHub) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.hits++
	over := s.over
	s.mu.Unlock()
	if over != nil && over(w, r) {
		return
	}
	if got := r.Header.Get("Authorization"); got != "Bearer "+githubStubToken {
		http.Error(w, `{"message":"Bad credentials"}`, http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	path := r.URL.Path
	switch {
	case r.Method == http.MethodGet && path == "/user":
		_, _ = w.Write([]byte(`{"login":"alice-gh","id":1001}`))
	case r.Method == http.MethodGet && path == "/search/issues":
		_, _ = w.Write([]byte(`{"total_count":0,"incomplete_results":false,"items":[]}`))
	case r.Method == http.MethodPost && issuesRE.MatchString(path):
		m := issuesRE.FindStringSubmatch(path)
		s.create(w, r, m[1]+"/"+m[2])
	default:
		http.Error(w, `{"message":"Not Found"}`, http.StatusNotFound)
	}
}

func (s *stubGitHub) create(w http.ResponseWriter, r *http.Request, repo string) {
	var in struct {
		Title string `json:"title"`
		Body  string `json:"body"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || strings.TrimSpace(in.Title) == "" {
		http.Error(w, `{"message":"Validation Failed"}`, http.StatusUnprocessableEntity)
		return
	}
	s.mu.Lock()
	s.nextID++
	is := stubIssue{
		ID: s.nextID, Number: len(s.issues) + 1, Title: in.Title, Body: in.Body, State: "open",
		URL:  "https://github.example.test/" + repo + "/issues/" + strconv.Itoa(len(s.issues)+1),
		repo: repo,
	}
	s.issues = append(s.issues, is)
	s.mu.Unlock()
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(is)
}

// --- Slack ------------------------------------------------------------------------

// stubSlack serves users.conversations and chat.postMessage (what
// list_channels and post_message use) and checks the form token; a test
// can install an override.
type stubSlack struct {
	srv   *httptest.Server
	mu    sync.Mutex
	over  override
	posts []map[string]string
	hits  int
}

func newStubSlack(t *testing.T) *stubSlack {
	t.Helper()
	s := &stubSlack{}
	s.srv = httptest.NewServer(http.HandlerFunc(s.serve))
	t.Cleanup(s.srv.Close)
	return s
}

func (s *stubSlack) URL() string { return s.srv.URL + "/api/" }

func (s *stubSlack) setOverride(o override) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.over = o
}

func (s *stubSlack) list() []map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]map[string]string(nil), s.posts...)
}

func (s *stubSlack) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.hits
}

func (s *stubSlack) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.hits++
	over := s.over
	s.mu.Unlock()
	if over != nil && over(w, r) {
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.PostForm.Get("token") != slackUserToken {
		_, _ = w.Write([]byte(`{"ok":false,"error":"invalid_auth"}`))
		return
	}
	switch strings.TrimPrefix(r.URL.Path, "/api/") {
	case "users.conversations":
		_, _ = w.Write([]byte(`{"ok":true,"channels":[
			{"id":"C0ENGDEP01","name":"eng-deploys","name_normalized":"eng-deploys","is_channel":true,"is_member":true},
			{"id":"C0ENGSEC01","name":"eng-secrets","name_normalized":"eng-secrets","is_channel":true,"is_member":true},
			{"id":"C0RANDOM01","name":"random","name_normalized":"random","is_channel":true,"is_member":true}
		],"response_metadata":{"next_cursor":""}}`))
	case "chat.postMessage":
		form := map[string]string{}
		for k := range r.PostForm {
			if k != "token" {
				form[k] = r.PostForm.Get(k)
			}
		}
		s.mu.Lock()
		s.posts = append(s.posts, form)
		n := len(s.posts)
		s.mu.Unlock()
		_, _ = fmt.Fprintf(w, `{"ok":true,"channel":%q,"ts":"17000040%02d.000100"}`, form["channel"], n)
	default:
		_, _ = w.Write([]byte(`{"ok":false,"error":"unknown_method"}`))
	}
}

// --- hostile vendor answers ---------------------------------------------------

// secretCorpus is what a hostile or broken vendor might put in an error
// body: token shapes the redactor must catch and raw material (HTML,
// stack traces) that must never be forwarded verbatim.
var secretCorpus = []struct{ what, value string }{
	{"github token", "ghp_9f8e7d6c5b4a39281716151413121110aaBBcc"},
	{"github user token", "ghu_1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b"},
	{"slack bot token", "xoxb-1234567890-0987654321-AbCdEfGhIjKlMnOpQrStUvWx"},
	{"slack user token", "xoxp-2222222222-3333333333-4444444444-deadbeefcafebabe"},
	{"bearer", "Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhdHRhY2tlciJ9.c2lnbmF0dXJlLXNpZ25hdHVyZQ"},
	{"jwt", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJtY3AifQ.YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo"},
	{"private key", "-----BEGIN PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\n-----END PRIVATE KEY-----"},
	{"google api key", "AIzaSyD-9tSrke72PouQMnMX-a7eZSW0jkFMBxY"},
	{"github pat", "github_pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcd"},
}

// secretSoup joins every corpus value into one vendor message.
func secretSoup() string {
	parts := make([]string, 0, len(secretCorpus))
	for _, c := range secretCorpus {
		parts = append(parts, c.value)
	}
	return strings.Join(parts, " ")
}

// htmlBody is a 5xx HTML page with an internal hostname and a stack
// trace: vendor body that must never reach the client.
const htmlBody = `<!DOCTYPE html><html><head><title>502 Bad Gateway</title></head><body>
<h1>502 Bad Gateway</h1><pre>upstream internal-api-7f3a.vendor.internal:8443 failed
at vendor.Handler.serve (handler.go:217)
secret=ghp_9f8e7d6c5b4a39281716151413121110aaBBcc</pre></body></html>`
