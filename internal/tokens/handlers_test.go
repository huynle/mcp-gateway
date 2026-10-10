package tokens_test

import (
	"html"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/tokens"
	"github.com/huynle/mcp-gateway/internal/tokens/tokenstest"
)

const csrf = "csrf-token-value"

// pagesFixture mounts the token pages on a plain mux through the same
// Mount callback the portal supplies; who returns the configured user.
type pagesFixture struct {
	st   *tokenstest.MemStore
	svc  *tokens.Service
	mux  *http.ServeMux
	user string
}

func newPages(t *testing.T) *pagesFixture {
	t.Helper()
	f := &pagesFixture{st: tokenstest.NewMemStore(), mux: http.NewServeMux(), user: alice}
	svc, err := tokens.New(tokens.Config{SignInMaxAge: tokens.DefaultSignInMaxAge}, f.st, nil, nil, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	f.svc = svc
	signedIn := time.Now().Add(-time.Hour)
	f.st.AddUser(alice, &signedIn)
	f.st.AddUser(bob, &signedIn)
	who := func(*http.Request) (string, string) {
		if f.user == "" {
			return "", ""
		}
		return f.user, csrf
	}
	pages := tokens.NewPortal(svc, who, "https://gw.example.com/", slog.New(slog.DiscardHandler))
	pages.Mount(f.mux.Handle)
	return f
}

func (f *pagesFixture) get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

func (f *pagesFixture) post(t *testing.T, path string, form url.Values) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

var tokenRE = regexp.MustCompile(tokens.ScanPattern)

func TestTokenPagesRequireAUser(t *testing.T) {
	f := newPages(t)
	f.user = ""
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/tokens"}, {http.MethodGet, "/tokens/new"}, {http.MethodPost, "/tokens/new"}, {http.MethodPost, "/tokens/x/revoke"},
	} {
		var rec *httptest.ResponseRecorder
		if c.method == http.MethodGet {
			rec = f.get(t, c.path)
		} else {
			rec = f.post(t, c.path, url.Values{"name": {"x"}})
		}
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s anonymous = %d, want 401", c.method, c.path, rec.Code)
		}
	}
}

func TestTokenListAndNewForm(t *testing.T) {
	f := newPages(t)
	rec := f.get(t, "/tokens")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /tokens = %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "No tokens yet") || !strings.Contains(body, `href="/tokens/new"`) {
		t.Errorf("empty list page:\n%s", body)
	}
	rec = f.get(t, "/tokens/new")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /tokens/new = %d", rec.Code)
	}
	body = rec.Body.String()
	for _, want := range []string{`name="name"`, `name="expiry_days"`, `value="30"`, `max="90"`, `name="read_only"`, `name="allow_list"`, `name="_csrf" value="` + csrf + `"`} {
		if !strings.Contains(body, want) {
			t.Errorf("new form lacks %s:\n%s", want, body)
		}
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q", cc)
	}
}

func TestCreateShowsTheTokenOnceAndTheListOnlyThePrefix(t *testing.T) {
	f := newPages(t)
	rec := f.post(t, "/tokens/new", url.Values{"name": {"laptop"}, "expiry_days": {"7"}, "read_only": {"on"}, "allow_list": {"github, slack.post_message"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("POST /tokens/new = %d:\n%s", rec.Code, rec.Body)
	}
	body := html.UnescapeString(rec.Body.String())
	raws := tokenRE.FindAllString(body, -1)
	if len(raws) == 0 {
		t.Fatalf("created page shows no token:\n%s", body)
	}
	raw := raws[0]
	for _, r := range raws {
		if r != raw {
			t.Fatalf("created page shows two different tokens: %s %s", raw, r)
		}
	}
	// One token, shown in the code block and in both harness snippets.
	for _, want := range []string{
		`https://gw.example.com/mcp`,
		`"Authorization": "Bearer ` + raw + `"`,
		`"mcpServers"`, // Claude Code
		`"mcp"`,        // OpenCode
		`opencode.json`, `.mcp.json`,
		"laptop", "read-only", "github, slack.post_message",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("created page lacks %q", want)
		}
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q, the one-time page must not be cached", cc)
	}
	// It authenticates and carries the requested scope.
	p, err := f.svc.Authenticate(t.Context(), raw)
	if err != nil {
		t.Fatalf("created token rejected: %v", err)
	}
	if p.UserID != alice || !p.Scope.ReadOnly || !p.Scope.Allows("github.x") || p.Scope.Allows("jira.x") {
		t.Errorf("principal = %+v", p)
	}
	if exp := f.st.Token(p.TokenID).ExpiresAt; time.Until(exp) > 7*24*time.Hour || time.Until(exp) < 6*24*time.Hour {
		t.Errorf("expiry = %v, want ~7 days", exp)
	}

	// The list shows the prefix and never the secret.
	rec = f.get(t, "/tokens")
	body = rec.Body.String()
	_, secret, _ := tokens.Parse(raw)
	if strings.Contains(body, secret) || tokenRE.MatchString(body) {
		t.Fatalf("list page leaks the token:\n%s", body)
	}
	if !strings.Contains(body, "mgw_"+p.PublicID) || !strings.Contains(body, "laptop") || !strings.Contains(body, "github, slack.post_message, read-only") {
		t.Errorf("list page lacks the prefix/name/scope:\n%s", body)
	}
	if !strings.Contains(body, `action="/tokens/`+p.TokenID+`/revoke"`) || !strings.Contains(body, `name="_csrf" value="`+csrf+`"`) {
		t.Errorf("list page lacks a CSRF-protected revoke form:\n%s", body)
	}
}

func TestCreateValidationErrorsRerenderTheForm(t *testing.T) {
	f := newPages(t)
	cases := []url.Values{
		{"name": {""}},
		{"name": {"x"}, "expiry_days": {"91"}},
		{"name": {"x"}, "expiry_days": {"abc"}},
		{"name": {"x"}, "allow_list": {"git/hub"}},
	}
	for _, form := range cases {
		rec := f.post(t, "/tokens/new", form)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("POST %v = %d, want 400", form, rec.Code)
		}
		body := rec.Body.String()
		if !strings.Contains(body, `name="name"`) || !strings.Contains(body, `class="error"`) {
			t.Errorf("POST %v did not re-render the form with an error:\n%s", form, body)
		}
		if tokenRE.MatchString(body) {
			t.Errorf("POST %v shows a token on failure", form)
		}
	}
	list, _ := f.svc.List(t.Context(), alice)
	if len(list) != 0 {
		t.Errorf("invalid requests created tokens: %+v", list)
	}
}

func TestRevokeFromThePortal(t *testing.T) {
	f := newPages(t)
	c, err := f.svc.Create(t.Context(), alice, tokens.CreateRequest{Name: "laptop"})
	if err != nil {
		t.Fatal(err)
	}
	// Bob cannot revoke Alice's token: 404.
	f.user = bob
	if rec := f.post(t, "/tokens/"+c.Token.ID+"/revoke", nil); rec.Code != http.StatusNotFound {
		t.Errorf("bob revoking alice's token = %d, want 404", rec.Code)
	}
	if _, err := f.svc.Authenticate(t.Context(), c.Raw); err != nil {
		t.Fatalf("token revoked by another user: %v", err)
	}
	f.user = alice
	rec := f.post(t, "/tokens/"+c.Token.ID+"/revoke", nil)
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/tokens") {
		t.Errorf("revoke = %d %q, want 303 to /tokens", rec.Code, rec.Header().Get("Location"))
	}
	if _, err := f.svc.Authenticate(t.Context(), c.Raw); err == nil {
		t.Error("token still authenticates after portal revoke")
	}
	body := f.get(t, "/tokens").Body.String()
	if !strings.Contains(body, "revoked") {
		t.Errorf("list does not show the token as revoked:\n%s", body)
	}
	if strings.Contains(body, `action="/tokens/`+c.Token.ID+`/revoke"`) {
		t.Error("list still offers to revoke a revoked token")
	}
	// Unknown id: 404.
	if rec := f.post(t, "/tokens/nope/revoke", nil); rec.Code != http.StatusNotFound {
		t.Errorf("revoke unknown = %d, want 404", rec.Code)
	}
}

func TestHarnessSnippetUsesBaseURL(t *testing.T) {
	snippet := tokens.HarnessSnippets("https://gw.example.com/", "mgw_a_b")
	if snippet.MCPURL != "https://gw.example.com/mcp" {
		t.Errorf("MCPURL = %q", snippet.MCPURL)
	}
	for name, s := range map[string]string{"opencode": snippet.OpenCode, "claude": snippet.ClaudeCode, "claude cli": snippet.ClaudeCodeCLI, "curl": snippet.Curl} {
		if !strings.Contains(s, "https://gw.example.com/mcp") || !strings.Contains(s, "mgw_a_b") {
			t.Errorf("%s snippet = %q", name, s)
		}
	}
	// Must be whole documents a user can paste.
	if !strings.HasPrefix(strings.TrimSpace(snippet.OpenCode), "{") || !strings.HasPrefix(strings.TrimSpace(snippet.ClaudeCode), "{") {
		t.Error("JSON snippets are not whole documents")
	}
}
