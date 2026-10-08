package approvals_test

import (
	"html"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/approvals"
)

const csrf = "csrf-token-value"

// pagesFixture mounts the approval pages on a plain mux through the same
// Mount callback the portal supplies; who returns the configured user.
type pagesFixture struct {
	*fixture
	mux  *http.ServeMux
	user string
}

func newPages(t *testing.T) *pagesFixture {
	t.Helper()
	f := &pagesFixture{fixture: newFixture(t), mux: http.NewServeMux(), user: alice}
	f.st.Accounts[acctA] = [2]string{"company", "Alice at work"}
	who := func(*http.Request) (string, string) {
		if f.user == "" {
			return "", ""
		}
		return f.user, csrf
	}
	approvals.NewPortal(f.svc, who, slog.New(slog.DiscardHandler)).Mount(f.mux.Handle)
	return f
}

func (f *pagesFixture) get(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

func (f *pagesFixture) post(t *testing.T, path string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, path, strings.NewReader(url.Values{"_csrf": {csrf}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	return rec
}

func TestApprovalPagesRequireAUser(t *testing.T) {
	f := newPages(t)
	f.user = ""
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/approvals"}, {http.MethodGet, "/approvals/history"},
		{http.MethodPost, "/approvals/x/approve"}, {http.MethodPost, "/approvals/x/deny"},
	} {
		var rec *httptest.ResponseRecorder
		if c.method == http.MethodGet {
			rec = f.get(t, c.path)
		} else {
			rec = f.post(t, c.path)
		}
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s %s anonymous = %d, want 401", c.method, c.path, rec.Code)
		}
	}
}

func TestPendingPageShowsSummaryAndPolls(t *testing.T) {
	f := newPages(t)
	rec := f.get(t, "/approvals")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "No approvals waiting") {
		t.Fatalf("empty page = %d:\n%s", rec.Code, rec.Body)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("Cache-Control = %q", cc)
	}
	a := f.create(t, map[string]any{"id": "it-1", "name": strings.Repeat("n", 250), "body": "line <one>", "labels": []any{"x", "y"}})
	f.advance(30 * time.Second)
	rec = f.get(t, "/approvals")
	body := rec.Body.String()
	for _, want := range []string{
		"fake.create_item", "Alice at work", "company", "it-1", // tool, account, resource identity
		`action="/approvals/` + a.ID + `/approve"`, `action="/approvals/` + a.ID + `/deny"`,
		`name="_csrf" value="` + csrf + `"`,
		`hx-get="/approvals"`, `hx-trigger="every 5s"`, `id="pending"`,
		"line &lt;one&gt;", // escaped
		`["x","y"]`, "Expires in 14m 30s",
	} {
		if !strings.Contains(html.UnescapeString(body), html.UnescapeString(want)) && !strings.Contains(body, want) {
			t.Errorf("page lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, strings.Repeat("n", 250)) {
		t.Error("long value not truncated")
	}
	if !strings.Contains(body, "…") {
		t.Error("truncation marker missing")
	}
	// Bob sees nothing of alice's.
	f.user = bob
	if rec := f.get(t, "/approvals"); strings.Contains(rec.Body.String(), a.ID) {
		t.Error("bob sees alice's approval")
	}
}

func TestApproveAndDenyThroughThePages(t *testing.T) {
	f := newPages(t)
	a := f.create(t, sampleArgs)
	b := f.create(t, sampleArgs)
	rec := f.post(t, "/approvals/"+a.ID+"/approve")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/approvals?decided=approved" {
		t.Errorf("approve = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if got := f.st.Record(a.ID); got.Status != approvals.StatusApproved || got.Payload == nil {
		t.Errorf("after approve: %+v", got)
	}
	rec = f.post(t, "/approvals/"+b.ID+"/deny")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/approvals?decided=denied" {
		t.Errorf("deny = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if got := f.st.Record(b.ID); got.Status != approvals.StatusDenied || got.Payload != nil {
		t.Errorf("after deny: %+v", got)
	}
	// Deciding twice: not an error page, back to the list with a notice.
	rec = f.post(t, "/approvals/"+a.ID+"/approve")
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/approvals?decided=already" {
		t.Errorf("second approve = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	// The notice renders.
	if rec := f.get(t, "/approvals?decided=approved"); !strings.Contains(rec.Body.String(), "Approved") {
		t.Errorf("notice missing:\n%s", rec.Body)
	}
	// Someone else's approval, or an unknown one: 404.
	c := f.create(t, sampleArgs)
	f.user = bob
	for _, path := range []string{"/approvals/" + c.ID + "/approve", "/approvals/" + c.ID + "/deny", "/approvals/not-a-uuid/approve"} {
		if rec := f.post(t, path); rec.Code != http.StatusNotFound {
			t.Errorf("POST %s as bob = %d, want 404", path, rec.Code)
		}
	}
	if f.st.Record(c.ID).Status != approvals.StatusPending {
		t.Error("bob changed alice's approval")
	}
	// htmx requests get the refreshed pending fragment instead of a redirect.
	f.user = alice
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/approvals/"+c.ID+"/approve", strings.NewReader(url.Values{"_csrf": {csrf}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	rec = httptest.NewRecorder()
	f.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `id="pending"`) || strings.Contains(rec.Body.String(), "<html") {
		t.Errorf("htmx approve = %d:\n%s", rec.Code, rec.Body)
	}
}

func TestHistoryPageListsDecisionsWithoutArguments(t *testing.T) {
	f := newPages(t)
	a := f.create(t, sampleArgs)
	f.advance(time.Second)
	b := f.create(t, sampleArgs)
	if _, err := f.svc.Deny(t.Context(), alice, b.ID); err != nil {
		t.Fatal(err)
	}
	rec := f.get(t, "/approvals/history")
	if rec.Code != http.StatusOK {
		t.Fatalf("history = %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{a.ID[:8], b.ID[:8], "pending", "denied", "fake.create_item", "Alice at work"} {
		if !strings.Contains(body, want) {
			t.Errorf("history lacks %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "SECRET BODY") || strings.Contains(body, "first") {
		t.Error("history shows argument content")
	}
	if strings.Index(body, b.ID[:8]) > strings.Index(body, a.ID[:8]) {
		t.Error("history is not newest first")
	}
}
