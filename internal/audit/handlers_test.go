package audit_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/audit"
	"github.com/huynle/mcp-gateway/internal/insights"
)

const (
	alice = "0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"
	bob   = "1b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d"
)

type fakeReader struct {
	listUser   string
	listFilter audit.Filter
	listPage   audit.Page
	listCalls  int

	adminFilter audit.Filter
	adminPage   audit.Page
	adminCalls  int

	rows []audit.Record
	err  error
}

func (f *fakeReader) ListForUser(_ context.Context, userID string, fl audit.Filter, p audit.Page) ([]audit.Record, error) {
	f.listCalls++
	f.listUser, f.listFilter, f.listPage = userID, fl, p
	return f.rows, f.err
}

func (f *fakeReader) AdminSearch(_ context.Context, fl audit.Filter, p audit.Page) ([]audit.Record, error) {
	f.adminCalls++
	f.adminFilter, f.adminPage = fl, p
	return f.rows, f.err
}

func sampleRows() []audit.Record {
	t0 := time.Date(2026, 10, 8, 9, 30, 0, 0, time.UTC)
	return []audit.Record{
		{ID: "r1", EventType: audit.EventTypeToolCall, Event: audit.Event{
			Time: t0, UserID: alice, TokenID: "tok-1", Tool: "github.create_issue", AccountLabel: "company",
			ResourceIdentity: map[string]string{"repo": "acme/api", "title": "<script>alert(1)</script>"},
			Decision:         "allow", Outcome: "succeeded", Latency: 250 * time.Millisecond, RequestID: "req-alice-0001",
		}},
		{ID: "r2", EventType: audit.EventTypeToolCall, Event: audit.Event{
			Time: t0.Add(time.Minute), UserID: bob, Tool: "slack.post_message", AccountLabel: "personal",
			Decision: "deny", Outcome: "denied", ErrorClass: "policy_denied", RequestID: "req-bob-00001",
		}},
	}
}

func identity(user string, admin bool) audit.Identity {
	return func(*http.Request) (string, bool) { return user, admin }
}

func get(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, target, nil))
	return rec
}

// --- ActivityHandler --------------------------------------------------------

func TestActivityRequiresSignIn(t *testing.T) {
	f := &fakeReader{}
	rec := get(t, audit.ActivityHandler(f, identity("", false)), "/activity")
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", rec.Code)
	}
	if f.listCalls != 0 || f.adminCalls != 0 {
		t.Error("reader called without a signed-in user")
	}
}

func TestActivityListsOnlyTheSessionUser(t *testing.T) {
	f := &fakeReader{rows: sampleRows()[:1]}
	// Even an admin's own activity page is their own rows, and a user_id
	// query parameter must not widen the view.
	rec := get(t, audit.ActivityHandler(f, identity(alice, true)), "/activity?user_id="+bob+"&tool=github.create_issue&decision=allow&outcome=succeeded&page=3")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if f.adminCalls != 0 {
		t.Error("activity page used AdminSearch")
	}
	if f.listCalls != 1 || f.listUser != alice {
		t.Errorf("ListForUser called %d times for %q, want once for alice", f.listCalls, f.listUser)
	}
	if f.listFilter.UserID != "" {
		t.Errorf("user_id query leaked into the filter: %q", f.listFilter.UserID)
	}
	if f.listFilter.Tool != "github.create_issue" || f.listFilter.Decision != "allow" || f.listFilter.Outcome != "succeeded" {
		t.Errorf("filter = %+v", f.listFilter)
	}
	if f.listPage.Limit != audit.DefaultPageSize || f.listPage.Offset != 2*audit.DefaultPageSize {
		t.Errorf("page = %+v, want limit %d offset %d", f.listPage, audit.DefaultPageSize, 2*audit.DefaultPageSize)
	}
}

func TestActivityRendersMetadataEscaped(t *testing.T) {
	f := &fakeReader{rows: sampleRows()}
	rec := get(t, audit.ActivityHandler(f, identity(alice, false)), "/activity")
	body := rec.Body.String()
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type = %q", ct)
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("cache-control = %q, want no-store", cc)
	}
	for _, want := range []string{"github.create_issue", "allow", "succeeded", "company", "repo", "acme/api", "250ms", "req-alice-0001", "policy_denied", "2026-10-08"} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Error("resource identity value rendered unescaped")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("expected HTML-escaped resource value")
	}
}

func TestActivityHidesReaderErrors(t *testing.T) {
	f := &fakeReader{err: errors.New("pg: connect postgres://gateway:mgw_dbpassword@db/gateway failed")}
	rec := get(t, audit.ActivityHandler(f, identity(alice, false)), "/activity")
	if rec.Code != http.StatusInternalServerError {
		t.Errorf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "mgw_dbpassword") || strings.Contains(rec.Body.String(), "postgres://") {
		t.Errorf("error text leaked to the client: %s", rec.Body.String())
	}
}

func TestActivityRejectsBadInput(t *testing.T) {
	f := &fakeReader{}
	h := audit.ActivityHandler(f, identity(alice, false))
	for _, q := range []string{"?page=abc", "?page=-1", "?since=yesterday", "?until=2026-13-45"} {
		if rec := get(t, h, "/activity"+q); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", q, rec.Code)
		}
	}
	if f.listCalls != 0 {
		t.Error("reader called with invalid input")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/activity", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST status = %d, want 405", rec.Code)
	}
}

func TestActivityParsesDateFilters(t *testing.T) {
	f := &fakeReader{}
	get(t, audit.ActivityHandler(f, identity(alice, false)), "/activity?since=2026-10-01&until=2026-10-08T12:00:00Z")
	if f.listFilter.Since != time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC) {
		t.Errorf("since = %v", f.listFilter.Since)
	}
	if f.listFilter.Until != time.Date(2026, 10, 8, 12, 0, 0, 0, time.UTC) {
		t.Errorf("until = %v", f.listFilter.Until)
	}
}

func TestActivityPagingLinks(t *testing.T) {
	rows := make([]audit.Record, audit.DefaultPageSize)
	for i := range rows {
		rows[i] = sampleRows()[0]
	}
	f := &fakeReader{rows: rows}
	body := get(t, audit.ActivityHandler(f, identity(alice, false)), "/activity?page=2&tool=x").Body.String()
	if !strings.Contains(body, "page=3") || !strings.Contains(body, "page=1") {
		t.Errorf("expected next (page=3) and previous (page=1) links in:\n%s", body)
	}
	if !strings.Contains(body, "tool=x") {
		t.Error("paging links drop the active filter")
	}
	f.rows = rows[:3]
	body = get(t, audit.ActivityHandler(f, identity(alice, false)), "/activity").Body.String()
	if strings.Contains(body, "page=2") {
		t.Error("next link shown on a short (last) page")
	}
	if strings.Contains(body, "page=0") {
		t.Error("previous link shown on the first page")
	}
}

func TestActivityEmptyState(t *testing.T) {
	f := &fakeReader{}
	body := get(t, audit.ActivityHandler(f, identity(alice, false)), "/activity").Body.String()
	if !strings.Contains(strings.ToLower(body), "no activity") {
		t.Errorf("expected an empty-state message:\n%s", body)
	}
}

// --- AdminSearchHandler -----------------------------------------------------

func TestAdminSearchRequiresAdmin(t *testing.T) {
	f := &fakeReader{rows: sampleRows()}
	h := audit.AdminSearchHandler(f, identity("", false))
	if rec := get(t, h, "/admin/audit"); rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous: status = %d, want 401", rec.Code)
	}
	h = audit.AdminSearchHandler(f, identity(alice, false))
	if rec := get(t, h, "/admin/audit"); rec.Code != http.StatusForbidden {
		t.Errorf("non-admin: status = %d, want 403", rec.Code)
	}
	if f.adminCalls != 0 || f.listCalls != 0 {
		t.Error("reader called for a non-admin")
	}
}

func TestAdminSearchShowsAllUsersAndFilters(t *testing.T) {
	f := &fakeReader{rows: sampleRows()}
	rec := get(t, audit.AdminSearchHandler(f, identity(alice, true)), "/admin/audit?user_id="+bob+"&tool=slack.post_message&page=2")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d: %s", rec.Code, rec.Body.String())
	}
	if f.adminCalls != 1 || f.listCalls != 0 {
		t.Errorf("admin=%d list=%d calls", f.adminCalls, f.listCalls)
	}
	if f.adminFilter.UserID != bob || f.adminFilter.Tool != "slack.post_message" {
		t.Errorf("filter = %+v", f.adminFilter)
	}
	if f.adminPage.Offset != audit.DefaultPageSize {
		t.Errorf("page = %+v", f.adminPage)
	}
	body := rec.Body.String()
	for _, want := range []string{alice, bob, "github.create_issue", "slack.post_message", "req-bob-00001", "policy_denied", "tok-1"} {
		if !strings.Contains(body, want) {
			t.Errorf("admin page missing %q", want)
		}
	}
	if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Errorf("cache-control = %q", cc)
	}
}

func TestAdminSearchRejectsBadUserID(t *testing.T) {
	f := &fakeReader{}
	rec := get(t, audit.AdminSearchHandler(f, identity(alice, true)), "/admin/audit?user_id=%27+OR+1=1")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
	if f.adminCalls != 0 {
		t.Error("reader called with a malformed user id")
	}
}

// With insights, /activity charts the session user's own calls above the
// table (the loader gets the session user whatever the query says), keeps
// the range in the filter form, and rejects a bad range.
func TestActivityChartsWithInsights(t *testing.T) {
	f := &fakeReader{rows: sampleRows()}
	var gotUser, gotRange string
	load := func(_ context.Context, user string, r insights.Range, u *url.URL) (*insights.Dashboard, error) {
		gotUser, gotRange = user, r.Key
		return &insights.Dashboard{Title: "Insights", Range: r, RangeLinks: insights.RangeLinksFor(u, r),
			Stats:  []insights.Stat{{Label: "Tool calls", Value: "7"}},
			Groups: []insights.Group{{Title: "Calls", Charts: []insights.Chart{{ID: "calls", Title: "Calls over time", Kind: insights.KindStacked}}}}}, nil
	}
	h := audit.ActivityHandler(f, identity(alice, false), audit.WithInsights(load))
	rec := get(t, h, "/activity?range=24h&user_id="+bob)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || gotUser != alice || gotRange != "24h" {
		t.Fatalf("GET = %d, loader user %q range %q", rec.Code, gotUser, gotRange)
	}
	for _, want := range []string{`<canvas id="chart-calls"`, "data-insights", `<input type="hidden" name="range" value="24h">`} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if rec := get(t, h, "/activity?range=1y"); rec.Code != http.StatusBadRequest {
		t.Errorf("bad range = %d, want 400", rec.Code)
	}
	// Without insights the page has no charts.
	if body := get(t, audit.ActivityHandler(f, identity(alice, false)), "/activity").Body.String(); strings.Contains(body, "data-insights") {
		t.Error("charts rendered without insights")
	}
}
