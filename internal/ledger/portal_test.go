package ledger_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/insights"
	"github.com/huynle/mcp-gateway/internal/portal/nav"

	"github.com/huynle/mcp-gateway/internal/ledger"
	"github.com/huynle/mcp-gateway/internal/store"
)

func TestOperationsPageListsTheCallersOperationsWithHints(t *testing.T) {
	f := newFixture(t)
	ok := f.begin(t, f.intent(map[string]any{"id": "it-ok"}))
	if _, err := f.svc.Finish(t.Context(), alice, ok.ID, ledger.Succeeded(map[string]string{"id": "it-ok", "url": "https://app.example.com/i/it-ok"})); err != nil {
		t.Fatal(err)
	}
	failed := f.begin(t, f.intent(map[string]any{"id": "it-failed"}))
	if _, err := f.svc.Finish(t.Context(), alice, failed.ID, ledger.Failed("tool_error")); err != nil {
		t.Fatal(err)
	}
	unresolved := f.begin(t, f.intent(map[string]any{"id": "it-lost"}))
	f.st.SetState(unresolved.ID, store.LedgerUnresolved)
	other := f.intent(map[string]any{"id": "it-bob"})
	other.UserID = bob
	bobs := f.begin(t, other)

	mux := http.NewServeMux()
	who := func(r *http.Request) (string, string) {
		if r.Header.Get("X-User") == "" {
			return "", ""
		}
		return r.Header.Get("X-User"), "csrf-token"
	}
	ledger.NewPortal(f.svc, who, slog.New(slog.DiscardHandler)).Mount(mux.Handle)

	// The portal middleware attaches the shared nav data (sign-out form
	// token, admin flag) to every request; simulate it for a member.
	ctx := nav.WithData(t.Context(), nav.Data{SignedIn: true, CSRFToken: "csrf-token"})
	req := httptest.NewRequestWithContext(ctx, http.MethodGet, "/operations", nil)
	req.Header.Set("X-User", alice)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("status %d %s", rec.Code, rec.Header().Get("Content-Type"))
	}
	body := rec.Body.String()
	for _, want := range []string{
		"<title>Operations", "fake.create_item", ok.ID[:8], failed.ID[:8], unresolved.ID[:8],
		"succeeded", "failed", "unresolved", "it-ok", "https://app.example.com/i/it-ok", "verify in the app", "csrf-token",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(body, "/admin/") {
		t.Error("member page shows admin links")
	}
	if strings.Contains(body, bobs.ID[:8]) || strings.Contains(body, "it-bob") {
		t.Error("page shows another user's operation")
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("Cache-Control = %q", rec.Header().Get("Cache-Control"))
	}

	// Anonymous: refused.
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/operations", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("anonymous status = %d", rec.Code)
	}
}

// With insights the page charts the caller's writes above the list (the
// loader gets the caller and the range); a bad range is a 400.
func TestOperationsPageChartsWithInsights(t *testing.T) {
	f := newFixture(t)
	var gotUser, gotRange string
	load := func(_ context.Context, user string, r insights.Range, u *url.URL) (*insights.Dashboard, error) {
		gotUser, gotRange = user, r.Key
		return &insights.Dashboard{Title: "Insights", Range: r, RangeLinks: insights.RangeLinksFor(u, r),
			Stats:  []insights.Stat{{Label: "Writes", Value: "42"}},
			Groups: []insights.Group{{Title: "Writes", Charts: []insights.Chart{{ID: "writes", Title: "Writes over time", Kind: insights.KindStacked}}}}}, nil
	}
	mux := http.NewServeMux()
	who := func(*http.Request) (string, string) { return alice, "csrf-token" }
	ledger.NewPortal(f.svc, who, slog.New(slog.DiscardHandler)).WithInsights(load).Mount(mux.Handle)

	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/operations?range=30d", nil))
	body := rec.Body.String()
	if rec.Code != http.StatusOK || gotUser != alice || gotRange != "30d" {
		t.Fatalf("GET = %d, loader user %q range %q", rec.Code, gotUser, gotRange)
	}
	for _, want := range []string{`<canvas id="chart-writes"`, "data-insights", "Latest writes", "42"} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/operations?range=forever", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("bad range = %d, want 400", rec.Code)
	}
}
