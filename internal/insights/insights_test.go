package insights

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/portal/nav/navtest"
	"github.com/huynle/mcp-gateway/internal/store"
)

func TestParseRange(t *testing.T) {
	if r, err := ParseRange(""); err != nil || r.Key != DefaultRange.Key {
		t.Errorf(`ParseRange("") = %v, %v; want the default`, r.Key, err)
	}
	for _, k := range []string{"24h", "7d", "30d"} {
		if r, err := ParseRange(k); err != nil || r.Key != k {
			t.Errorf("ParseRange(%q) = %v, %v", k, r.Key, err)
		}
	}
	for _, k := range []string{"1y", "7D", "<script>"} {
		if _, err := ParseRange(k); err == nil {
			t.Errorf("ParseRange(%q) accepted", k)
		}
	}
}

func TestRangeLinksKeepFiltersAndResetPage(t *testing.T) {
	u, _ := url.Parse("/activity?tool=github.get_issue&page=3&range=24h")
	links := RangeLinksFor(u, Ranges[0])
	if len(links) != len(Ranges) || !links[0].Current || links[1].Current {
		t.Fatalf("links = %+v", links)
	}
	if got := links[2].Href; got != "/activity?range=30d&tool=github.get_issue" {
		t.Errorf("30d link = %q", got)
	}
	if got := DrillHref("/activity", u, RangeParam); got != "/activity?range=24h" {
		t.Errorf("DrillHref = %q, want only the range kept", got)
	}
}

// The window starts on a bucket boundary in UTC (so the Go timeline and
// the database's date_bin buckets coincide) and the timeline covers it.
func TestWindowAndTimelineAlign(t *testing.T) {
	now := time.Date(2026, 10, 29, 13, 47, 12, 0, time.FixedZone("x", -7*3600))
	s := &Source{now: func() time.Time { return now }}
	for _, r := range Ranges {
		w := s.window(r)
		if !w.Since.Equal(w.Since.Truncate(r.Bucket)) || w.Since.Location() != time.UTC {
			t.Errorf("%s: since %v not aligned to %v in UTC", r.Key, w.Since, r.Bucket)
		}
		if got := now.Sub(w.Since); got < r.Span || got >= r.Span+r.Bucket {
			t.Errorf("%s: window spans %v, want [%v, %v)", r.Key, got, r.Span, r.Span+r.Bucket)
		}
		ts := timeline(w)
		if !ts[0].Equal(w.Since) || !ts[len(ts)-1].Before(w.Until) || ts[len(ts)-1].Add(r.Bucket).Before(w.Until) {
			t.Errorf("%s: timeline %v..%v does not cover the window", r.Key, ts[0], ts[len(ts)-1])
		}
	}
	if d := s.window(Ranges[2]).Since; d.Hour() != 0 || d.Minute() != 0 {
		t.Errorf("30d window starts at %v, want UTC midnight", d)
	}
}

func TestStackedOrdersKnownSeriesAndFillsZeros(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	times := []time.Time{t0, t0.Add(time.Hour), t0.Add(2 * time.Hour)}
	rows := []store.InsightsBucketCount{
		{Bucket: t0, Key: "failed", Count: 1},
		{Bucket: t0, Key: "succeeded", Count: 5},
		{Bucket: t0.Add(2 * time.Hour), Key: "succeeded", Count: 2},
		{Bucket: t0.Add(time.Hour), Key: "weird", Count: 3},
		{Bucket: t0.Add(time.Hour), Key: "none", Count: 4},
		{Bucket: t0.Add(9 * time.Hour), Key: "succeeded", Count: 99}, // outside the timeline
	}
	got := stacked(rows, times, outcomeTones)
	var names []string
	for _, s := range got {
		names = append(names, s.Name)
	}
	if strings.Join(names, ",") != "succeeded,failed,no outcome,weird" {
		t.Fatalf("series = %v", names)
	}
	if d := got[0].Data; d[0] != 5 || d[1] != 0 || d[2] != 2 {
		t.Errorf("succeeded = %v", d)
	}
	if got[2].Key != "" {
		t.Errorf(`"none" series key = %q, want "" (no drill filter)`, got[2].Key)
	}
	if got[3].Tone != "muted" {
		t.Errorf("unknown key tone = %q, want muted", got[3].Tone)
	}
}

// Buckets without latency are gaps (null), not zeros.
func TestPercentileGapsEncodeAsNull(t *testing.T) {
	t0 := time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC)
	times := []time.Time{t0, t0.Add(time.Hour)}
	s := percentiles([]store.InsightsPercentiles{{Bucket: t0.Add(time.Hour), N: 2, P50: 12.345, P95: 40, P99: 41}}, times)
	b, err := json.Marshal(s[0].Data)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != "[null,12.35]" {
		t.Errorf("p50 = %s, want [null,12.35]", b)
	}
	if b, _ := json.Marshal(Num(math.Inf(1))); string(b) != "null" {
		t.Errorf("Inf = %s", b)
	}
}

func TestMatrixChartIndexesRowsAndColumns(t *testing.T) {
	if matrixChart(nil, "/admin/audit?") != nil {
		t.Error("empty matrix should be nil")
	}
	m := matrixChart([]store.InsightsUserToolCount{
		{UserID: "u1", DisplayName: "Alice", Tool: "a", Count: 5},
		{UserID: "u2", DisplayName: "", Tool: "a", Count: 3},
		{UserID: "u1", DisplayName: "Alice", Tool: "b", Count: 1},
	}, "/admin/audit?")
	if strings.Join(m.Labels, ",") != "Alice,user u2" || strings.Join(m.Keys, ",") != "u1,u2" || strings.Join(m.XLabels, ",") != "a,b" {
		t.Errorf("matrix labels = %v keys = %v columns = %v", m.Labels, m.Keys, m.XLabels)
	}
	if len(m.Points) != 3 || m.Points[2] != (Point{X: 1, Y: 0, V: 1}) {
		t.Errorf("points = %+v", m.Points)
	}
}

func TestFormatting(t *testing.T) {
	for in, want := range map[int64]string{0: "0", 999: "999", 1000: "1,000", 1234567: "1,234,567", -4200: "-4,200"} {
		if got := fmtCount(in); got != want {
			t.Errorf("fmtCount(%d) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[float64]string{0: "–", 12.4: "12 ms", 1500: "1.5 s", 90000: "1.5 min"} {
		if got := fmtMS(in); got != want {
			t.Errorf("fmtMS(%v) = %q, want %q", in, got, want)
		}
	}
	if fmtPct(1, 0) != "–" || fmtPct(3, 3) != "100%" || fmtPct(1, 3) != "33.3%" {
		t.Errorf("fmtPct = %q %q %q", fmtPct(1, 0), fmtPct(3, 3), fmtPct(1, 3))
	}
}

// --- AdminHandler ---------------------------------------------------------------

func who(id string, admin bool) Identity {
	return func(*http.Request) (string, bool) { return id, admin }
}

func sampleDashboard(r Range, u *url.URL) *Dashboard {
	return &Dashboard{Title: "Insights", Range: r, RangeLinks: RangeLinksFor(u, r),
		Stats: []Stat{{Label: "Tool calls", Value: "1,234"}, {Label: "Failed", Value: "7", Tone: "danger"}},
		Groups: []Group{{Title: "Users", Charts: []Chart{{ID: "users", Title: "Top users", Kind: KindHBar,
			Labels: []string{"</script><script>alert(1)</script>"}, Keys: []string{"u1"},
			Series: []Series{{Key: "calls", Name: "calls", Tone: "ok", Data: []Num{3}}},
			Drill:  &Drill{Href: "/admin/audit?", Param: "user_id"}}}}},
		Users: []UserRow{{UserID: "u1", Name: "Alice", Calls: 3, Href: "/admin/audit?user_id=u1", LastSeen: time.Unix(0, 0)}}}
}

func serve(h http.Handler, method, target string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequestWithContext(context.Background(), method, target, nil))
	return rec
}

func TestAdminHandlerGuards(t *testing.T) {
	called := false
	load := func(context.Context, Range, *url.URL) (*Dashboard, error) { called = true; return &Dashboard{}, nil }
	for _, c := range []struct {
		name, method, target string
		who                  Identity
		want                 int
	}{
		{"anonymous", http.MethodGet, "/admin/insights", who("", false), http.StatusUnauthorized},
		{"member", http.MethodGet, "/admin/insights", who("u1", false), http.StatusForbidden},
		{"post", http.MethodPost, "/admin/insights", who("u1", true), http.StatusMethodNotAllowed},
		{"bad range", http.MethodGet, "/admin/insights?range=1y", who("u1", true), http.StatusBadRequest},
	} {
		if rec := serve(AdminHandler(load, c.who, nil), c.method, c.target); rec.Code != c.want {
			t.Errorf("%s: %d, want %d", c.name, rec.Code, c.want)
		}
	}
	if called {
		t.Error("the loader ran for a refused request")
	}
}

func TestAdminHandlerRendersChartsAndUsers(t *testing.T) {
	var gotRange Range
	load := func(_ context.Context, r Range, u *url.URL) (*Dashboard, error) { gotRange = r; return sampleDashboard(r, u), nil }
	rec := serve(AdminHandler(load, who("u1", true), nil), http.MethodGet, "/admin/insights?range=30d")
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("GET = %d (Cache-Control %q)", rec.Code, rec.Header().Get("Cache-Control"))
	}
	if gotRange.Key != "30d" {
		t.Errorf("loader got range %q, want 30d", gotRange.Key)
	}
	body := rec.Body.String()
	navtest.AssertShell(t, "/admin/insights", body)
	for _, want := range []string{
		`<canvas id="chart-users"`, `data-insights`, `/static/chart.umd.min.js?v=`, `/static/charts.js?v=`,
		`stat-danger`, `1,234`, `href="/admin/audit?user_id=u1"`, `aria-current="true">30 days`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	// The label is attacker-influenced (a display name): inside the JSON
	// block it must not be able to close the script element.
	if strings.Contains(body, "</script><script>alert(1)") {
		t.Error("chart data was not escaped inside the JSON block")
	}
	_, block, _ := strings.Cut(body, "data-insights>")
	block, _, _ = strings.Cut(block, "</script>")
	var charts []Chart
	if err := json.Unmarshal([]byte(block), &charts); err != nil {
		t.Fatalf("data block is not JSON: %v\n%s", err, block)
	}
	if len(charts) != 1 || charts[0].Labels[0] != "</script><script>alert(1)</script>" || charts[0].Drill.Param != "user_id" {
		t.Errorf("decoded charts = %+v", charts)
	}
}

func TestAdminHandlerShowsNoticeWhenLoadingFails(t *testing.T) {
	load := func(context.Context, Range, *url.URL) (*Dashboard, error) {
		return nil, errors.New("pq: connection to postgres://user:secret@db failed")
	}
	rec := serve(AdminHandler(load, who("u1", true), nil), http.MethodGet, "/admin/insights")
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "could not be loaded") {
		t.Errorf("failed load = %d, want 200 with a notice", rec.Code)
	}
	if strings.Contains(body, "secret") || strings.Contains(body, "data-insights") {
		t.Error("failure page leaks the error or still renders charts")
	}
}

func TestForUser(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/activity?range=24h", nil)
	if d, err := ForUser(req, nil, "u1", nil); d != nil || err != nil {
		t.Errorf("nil loader = %v, %v; want nothing", d, err)
	}
	var gotUser string
	ok := func(_ context.Context, user string, r Range, u *url.URL) (*Dashboard, error) {
		gotUser = user
		return sampleDashboard(r, u), nil
	}
	if d, err := ForUser(req, ok, "u1", nil); err != nil || d == nil || d.Range.Key != "24h" || gotUser != "u1" {
		t.Errorf("ForUser = %+v, %v (user %q)", d, err, gotUser)
	}
	bad := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/activity?range=nope", nil)
	if _, err := ForUser(bad, ok, "u1", nil); err == nil {
		t.Error("bad range accepted")
	}
	fail := func(context.Context, string, Range, *url.URL) (*Dashboard, error) { return nil, errors.New("boom") }
	if d, err := ForUser(req, fail, "u1", nil); err != nil || d == nil || !d.Failed {
		t.Errorf("failing loader = %+v, %v; want a Failed dashboard", d, err)
	}
}
