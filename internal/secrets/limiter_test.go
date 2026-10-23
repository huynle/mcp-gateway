package secrets_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/secrets"
)

// limitedPages mounts the pages with an address limiter of burst failed
// lookups per minute; the caller is user.
func limitedPages(t *testing.T, burst int, user *string) (*fixture, *http.ServeMux) {
	t.Helper()
	f := newFixture(t)
	mux := http.NewServeMux()
	who := func(*http.Request) (string, string) { return *user, pageCSRF }
	lim := secrets.NewAddressLimiter(burst, time.Minute, nil)
	secrets.NewPortal(f.svc, who, secrets.PortalOptions{FailureLimiter: lim}).Mount(mux.Handle)
	return f, mux
}

func serveFrom(mux *http.ServeMux, addr, method, path string, form url.Values) *httptest.ResponseRecorder {
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(method, path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	req.RemoteAddr = addr + ":40000"
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestEntryLookupFailuresAreLimitedPerAddress(t *testing.T) {
	user := alice
	f, mux := limitedPages(t, 3, &user)
	const attacker, other = "198.51.100.7", "203.0.113.9"
	unknown := "/s/" + strings.Repeat("Z", 43)

	first := serveFrom(mux, attacker, http.MethodGet, unknown, nil)
	if first.Code != http.StatusNotFound {
		t.Fatalf("first unknown = %d", first.Code)
	}
	want := first.Body.String()
	for i := 2; i <= 3; i++ {
		rec := serveFrom(mux, attacker, http.MethodGet, unknown, nil)
		if rec.Code != http.StatusNotFound || rec.Body.String() != want {
			t.Fatalf("unknown #%d below the budget = %d, want the same 404", i, rec.Code)
		}
	}
	over := serveFrom(mux, attacker, http.MethodGet, unknown, nil)
	if over.Code != http.StatusTooManyRequests {
		t.Fatalf("unknown past the budget = %d, want 429", over.Code)
	}
	if ra, err := strconv.Atoi(over.Header().Get("Retry-After")); err != nil || ra < 1 {
		t.Errorf("Retry-After = %q", over.Header().Get("Retry-After"))
	}
	if over.Header().Get("X-Frame-Options") != "DENY" || over.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("429 headers = %v", over.Header())
	}

	// The address is limited for real links and POSTs too; another
	// address is not.
	r := f.request(t, alice, 0, 1)
	if rec := serveFrom(mux, attacker, http.MethodGet, "/s/"+r.RequestID, nil); rec.Code != http.StatusTooManyRequests {
		t.Errorf("limited address, real link = %d, want 429", rec.Code)
	}
	if rec := serveFrom(mux, attacker, http.MethodPost, unknown, deny()); rec.Code != http.StatusTooManyRequests {
		t.Errorf("limited address, POST = %d, want 429", rec.Code)
	}
	if rec := serveFrom(mux, other, http.MethodGet, unknown, nil); rec.Code != http.StatusNotFound || rec.Body.String() != want {
		t.Errorf("other address = %d, want the 404", rec.Code)
	}
	if rec := serveFrom(mux, other, http.MethodGet, "/s/"+r.RequestID, nil); rec.Code != http.StatusOK {
		t.Errorf("other address, real link = %d", rec.Code)
	}
}

func TestSuccessfulLookupsDoNotSpendTheBudget(t *testing.T) {
	user := alice
	f, mux := limitedPages(t, 2, &user)
	r := f.request(t, alice, 0, 1)
	for i := range 5 {
		if rec := serveFrom(mux, "198.51.100.7", http.MethodGet, "/s/"+r.RequestID, nil); rec.Code != http.StatusOK {
			t.Fatalf("GET #%d = %d", i+1, rec.Code)
		}
	}
	// Another user's link is the 404 and spends it.
	user = bob
	for range 2 {
		if rec := serveFrom(mux, "198.51.100.7", http.MethodGet, "/s/"+r.RequestID, nil); rec.Code != http.StatusNotFound {
			t.Fatalf("bob = %d, want 404", rec.Code)
		}
	}
	if rec := serveFrom(mux, "198.51.100.7", http.MethodGet, "/s/"+r.RequestID, nil); rec.Code != http.StatusTooManyRequests {
		t.Errorf("bob past the budget = %d, want 429", rec.Code)
	}
}

func TestAddressLimiterUsesTheClientIPFunc(t *testing.T) {
	lim := secrets.NewAddressLimiter(1, time.Minute, func(r *http.Request) string { return r.Header.Get("X-Test-IP") })
	a := httptest.NewRequest(http.MethodGet, "/s/x", nil)
	a.Header.Set("X-Test-IP", "a")
	b := httptest.NewRequest(http.MethodGet, "/s/x", nil)
	b.Header.Set("X-Test-IP", "b")
	lim.Fail(a)
	if ok, wait := lim.Allow(a); ok || wait <= 0 {
		t.Errorf("a after its budget: ok=%v wait=%v", ok, wait)
	}
	if ok, _ := lim.Allow(b); !ok {
		t.Error("b was limited by a's failures")
	}
}
