package ledger_test

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/huynle/mcp-gateway/internal/ledger"
	"github.com/huynle/mcp-gateway/internal/portal/nav"
	"github.com/huynle/mcp-gateway/internal/portal/nav/navtest"
)

func TestOperationsPageUsesTheSharedShell(t *testing.T) {
	f := newFixture(t)
	f.begin(t, f.intent(map[string]any{"id": "it-1"}))
	mux := http.NewServeMux()
	ledger.NewPortal(f.svc, func(*http.Request) (string, string) { return alice, "csrf-token" }, slog.New(slog.DiscardHandler)).Mount(mux.Handle)
	req := httptest.NewRequestWithContext(nav.WithData(t.Context(), nav.Data{SignedIn: true, CSRFToken: "csrf-token"}), http.MethodGet, "/operations", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	navtest.AssertShell(t, "/operations", rec.Body.String())
}
