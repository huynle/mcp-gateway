package portal_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/huynle/mcp-gateway/internal/approvals"
	"github.com/huynle/mcp-gateway/internal/approvals/approvalstest"
	"github.com/huynle/mcp-gateway/internal/config"
	"github.com/huynle/mcp-gateway/internal/crypto"
	"github.com/huynle/mcp-gateway/internal/identity"
	"github.com/huynle/mcp-gateway/internal/identity/identitytest"
	"github.com/huynle/mcp-gateway/internal/portal"
)

// The approval pages mounted through MountUser, end to end: session
// cookie, anonymous redirect, CSRF, another user's approval is a 404,
// approve and deny.
func TestApprovalPagesThroughThePortal(t *testing.T) {
	st := identitytest.NewMemStore()
	cfg := identity.Config{
		BaseURL:         "http://localhost:18080",
		Providers:       []config.OIDCProvider{{Name: "dex", DisplayName: "Local dex", Issuer: issuer, ClientID: "gateway", ClientSecret: "s", AllowedDomains: []string{"example.com"}}},
		DefaultRole:     defaultRole,
		IdleTimeout:     12 * time.Hour,
		AbsoluteTimeout: 7 * 24 * time.Hour,
	}
	svc, err := identity.New(cfg, st, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	p, err := portal.New(svc, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := crypto.NewStaticProvider("k1", map[string][]byte{"k1": bytes.Repeat([]byte{3}, 32)})
	if err != nil {
		t.Fatal(err)
	}
	ast := approvalstest.NewMemStore()
	asvc, err := approvals.New(approvals.Config{TTL: 15 * time.Minute, Wait: time.Second, BaseURL: cfg.BaseURL}, ast, keys, approvals.Options{Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	who := func(r *http.Request) (string, string) {
		pr := identity.PrincipalFrom(r.Context())
		if pr == nil {
			return "", ""
		}
		return pr.UserID, pr.CSRFToken
	}
	approvals.NewPortal(asvc, who, slog.New(slog.DiscardHandler)).Mount(p.MountUser)

	h := &harness{h: p.Handler(), svc: svc, st: st}
	cookie, member := h.session(t, memberSub, "Member")
	otherCookie, other := h.session(t, otherSub, "Other")
	const acct = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
	create := func(user string) *approvals.Approval {
		a, err := asvc.Create(context.Background(), approvals.Request{UserID: user, AccountID: acct, AccountLabel: "company", Tool: "fake.create_item",
			Args: map[string]any{"name": "first", "body": "SECRET"}, PolicyVersionID: "99999999-9999-4999-8999-999999999991"})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	mine := create(member.UserID)
	theirs := create(other.UserID)

	// Anonymous: redirected to sign-in.
	rec := h.do(t, request{method: http.MethodGet, path: "/approvals"})
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/signin?return_to=") {
		t.Errorf("anonymous GET /approvals = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	// Signed in: only my own approval is listed, with its arguments.
	rec = h.do(t, request{method: http.MethodGet, path: "/approvals", cookie: cookie})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), mine.ID) || strings.Contains(rec.Body.String(), theirs.ID) || !strings.Contains(rec.Body.String(), "SECRET") {
		t.Errorf("GET /approvals = %d:\n%s", rec.Code, rec.Body)
	}
	// POST without the CSRF token is refused before the handler runs.
	if rec := h.do(t, request{method: http.MethodPost, path: "/approvals/" + mine.ID + "/approve", cookie: cookie, form: url.Values{}}); rec.Code != http.StatusForbidden {
		t.Errorf("POST without CSRF = %d, want 403", rec.Code)
	}
	if ast.Record(mine.ID).Status != approvals.StatusPending {
		t.Fatal("CSRF-less POST decided the approval")
	}
	// Someone else's approval: 404, untouched.
	form := url.Values{"_csrf": {member.CSRFToken}}
	if rec := h.do(t, request{method: http.MethodPost, path: "/approvals/" + theirs.ID + "/approve", cookie: cookie, form: form}); rec.Code != http.StatusNotFound {
		t.Errorf("POST other's approval = %d, want 404", rec.Code)
	}
	if ast.Record(theirs.ID).Status != approvals.StatusPending {
		t.Error("member decided other's approval")
	}
	// Mine: approved.
	rec = h.do(t, request{method: http.MethodPost, path: "/approvals/" + mine.ID + "/approve", cookie: cookie, form: form})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/approvals?decided=approved" {
		t.Errorf("approve = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if ast.Record(mine.ID).Status != approvals.StatusApproved {
		t.Error("approve did not take")
	}
	// Other denies theirs with their own session and token.
	otherForm := url.Values{"_csrf": {other.CSRFToken}}
	if rec := h.do(t, request{method: http.MethodPost, path: "/approvals/" + theirs.ID + "/deny", cookie: otherCookie, form: otherForm}); rec.Code != http.StatusSeeOther {
		t.Errorf("other denies = %d", rec.Code)
	}
	if got := ast.Record(theirs.ID); got.Status != approvals.StatusDenied || got.Payload != nil {
		t.Errorf("after deny: %+v", got)
	}
	// History for the member shows only the member's row.
	rec = h.do(t, request{method: http.MethodGet, path: "/approvals/history", cookie: cookie})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), mine.ID[:8]) || strings.Contains(rec.Body.String(), theirs.ID[:8]) || strings.Contains(rec.Body.String(), "SECRET") {
		t.Errorf("GET /approvals/history = %d:\n%s", rec.Code, rec.Body)
	}
}
