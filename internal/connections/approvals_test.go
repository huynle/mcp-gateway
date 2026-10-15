package connections_test

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/federation/snapshot"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/policy/policytest"
)

type toolList []connectors.Tool

func (l toolList) List() []connectors.Tool { return l }
func (l toolList) IsServerApp(string) bool { return false }

func approvalTools() toolList {
	w := func(app, name string) connectors.Tool {
		return connectors.Tool{App: app, Name: name, Kind: connectors.KindWrite, Description: "Does " + name + "."}
	}
	return toolList{
		w("github", "create_issue"), w("github", "add_comment"),
		{App: "github", Name: "list_issues", Kind: connectors.KindRead},
		w("gmail", "send_message"), w("calendar", "create_event"),
	}
}

// approvalHarness is the portal harness with the policy service's vendor
// tool approvals wired into the vendor app pages.
func approvalHarness(t *testing.T) (*harness, *policy.Service) {
	t.Helper()
	h := newHarness(t)
	pol, err := policy.New(policytest.NewMemStore(), policy.Options{Tools: approvalTools()})
	if err != nil {
		t.Fatal(err)
	}
	h.conn.MapApp("gmail", "google")
	h.conn.MapApp("calendar", "google")
	h.cp.SetToolApprovals(pol)
	return h, pol
}

func modeOf(t *testing.T, pol *policy.Service, app, tool string) snapshot.Approval {
	t.Helper()
	modes, err := pol.AppApprovalModes(context.Background(), app)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range modes {
		if m.Tool == tool {
			return m.Mode
		}
	}
	t.Fatalf("no %s.%s in %+v", app, tool, modes)
	return ""
}

func TestVendorToolApprovalsPage(t *testing.T) {
	h, _ := approvalHarness(t)
	admin, _ := h.session(t, adminSub, "Admin")
	rec := h.do(t, request{method: http.MethodGet, path: "/admin/vendor-apps/github", cookie: admin})
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("GET = %d", rec.Code)
	}
	for _, want := range []string{
		"Tool approvals", `action="/admin/vendor-apps/github/approvals"`, `name="app" value="github"`,
		`name="mode_create_issue" value="ask"`, `name="mode_create_issue" value="auto" checked`,
		`name="mode_add_comment"`, "Run all without asking", "Ask for all", "2 write tools",
		"still applies", `class="seg"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	if strings.Contains(body, "mode_list_issues") {
		t.Error("a read tool is offered an approval mode")
	}
	// Google: every app mapped to the vendor, on either variant's page.
	rec = h.do(t, request{method: http.MethodGet, path: "/admin/vendor-apps/google/external", cookie: admin})
	body = rec.Body.String()
	for _, want := range []string{`name="app" value="gmail"`, `name="app" value="calendar"`, "mode_send_message", "mode_create_event", `action="/admin/vendor-apps/google/approvals"`} {
		if !strings.Contains(body, want) {
			t.Errorf("google page lacks %q", want)
		}
	}
}

func TestVendorToolApprovalsSave(t *testing.T) {
	h, pol := approvalHarness(t)
	admin, ap := h.session(t, adminSub, "Admin")
	member, mp := h.session(t, memberSub, "Member")
	const path = "/admin/vendor-apps/github/approvals"
	form := url.Values{"app": {"github"}, "mode_create_issue": {"ask"}, "mode_add_comment": {"auto"}}

	if rec := h.do(t, request{method: http.MethodPost, path: path, cookie: admin, form: form}); rec.Code != http.StatusForbidden {
		t.Errorf("POST without CSRF = %d, want 403", rec.Code)
	}
	memberForm := url.Values{"_csrf": {mp.CSRFToken}}
	for k, v := range form {
		memberForm[k] = v
	}
	if rec := h.do(t, request{method: http.MethodPost, path: path, cookie: member, form: memberForm}); rec.Code != http.StatusNotFound {
		t.Errorf("member POST = %d, want 404 (admin pages do not exist for members)", rec.Code)
	}
	if got := modeOf(t, pol, "github", "create_issue"); got != snapshot.ApprovalAuto {
		t.Fatalf("refused POSTs changed the mode to %s", got)
	}

	form.Set("_csrf", ap.CSRFToken)
	rec := h.do(t, request{method: http.MethodPost, path: path, cookie: admin, form: form})
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/vendor-apps/github?approvals=1#approvals" {
		t.Fatalf("admin POST = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if got := modeOf(t, pol, "github", "create_issue"); got != snapshot.ApprovalAsk {
		t.Errorf("create_issue = %s, want ask", got)
	}
	rec = h.do(t, request{method: http.MethodGet, path: "/admin/vendor-apps/github?approvals=1", cookie: admin})
	if body := rec.Body.String(); !strings.Contains(body, `name="mode_create_issue" value="ask" checked`) || !strings.Contains(body, "Approval modes saved.") {
		t.Errorf("page after save does not show the new mode and notice")
	}

	// Bulk buttons.
	bulk := url.Values{"_csrf": {ap.CSRFToken}, "app": {"github"}, "all": {"ask"}}
	if rec := h.do(t, request{method: http.MethodPost, path: path, cookie: admin, form: bulk}); rec.Code != http.StatusSeeOther {
		t.Fatalf("all=ask = %d", rec.Code)
	}
	if got := modeOf(t, pol, "github", "add_comment"); got != snapshot.ApprovalAsk {
		t.Errorf("after all=ask add_comment = %s", got)
	}

	// Invalid mode: 422 with the shared message, nothing changed.
	bad := url.Values{"_csrf": {ap.CSRFToken}, "app": {"github"}, "mode_create_issue": {"sometimes"}}
	rec = h.do(t, request{method: http.MethodPost, path: path, cookie: admin, form: bad})
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "Choose Ask or Auto for each tool.") {
		t.Errorf("invalid mode = %d", rec.Code)
	}
	bad = url.Values{"_csrf": {ap.CSRFToken}, "app": {"github"}, "all": {"never"}}
	if rec := h.do(t, request{method: http.MethodPost, path: path, cookie: admin, form: bad}); rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("invalid all = %d, want 422", rec.Code)
	}
	// An app of another vendor is not found here.
	other := url.Values{"_csrf": {ap.CSRFToken}, "app": {"gmail"}, "mode_send_message": {"ask"}}
	if rec := h.do(t, request{method: http.MethodPost, path: path, cookie: admin, form: other}); rec.Code != http.StatusNotFound {
		t.Errorf("other vendor's app = %d, want 404", rec.Code)
	}
	if got := modeOf(t, pol, "gmail", "send_message"); got != snapshot.ApprovalAuto {
		t.Errorf("gmail changed through github's page: %s", got)
	}
}
