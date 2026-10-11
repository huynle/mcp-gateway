package policy_test

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/fake"
	"github.com/huynle/mcp-gateway/internal/policy"
	"github.com/huynle/mcp-gateway/internal/policy/policytest"
)

const (
	adminUser  = "u-admin"
	memberUser = "u-member"
)

type pages struct {
	mux *http.ServeMux
	svc *policy.Service
	st  *policytest.MemStore
	rec *memRecorder
	reg *connectors.Registry
}

// newPages mounts the admin pages on a bare mux with a fake identity: the
// X-Test-User header names the caller, X-Test-Admin marks admins. CSRF is
// the portal's job (portal.MountAdmin); the pages still echo the token.
func newPages(t *testing.T) pages {
	t.Helper()
	f := fake.New(fake.Options{})
	reg := connectors.NewRegistry()
	if err := connectors.RegisterConnector(reg, f, f.Accounts()); err != nil {
		t.Fatal(err)
	}
	st := policytest.NewMemStore()
	st.PutRole(policy.Role{Name: "member", Description: "Default", Rules: []policy.ToolRule{{App: "fake", Tool: "list_items", Outcome: policy.OutcomeAllow}}})
	st.PutRole(policy.Role{Name: "admin"})
	st.Assign(memberUser, "member")
	rec := &memRecorder{}
	svc, err := policy.New(st, policy.Options{Audit: rec, Log: slog.New(slog.DiscardHandler)})
	if err != nil {
		t.Fatal(err)
	}
	who := func(r *http.Request) (string, string, bool) {
		return r.Header.Get("X-Test-User"), "csrf-token", r.Header.Get("X-Test-Admin") == "1"
	}
	mux := http.NewServeMux()
	policy.NewPortal(svc, reg, who, slog.New(slog.DiscardHandler)).Mount(mux.Handle)
	return pages{mux: mux, svc: svc, st: st, rec: rec, reg: reg}
}

func (p pages) do(t *testing.T, method, path string, form url.Values, admin bool) *httptest.ResponseRecorder {
	t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequestWithContext(context.Background(), method, path, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if admin {
		req.Header.Set("X-Test-User", adminUser)
		req.Header.Set("X-Test-Admin", "1")
	} else {
		req.Header.Set("X-Test-User", memberUser)
	}
	rec := httptest.NewRecorder()
	p.mux.ServeHTTP(rec, req)
	return rec
}

func TestRolePagesAreAdminOnly(t *testing.T) {
	p := newPages(t)
	for _, path := range []string{"/admin/roles", "/admin/roles/new", "/admin/roles/member", "/admin/settings/default-role"} {
		if rec := p.do(t, http.MethodGet, path, nil, false); rec.Code != http.StatusNotFound {
			t.Errorf("member GET %s = %d, want 404", path, rec.Code)
		}
	}
	if rec := p.do(t, http.MethodPost, "/admin/roles/member/delete", url.Values{}, false); rec.Code != http.StatusNotFound {
		t.Errorf("member POST delete = %d, want 404", rec.Code)
	}
	if roles, _ := p.svc.Roles(context.Background()); len(roles) != 2 {
		t.Errorf("non-admin changed roles: %+v", roles)
	}
}

func TestRoleListAndEditorRender(t *testing.T) {
	p := newPages(t)
	rec := p.do(t, http.MethodGet, "/admin/roles", nil, true)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "member") || !strings.Contains(body, "admin") || !strings.Contains(body, "/admin/roles/new") {
		t.Errorf("GET /admin/roles = %d:\n%s", rec.Code, body)
	}
	rec = p.do(t, http.MethodGet, "/admin/roles/member", nil, true)
	body = rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /admin/roles/member = %d:\n%s", rec.Code, body)
	}
	// The grid comes from the registry: every fake tool plus the app
	// wildcard row, with the stored outcome selected.
	for _, want := range []string{`name="outcome.fake.*"`, `name="outcome.fake.list_items"`, `name="outcome.fake.create_item"`, `name="outcome.fake.list_accounts"`, `name="personal.fake"`, `name="description"`} {
		if !strings.Contains(body, want) {
			t.Errorf("editor lacks %s", want)
		}
	}
	if !regexp.MustCompile(`name="outcome\.fake\.list_items"[^>]*>\s*(<option[^>]*>[^<]*</option>\s*)*<option value="allow" selected`).MatchString(body) {
		t.Errorf("stored outcome not selected:\n%s", body)
	}
	if rec := p.do(t, http.MethodGet, "/admin/roles/ghost", nil, true); rec.Code != http.StatusNotFound {
		t.Errorf("GET unknown role = %d", rec.Code)
	}
}

// formFieldRE finds every form control name the editor renders.
var formFieldRE = regexp.MustCompile(`<(?:input|textarea|select)[^>]*\sname="([^"]+)"`)

func TestEditorHasNoRawPolicyInput(t *testing.T) {
	p := newPages(t)
	for _, path := range []string{"/admin/roles/new", "/admin/roles/member", "/admin/settings/default-role"} {
		body := p.do(t, http.MethodGet, path, nil, true).Body.String()
		for _, m := range formFieldRE.FindAllStringSubmatch(body, -1) {
			name := m[1]
			lower := strings.ToLower(name)
			if strings.Contains(lower, "cedar") || strings.Contains(lower, "policy") || strings.Contains(lower, "json") {
				t.Errorf("%s: form field %q looks like a raw policy input", path, name)
			}
			switch {
			case name == "_csrf", name == "name", name == "description", name == "role", name == "default_role":
			case strings.HasPrefix(name, "outcome."), strings.HasPrefix(name, "personal."):
			case strings.HasPrefix(name, "cond."):
			default:
				t.Errorf("%s: unexpected form field %q (every field must be structured)", path, name)
			}
		}
		if strings.Contains(body, "<textarea") {
			t.Errorf("%s: a textarea invites free text", path)
		}
	}
	// A posted "cedar" field is ignored.
	form := url.Values{"description": {"x"}, "outcome.fake.list_items": {"allow"}, "cedar": {`permit(principal, action, resource);`}}
	if rec := p.do(t, http.MethodPost, "/admin/roles/member", form, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("POST = %d:\n%s", rec.Code, rec.Body)
	}
	c, _ := p.svc.Current(context.Background())
	if strings.Contains(c.Cedar, "permit(principal, action, resource)") {
		t.Error("raw cedar reached the policy")
	}
}

func TestEditorRoundTrip(t *testing.T) {
	p := newPages(t)
	ctx := context.Background()
	before, _ := p.svc.Current(ctx)

	form := url.Values{
		"name":                     {" Engineer "},
		"description":              {"Engineers"},
		"outcome.fake.*":           {"allow"},
		"outcome.fake.create_item": {"hidden"},
		"outcome.fake.post_note":   {"confirm"},
		"outcome.fake.list_items":  {""}, // no rule
		"personal.fake":            {"confirm_writes"},
		// Conditional rules: one condition per row.
		"cond.1.app":     {"fake"},
		"cond.1.tool":    {"get_item"},
		"cond.1.outcome": {"deny"},
		"cond.1.key":     {"id"},
		"cond.1.op":      {"prefix"},
		"cond.1.value":   {"secret-"},
		"cond.2.app":     {""}, // blank row ignored
	}
	rec := p.do(t, http.MethodPost, "/admin/roles/new", form, true)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/roles/engineer" {
		t.Fatalf("POST /admin/roles/new = %d %q:\n%s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	role, err := p.svc.Role(ctx, "engineer")
	if err != nil {
		t.Fatal(err)
	}
	want := []policy.ToolRule{
		{App: "fake", Tool: "*", Outcome: policy.OutcomeAllow},
		{App: "fake", Tool: "create_item", Outcome: policy.OutcomeHidden},
		{App: "fake", Tool: "get_item", Outcome: policy.OutcomeDeny, Conditions: []policy.Condition{{Key: "id", Op: policy.OpPrefix, Value: "secret-"}}},
		{App: "fake", Tool: "post_note", Outcome: policy.OutcomeConfirm},
	}
	if role.Description != "Engineers" || !slices.EqualFunc(role.Rules, want, func(a, b policy.ToolRule) bool {
		return a.App == b.App && a.Tool == b.Tool && a.Outcome == b.Outcome && slices.Equal(a.Conditions, b.Conditions)
	}) || role.PersonalAccounts["fake"] != policy.AllowanceConfirmWrites {
		t.Errorf("saved role = %+v", role)
	}
	after, _ := p.svc.Current(ctx)
	if after.Version == before.Version {
		t.Error("creating a role kept the version")
	}
	if ev := p.rec.last(); ev.UserID != adminUser || ev.ResourceIdentity["action"] != "role_saved" || ev.ResourceIdentity["role"] != "engineer" {
		t.Errorf("audit = %+v", ev)
	}

	// The editor shows what was saved, including the condition row.
	body := p.do(t, http.MethodGet, "/admin/roles/engineer", nil, true).Body.String()
	for _, want := range []string{`value="secret-"`, `<option value="prefix" selected`, `<option value="confirm_writes" selected`} {
		if !strings.Contains(body, want) {
			t.Errorf("editor lacks %s:\n%s", want, body)
		}
	}
	// Editing keeps the name (it is the URL) and replaces the rules.
	form = url.Values{"name": {"ignored"}, "description": {"Engineers v2"}, "outcome.fake.list_items": {"allow"}}
	if rec := p.do(t, http.MethodPost, "/admin/roles/engineer", form, true); rec.Code != http.StatusSeeOther {
		t.Fatalf("POST edit = %d:\n%s", rec.Code, rec.Body)
	}
	role, _ = p.svc.Role(ctx, "engineer")
	if role.Description != "Engineers v2" || len(role.Rules) != 1 || role.Rules[0].Tool != "list_items" || len(role.PersonalAccounts) != 0 {
		t.Errorf("edited role = %+v", role)
	}
	if _, err := p.svc.Role(ctx, "ignored"); err == nil {
		t.Error("edit created a role from the posted name")
	}
	// Creating a role that exists is refused; so is a bad name or value.
	for name, form := range map[string]url.Values{
		"duplicate":   {"name": {"member"}},
		"bad name":    {"name": {"Not Valid"}},
		"bad outcome": {"name": {"x"}, "outcome.fake.*": {"sometimes"}},
		"bad op":      {"name": {"x"}, "cond.1.app": {"fake"}, "cond.1.tool": {"*"}, "cond.1.outcome": {"deny"}, "cond.1.key": {"id"}, "cond.1.op": {"regex"}, "cond.1.value": {"a"}},
		"empty value": {"name": {"x"}, "cond.1.app": {"fake"}, "cond.1.tool": {"*"}, "cond.1.outcome": {"deny"}, "cond.1.key": {"id"}, "cond.1.op": {"equals"}, "cond.1.value": {""}},
	} {
		rec := p.do(t, http.MethodPost, "/admin/roles/new", form, true)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), `class="error"`) {
			t.Errorf("%s: POST = %d:\n%s", name, rec.Code, firstLines(rec.Body.String()))
		}
	}
	if _, err := p.svc.Role(ctx, "x"); err == nil {
		t.Error("an invalid form created a role")
	}
}

func TestDeleteRole(t *testing.T) {
	p := newPages(t)
	ctx := context.Background()
	// Assigned: refused with the list re-rendered and an explanation.
	rec := p.do(t, http.MethodPost, "/admin/roles/member/delete", url.Values{}, true)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "assigned") {
		t.Errorf("delete assigned = %d:\n%s", rec.Code, firstLines(rec.Body.String()))
	}
	if _, err := p.svc.Role(ctx, "member"); err != nil {
		t.Error("assigned role was deleted")
	}
	if rec := p.do(t, http.MethodPost, "/admin/roles/ghost/delete", url.Values{}, true); rec.Code != http.StatusNotFound {
		t.Errorf("delete unknown = %d", rec.Code)
	}
	rec = p.do(t, http.MethodPost, "/admin/roles/admin/delete", url.Values{}, true)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/roles" {
		t.Errorf("delete unassigned = %d %q", rec.Code, rec.Header().Get("Location"))
	}
	if _, err := p.svc.Role(ctx, "admin"); err == nil {
		t.Error("unassigned role not deleted")
	}
	if ev := p.rec.last(); ev.ResourceIdentity["action"] != "role_deleted" || ev.ResourceIdentity["role"] != "admin" {
		t.Errorf("audit = %+v", ev)
	}
}

func TestDefaultRolePage(t *testing.T) {
	p := newPages(t)
	ctx := context.Background()
	body := p.do(t, http.MethodGet, "/admin/settings/default-role", nil, true).Body.String()
	if !strings.Contains(body, `name="default_role"`) || !strings.Contains(body, `value="member"`) || !strings.Contains(body, `value="admin"`) {
		t.Errorf("default role page:\n%s", body)
	}
	rec := p.do(t, http.MethodPost, "/admin/settings/default-role", url.Values{"default_role": {"member"}}, true)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("POST = %d:\n%s", rec.Code, rec.Body)
	}
	if name, _ := p.svc.DefaultRole(ctx); name != "member" {
		t.Errorf("DefaultRole = %q", name)
	}
	body = p.do(t, http.MethodGet, "/admin/settings/default-role", nil, true).Body.String()
	if !strings.Contains(body, `value="member" selected`) {
		t.Errorf("default not selected:\n%s", body)
	}
	if rec := p.do(t, http.MethodPost, "/admin/settings/default-role", url.Values{"default_role": {"ghost"}}, true); rec.Code != http.StatusBadRequest {
		t.Errorf("unknown default = %d", rec.Code)
	}
	if ev := p.rec.last(); ev.ResourceIdentity["action"] != "default_role_set" || ev.ResourceIdentity["role"] != "member" {
		t.Errorf("audit = %+v", ev)
	}
}

func firstLines(s string) string {
	lines := strings.Split(s, "\n")
	if len(lines) > 40 {
		lines = lines[:40]
	}
	return strings.Join(lines, "\n")
}

func TestEditorOffersBlankConditionRows(t *testing.T) {
	p := newPages(t)
	body := p.do(t, http.MethodGet, "/admin/roles/member", nil, true).Body.String()
	for _, want := range []string{`name="cond.1.app"`, `name="cond.2.app"`, `name="cond.3.app"`, `name="cond.1.value"`} {
		if !strings.Contains(body, want) {
			t.Errorf("editor lacks blank row field %s", want)
		}
	}
	if strings.Contains(body, `name="cond.0.`) {
		t.Error("rows are numbered from 0; the parser expects 1")
	}
}
