package policy_test

import (
	"context"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/policy"
)

func TestMemberBaselineApps(t *testing.T) {
	p := newPages(t)
	tools := p.reg.List()
	srv := tools[0]
	srv.App = "my-server"
	if err := p.reg.AddServerTools("my-server", []connectors.Tool{srv}); err != nil {
		t.Fatal(err)
	}
	gw := tools[0]
	gw.App = policy.GatewayApp
	if err := p.reg.Register(gw); err != nil {
		t.Fatal(err)
	}
	apps := policy.MemberBaselineApps(p.reg)
	if !slices.Equal(apps, []string{"fake"}) {
		t.Errorf("baseline apps = %v, want [fake] (no user-added servers, no gateway management app)", apps)
	}
}

func TestApplyMemberBaseline(t *testing.T) {
	p := newPages(t)
	ctx := context.Background()
	// Keep an admin's own deny on a single tool.
	p.st.PutRole(policy.Role{Name: "member", Rules: []policy.ToolRule{
		{App: "fake", Tool: "list_items", Outcome: policy.OutcomeDeny},
	}})

	body := p.do(t, http.MethodGet, "/admin/settings/default-role", nil, true).Body.String()
	if !strings.Contains(body, `action="/admin/settings/default-role/member-baseline"`) || !strings.Contains(body, "<code>fake.*</code>") {
		t.Fatalf("default-role page lacks the baseline action:\n%s", body)
	}
	if rec := p.do(t, http.MethodPost, "/admin/settings/default-role/member-baseline", url.Values{}, false); rec.Code != http.StatusNotFound {
		t.Errorf("non-admin = %d, want 404", rec.Code)
	}
	rec := p.do(t, http.MethodPost, "/admin/settings/default-role/member-baseline", url.Values{}, true)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/admin/settings/default-role?baseline=1" {
		t.Fatalf("apply = %d %q:\n%s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	role, err := p.svc.Role(ctx, "member")
	if err != nil {
		t.Fatal(err)
	}
	if !role.MayAddServers {
		t.Error("baseline must set may_add_servers")
	}
	var allow, deny bool
	for _, r := range role.Rules {
		allow = allow || r.App == "fake" && r.Tool == policy.Wildcard && r.Outcome == policy.OutcomeAllow
		deny = deny || r.App == "fake" && r.Tool == "list_items" && r.Outcome == policy.OutcomeDeny
	}
	if !allow || !deny {
		t.Errorf("member rules = %+v, want fake.* allow added and the existing deny kept", role.Rules)
	}
	ev := p.rec.last()
	if ev.UserID != adminUser || ev.ResourceIdentity["action"] != "member_baseline_applied" || ev.ResourceIdentity["role"] != "member" || ev.ResourceIdentity["apps"] != "1" {
		t.Errorf("audit = %+v", ev)
	}
	if name, _ := p.svc.DefaultRole(ctx); name != "" {
		t.Errorf("the baseline must not flag member as default, DefaultRole = %q", name)
	}
	// Idempotent.
	if err := p.svc.ApplyMemberBaseline(ctx, adminUser, []string{"fake"}); err != nil {
		t.Fatal(err)
	}
	role, _ = p.svc.Role(ctx, "member")
	n := 0
	for _, r := range role.Rules {
		if r.App == "fake" && r.Tool == policy.Wildcard {
			n++
		}
	}
	if n != 1 {
		t.Errorf("fake.* rules after a second apply = %d, want 1", n)
	}
	if !strings.Contains(p.do(t, http.MethodGet, "/admin/settings/default-role?baseline=1", nil, true).Body.String(), "baseline applied") {
		t.Error("no confirmation after applying")
	}
}

func TestApplyMemberBaselineSeveralAppsAndValidation(t *testing.T) {
	p := newPages(t)
	ctx := context.Background()
	if err := p.svc.ApplyMemberBaseline(ctx, adminUser, []string{"fake", "github"}); err != nil {
		t.Fatal(err)
	}
	role, err := p.svc.Role(ctx, "member")
	if err != nil || len(role.Rules) < 2 {
		t.Fatalf("member = %+v, %v", role, err)
	}
	if err := p.svc.ApplyMemberBaseline(ctx, adminUser, []string{"Not An App"}); err == nil {
		t.Error("an invalid app name must be refused")
	}
}
