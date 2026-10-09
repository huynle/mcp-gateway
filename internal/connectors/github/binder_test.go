package github_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"golang.org/x/oauth2"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/github"
)

// bindInput builds the BindInput the connect flow hands a binder: the
// vendor app (its UserInfoURL points the binder at the fixture server),
// the exchanged token and a client authenticated with it.
func bindInput(srv *apiServer, extra map[string]string, tok *oauth2.Token) connections.BindInput {
	app := connections.Defaults(connections.VendorGitHub, "")
	app.UserInfoURL = srv.URL + "/user"
	for k, v := range extra {
		app.Extra[k] = v
	}
	if tok == nil {
		tok = &oauth2.Token{AccessToken: testToken}
	}
	return connections.BindInput{
		App:    app,
		Token:  tok,
		Client: oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(tok)),
	}
}

func TestBinderCompanyWhenMemberOfCompanyOrg(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"GET /user":                              {status: 200, body: "user.json"},
		"GET /user/memberships/orgs/example-org": {status: 200, body: "org_membership_active.json"},
		"GET /user/memberships/orgs/other-org":   {status: 404, body: "error_not_found.json"},
	})
	b := github.Binder{}
	bound, err := b.Bind(context.Background(), bindInput(srv, map[string]string{github.ExtraCompanyOrgs: "other-org, Example-Org"}, nil))
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if bound.ExternalAccountID != "github:583231" {
		t.Errorf("ExternalAccountID = %q, want github:583231", bound.ExternalAccountID)
	}
	if bound.DisplayName != "octocat" {
		t.Errorf("DisplayName = %q, want octocat", bound.DisplayName)
	}
	if bound.Label != connectors.LabelCompany {
		t.Errorf("Label = %q, want company", bound.Label)
	}
}

func TestBinderPersonalWhenNotAMember(t *testing.T) {
	cases := map[string]route{
		"404 not found":     {status: 404, body: "error_not_found.json"},
		"pending":           {status: 200, body: "org_membership_pending.json"},
		"403 no permission": {status: 403, body: "error_forbidden.json"},
	}
	for name, rt := range cases {
		t.Run(name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{
				"GET /user":                              {status: 200, body: "user.json"},
				"GET /user/memberships/orgs/example-org": rt,
				"GET /orgs/example-org/members/octocat":  {status: 404, body: "error_not_found.json"},
			})
			bound, err := github.Binder{}.Bind(context.Background(), bindInput(srv, map[string]string{github.ExtraCompanyOrgs: "example-org"}, nil))
			if err != nil {
				t.Fatalf("Bind: %v", err)
			}
			if bound.Label != connectors.LabelPersonal {
				t.Errorf("Label = %q, want personal", bound.Label)
			}
		})
	}
}

func TestBinderPublicMembershipFallback(t *testing.T) {
	// Without the Members permission the membership endpoint answers 403;
	// the public membership check (204 = member) still classifies.
	srv := newAPIServer(t, map[string]route{
		"GET /user":                              {status: 200, body: "user.json"},
		"GET /user/memberships/orgs/example-org": {status: 403, body: "error_forbidden.json"},
		"GET /orgs/example-org/members/octocat":  {status: 204},
	})
	bound, err := github.Binder{}.Bind(context.Background(), bindInput(srv, map[string]string{github.ExtraCompanyOrgs: "example-org"}, nil))
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if bound.Label != connectors.LabelCompany {
		t.Errorf("Label = %q, want company", bound.Label)
	}
}

func TestBinderPersonalWithoutCompanyOrgs(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"GET /user": {status: 200, body: "user.json"},
	})
	bound, err := github.Binder{}.Bind(context.Background(), bindInput(srv, nil, nil))
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if bound.Label != connectors.LabelPersonal {
		t.Errorf("Label = %q, want personal", bound.Label)
	}
	if n := len(srv.Requests()); n != 1 {
		t.Errorf("requests = %d, want 1 (no membership lookups without company_orgs)", n)
	}
}

func TestBinderScopes(t *testing.T) {
	t.Run("from token response", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"GET /user": {status: 200, body: "user.json"}})
		tok := (&oauth2.Token{AccessToken: testToken}).WithExtra(map[string]any{"scope": "repo,read:org"})
		bound, err := github.Binder{}.Bind(context.Background(), bindInput(srv, nil, tok))
		if err != nil {
			t.Fatal(err)
		}
		if got, want := bound.Scopes, []string{"read:org", "repo"}; !equalStrings(got, want) {
			t.Errorf("Scopes = %v, want %v", got, want)
		}
	})
	t.Run("from X-OAuth-Scopes header", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"GET /user": {status: 200, body: "user.json", headers: map[string]string{"X-OAuth-Scopes": "repo, user:email"}}})
		bound, err := github.Binder{}.Bind(context.Background(), bindInput(srv, nil, nil))
		if err != nil {
			t.Fatal(err)
		}
		if got, want := bound.Scopes, []string{"repo", "user:email"}; !equalStrings(got, want) {
			t.Errorf("Scopes = %v, want %v", got, want)
		}
	})
	t.Run("github app token has none", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"GET /user": {status: 200, body: "user.json", headers: map[string]string{"X-OAuth-Scopes": ""}}})
		bound, err := github.Binder{}.Bind(context.Background(), bindInput(srv, nil, nil))
		if err != nil {
			t.Fatal(err)
		}
		if bound.Scopes != nil {
			t.Errorf("Scopes = %v, want nil (the flow falls back to the requested scopes)", bound.Scopes)
		}
	})
}

func TestBinderRejectedToken(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /user": {status: 401, body: "error_bad_credentials.json"}})
	in := bindInput(srv, nil, &oauth2.Token{AccessToken: testToken})
	_, err := github.Binder{}.Bind(context.Background(), in)
	var ghErr *github.Error
	if !errors.As(err, &ghErr) || ghErr.Status != http.StatusUnauthorized || ghErr.Class != github.ClassReconnectRequired {
		t.Fatalf("Bind err = %v, want *github.Error 401 class %s", err, github.ClassReconnectRequired)
	}
}

func TestBinderDerivesAPIBaseFromUserInfoURL(t *testing.T) {
	// A GHES app sets UserInfoURL to https://ghes.example/api/v3/user; the
	// membership lookups must go to the same API root.
	srv := newAPIServer(t, map[string]route{
		"GET /api/v3/user": {status: 200, body: "user.json"},
		"GET /api/v3/user/memberships/orgs/example-org": {status: 200, body: "org_membership_active.json"},
	})
	in := bindInput(srv, map[string]string{github.ExtraCompanyOrgs: "example-org"}, nil)
	in.App.UserInfoURL = srv.URL + "/api/v3/user"
	bound, err := github.Binder{}.Bind(context.Background(), in)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if bound.Label != connectors.LabelCompany {
		t.Errorf("Label = %q, want company", bound.Label)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
