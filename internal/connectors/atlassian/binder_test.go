package atlassian_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/oauth2"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/atlassian"
)

// bindInput builds the BindInput the connect flow hands a binder: the
// vendor app (its UserInfoURL points the binder at the fixture server),
// the exchanged token and a client authenticated with it.
func bindInput(srv *apiServer, extra map[string]string, tok *oauth2.Token) connections.BindInput {
	app := connections.Defaults(connections.VendorAtlassian, "")
	app.UserInfoURL = srv.URL + "/me"
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

func bindRoutes(resources string) map[string]route {
	return map[string]route{
		"GET /me":                               {status: 200, body: "me.json"},
		"GET /oauth/token/accessible-resources": {status: 200, body: resources},
	}
}

func TestBinderBindsTheFirstSite(t *testing.T) {
	srv := newAPIServer(t, bindRoutes("accessible_resources.json"))
	bound, err := atlassian.Binder{}.Bind(context.Background(), bindInput(srv, nil, nil))
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if bound.ExternalAccountID != "5b10ac8d82e05b22cc7d4ef5@"+cloudID {
		t.Errorf("ExternalAccountID = %q", bound.ExternalAccountID)
	}
	if bound.DisplayName != "Alice Example @ "+siteURL {
		t.Errorf("DisplayName = %q", bound.DisplayName)
	}
	if bound.Label != connectors.LabelPersonal {
		t.Errorf("Label = %q, want personal without company_sites", bound.Label)
	}
	if bound.Scopes != nil {
		t.Errorf("Scopes = %v, want nil when the token response has none", bound.Scopes)
	}
	if n := len(srv.Requests()); n != 2 {
		t.Errorf("requests = %d, want /me and accessible-resources only", n)
	}
	acct, cid, ok := atlassian.ParseExternalAccountID(bound.ExternalAccountID)
	if !ok || acct != "5b10ac8d82e05b22cc7d4ef5" || cid != cloudID {
		t.Errorf("ParseExternalAccountID = %q %q %v", acct, cid, ok)
	}
}

func TestBinderLabelsBySiteHostname(t *testing.T) {
	cases := map[string]struct {
		sites string
		label connectors.AccountLabel
	}{
		"company site listed":           {"example-site.atlassian.example.test", connectors.LabelCompany},
		"listed among others, any case": {"other.atlassian.example.test, Example-Site.Atlassian.Example.Test", connectors.LabelCompany},
		"listed as a url":               {"https://example-site.atlassian.example.test/", connectors.LabelCompany},
		"another site only":             {"other.atlassian.example.test", connectors.LabelPersonal},
		"second accessible site only":   {"personal-site.atlassian.example.test", connectors.LabelPersonal},
		"suffix is not a match":         {"site.atlassian.example.test", connectors.LabelPersonal},
		"empty list":                    {"", connectors.LabelPersonal},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := newAPIServer(t, bindRoutes("accessible_resources.json"))
			bound, err := atlassian.Binder{}.Bind(context.Background(), bindInput(srv, map[string]string{atlassian.ExtraCompanySites: tc.sites}, nil))
			if err != nil {
				t.Fatalf("Bind: %v", err)
			}
			if bound.Label != tc.label {
				t.Errorf("Label = %q, want %q", bound.Label, tc.label)
			}
		})
	}
}

func TestBinderScopesFromTheTokenResponse(t *testing.T) {
	srv := newAPIServer(t, bindRoutes("accessible_resources.json"))
	tok := (&oauth2.Token{AccessToken: testToken}).WithExtra(map[string]any{"scope": "read:jira-work offline_access write:jira-work"})
	bound, err := atlassian.Binder{}.Bind(context.Background(), bindInput(srv, nil, tok))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(bound.Scopes, " ") != "offline_access read:jira-work write:jira-work" {
		t.Errorf("Scopes = %v", bound.Scopes)
	}
}

func TestBinderNoAccessibleSite(t *testing.T) {
	srv := newAPIServer(t, bindRoutes("accessible_resources_empty.json"))
	_, err := atlassian.Binder{}.Bind(context.Background(), bindInput(srv, nil, nil))
	if !errors.Is(err, atlassian.ErrNoSite) {
		t.Fatalf("Bind err = %v, want ErrNoSite", err)
	}
}

func TestBinderRejectedToken(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /me": {status: 401, body: "error_unauthorized.json"}})
	_, err := atlassian.Binder{}.Bind(context.Background(), bindInput(srv, nil, nil))
	var aErr *atlassian.Error
	if !errors.As(err, &aErr) || aErr.Status != http.StatusUnauthorized || aErr.Class != atlassian.ClassReconnectRequired {
		t.Fatalf("Bind err = %v, want *atlassian.Error 401 class %s", err, atlassian.ClassReconnectRequired)
	}
}

func TestBinderUnavailableAndBadReplies(t *testing.T) {
	t.Run("5xx on accessible-resources", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"GET /me": {status: 200, body: "me.json"}, "GET /oauth/token/accessible-resources": {status: 503, body: ""}})
		_, err := atlassian.Binder{}.Bind(context.Background(), bindInput(srv, nil, nil))
		var aErr *atlassian.Error
		if !errors.As(err, &aErr) || aErr.Class != atlassian.ClassUnavailable {
			t.Fatalf("err = %v, want class unavailable", err)
		}
	})
	t.Run("me without an account id", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"GET /me": {status: 200, body: `{"name":"Nobody"}`}})
		_, err := atlassian.Binder{}.Bind(context.Background(), bindInput(srv, nil, nil))
		var aErr *atlassian.Error
		if !errors.As(err, &aErr) || aErr.Class != atlassian.ClassVendorError {
			t.Fatalf("err = %v, want class vendor_error", err)
		}
	})
	t.Run("site without an id", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"GET /me": {status: 200, body: "me.json"}, "GET /oauth/token/accessible-resources": {status: 200, body: `[{"url":"https://x.example.test","name":"X"}]`}})
		_, err := atlassian.Binder{}.Bind(context.Background(), bindInput(srv, nil, nil))
		if !errors.Is(err, atlassian.ErrNoSite) {
			t.Fatalf("err = %v, want ErrNoSite", err)
		}
	})
}

func TestBinderDerivesTheAPIRootFromUserInfoURL(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"GET /gateway/me": {status: 200, body: "me.json"},
		"GET /gateway/oauth/token/accessible-resources": {status: 200, body: "accessible_resources.json"},
	})
	in := bindInput(srv, nil, nil)
	in.App.UserInfoURL = srv.URL + "/gateway/me"
	if _, err := (atlassian.Binder{}).Bind(context.Background(), in); err != nil {
		t.Fatalf("Bind: %v", err)
	}
	in.App.UserInfoURL = ""
	b := atlassian.Binder{BaseURL: srv.URL + "/gateway"}
	if _, err := b.Bind(context.Background(), in); err != nil {
		t.Fatalf("Bind with BaseURL: %v", err)
	}
}

func TestParseExternalAccountID(t *testing.T) {
	for in, want := range map[string][3]string{
		"acct@cloud":       {"acct", "cloud", "ok"},
		"acct@":            {"", "", ""},
		"@cloud":           {"", "", ""},
		"nothing":          {"", "", ""},
		"a@b@c":            {"a@b", "c", "ok"},
		"":                 {"", "", ""},
		"\tacct @ cloud\n": {"acct", "cloud", "ok"},
	} {
		acct, cid, ok := atlassian.ParseExternalAccountID(in)
		if acct != want[0] || cid != want[1] || ok != (want[2] == "ok") {
			t.Errorf("ParseExternalAccountID(%q) = %q %q %v, want %v", in, acct, cid, ok, want)
		}
	}
}
