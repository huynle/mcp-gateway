package google_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/oauth2"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/google"
)

// bindInput builds the BindInput the connect flow hands a binder: the
// vendor app of the given variant (its UserInfoURL points the binder at
// the fixture server), the exchanged token and a client authenticated
// with it.
func bindInput(srv *apiServer, variant string, extra map[string]string, tok *oauth2.Token) connections.BindInput {
	app := connections.Defaults(connections.VendorGoogle, variant)
	app.UserInfoURL = srv.URL + "/v1/userinfo"
	for k, v := range extra {
		app.Extra[k] = v
	}
	if tok == nil {
		tok = &oauth2.Token{AccessToken: testToken}
	}
	return connections.BindInput{
		App:             app,
		Token:           tok,
		Client:          oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(tok)),
		RequestedScopes: []string{"openid", "https://www.googleapis.com/auth/userinfo.email", google.ScopeCalendarEvents, google.ScopeGmailReadonly},
	}
}

const userinfoPath = "GET /v1/userinfo"

func TestBinderCompanyWhenHostedDomainListed(t *testing.T) {
	srv := newAPIServer(t, map[string]route{userinfoPath: {status: 200, body: "userinfo_company.json"}})
	bound, err := google.Binder{}.Bind(context.Background(), bindInput(srv, connections.GoogleExternal, map[string]string{connections.ExtraCompanyDomains: "other.test, Example.Test"}, nil))
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if bound.ExternalAccountID != "google:110248495921238986420" {
		t.Errorf("ExternalAccountID = %q", bound.ExternalAccountID)
	}
	if bound.DisplayName != "alice@example.test" {
		t.Errorf("DisplayName = %q, want the email", bound.DisplayName)
	}
	if bound.Label != connectors.LabelCompany {
		t.Errorf("Label = %q, want company", bound.Label)
	}
	if n := len(srv.Requests()); n != 1 {
		t.Errorf("requests = %d, want 1", n)
	}
}

func TestBinderPersonalWhenDomainNotListed(t *testing.T) {
	srv := newAPIServer(t, map[string]route{userinfoPath: {status: 200, body: "userinfo_personal.json"}})
	bound, err := google.Binder{}.Bind(context.Background(), bindInput(srv, connections.GoogleExternal, map[string]string{connections.ExtraCompanyDomains: "example.test"}, nil))
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if bound.Label != connectors.LabelPersonal || bound.DisplayName != "alice.home@gmail.test" || bound.ExternalAccountID != "google:118374829102938475610" {
		t.Errorf("bound = %+v, want personal", bound)
	}
}

// The email domain alone (no hd claim: a consumer account, or a Workspace
// account whose userinfo omits hd) also classifies.
func TestBinderCompanyByEmailDomainWithoutHD(t *testing.T) {
	srv := newAPIServer(t, map[string]route{userinfoPath: {status: 200, body: `{"sub":"1","email":"Bob@Example.TEST","email_verified":true}`}})
	bound, err := google.Binder{}.Bind(context.Background(), bindInput(srv, connections.GoogleExternal, map[string]string{connections.ExtraCompanyDomains: "example.test"}, nil))
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if bound.Label != connectors.LabelCompany || bound.DisplayName != "Bob@Example.TEST" {
		t.Errorf("bound = %+v, want company", bound)
	}
}

// Without company_domains: default_label, else the variant decides
// (internal = company, external = personal).
func TestBinderWithoutCompanyDomains(t *testing.T) {
	cases := []struct {
		name    string
		variant string
		extra   map[string]string
		want    connectors.AccountLabel
	}{
		{"internal variant is company", connections.GoogleInternal, nil, connectors.LabelCompany},
		{"external variant is personal", connections.GoogleExternal, nil, connectors.LabelPersonal},
		{"default_label company", connections.GoogleExternal, map[string]string{connections.ExtraDefaultLabel: "company"}, connectors.LabelCompany},
		{"default_label personal", connections.GoogleInternal, map[string]string{connections.ExtraDefaultLabel: "personal"}, connectors.LabelPersonal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{userinfoPath: {status: 200, body: "userinfo_company.json"}})
			bound, err := google.Binder{}.Bind(context.Background(), bindInput(srv, tc.variant, tc.extra, nil))
			if err != nil {
				t.Fatalf("Bind: %v", err)
			}
			if bound.Label != tc.want {
				t.Errorf("Label = %q, want %q", bound.Label, tc.want)
			}
		})
	}
}

// Granular consent: the token response's scope field says what was
// actually granted, which may be fewer than requested; it is recorded
// exactly.
func TestBinderScopesFromTokenResponse(t *testing.T) {
	srv := newAPIServer(t, map[string]route{userinfoPath: {status: 200, body: "userinfo_company.json"}})
	tok := (&oauth2.Token{AccessToken: testToken}).WithExtra(map[string]any{
		"scope": "https://www.googleapis.com/auth/userinfo.email openid " + google.ScopeCalendarEvents,
	})
	bound, err := google.Binder{}.Bind(context.Background(), bindInput(srv, connections.GoogleExternal, nil, tok))
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	want := []string{google.ScopeCalendarEvents, "https://www.googleapis.com/auth/userinfo.email", "openid"}
	if strings.Join(bound.Scopes, " ") != strings.Join(want, " ") {
		t.Errorf("Scopes = %v, want %v (sorted; gmail.readonly was declined)", bound.Scopes, want)
	}
	for _, s := range bound.Scopes {
		if s == google.ScopeGmailReadonly {
			t.Error("a declined scope was recorded as granted")
		}
	}
	// No scope field: nil, so the flow falls back to what was requested.
	bound, err = google.Binder{}.Bind(context.Background(), bindInput(srv, connections.GoogleExternal, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	if bound.Scopes != nil {
		t.Errorf("Scopes without a scope field = %v, want nil", bound.Scopes)
	}
}

func TestBinderErrors(t *testing.T) {
	t.Run("401 reconnect", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{userinfoPath: {status: 401, body: "error_unauthorized.json"}})
		_, err := google.Binder{}.Bind(context.Background(), bindInput(srv, connections.GoogleExternal, nil, nil))
		wantClass(t, err, google.ClassReconnectRequired, http.StatusUnauthorized)
	})
	t.Run("5xx unavailable", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{userinfoPath: {status: 500, body: "error_server.json"}})
		_, err := google.Binder{}.Bind(context.Background(), bindInput(srv, connections.GoogleExternal, nil, nil))
		wantClass(t, err, google.ClassUnavailable, http.StatusInternalServerError)
	})
	t.Run("no sub", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{userinfoPath: {status: 200, body: "userinfo_no_sub.json"}})
		_, err := google.Binder{}.Bind(context.Background(), bindInput(srv, connections.GoogleExternal, nil, nil))
		wantClass(t, err, google.ClassVendorError, 0)
	})
	t.Run("not json", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{userinfoPath: {status: 200, body: `[1,2]`}})
		_, err := google.Binder{}.Bind(context.Background(), bindInput(srv, connections.GoogleExternal, nil, nil))
		wantClass(t, err, google.ClassVendorError, 0)
	})
	t.Run("override url", func(t *testing.T) {
		// Without a User info URL on the vendor app the binder's override
		// (and, in production, DefaultUserInfoURL) is used.
		srv := newAPIServer(t, map[string]route{"GET /override/userinfo": {status: 200, body: "userinfo_company.json"}})
		in := bindInput(srv, connections.GoogleExternal, nil, nil)
		in.App.UserInfoURL = ""
		b := google.Binder{UserInfoURL: srv.URL + "/override/userinfo"}
		bound, err := b.Bind(context.Background(), in)
		if err != nil || bound.ExternalAccountID != "google:110248495921238986420" {
			t.Fatalf("Bind = %+v, %v", bound, err)
		}
		if google.DefaultUserInfoURL != "https://openidconnect.googleapis.com/v1/userinfo" {
			t.Errorf("DefaultUserInfoURL = %q", google.DefaultUserInfoURL)
		}
	})
}

// The binder never sends the token anywhere but the user info URL and
// never sends the client secret.
func TestBinderUsesTheAuthenticatedClient(t *testing.T) {
	srv := newAPIServer(t, map[string]route{userinfoPath: {status: 200, body: "userinfo_company.json"}})
	in := bindInput(srv, connections.GoogleExternal, nil, nil)
	if _, err := (google.Binder{}).Bind(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	req := srv.Last(t, userinfoPath)
	if req.Header.Get("Accept") != "application/json" {
		t.Errorf("Accept = %q", req.Header.Get("Accept"))
	}
}
