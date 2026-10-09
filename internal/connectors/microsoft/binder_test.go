package microsoft_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/oauth2"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/microsoft"
)

const (
	workTenant = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	workOID    = "11111111-2222-4333-8444-555555555555"
)

// idToken builds an unsigned-looking JWT (header.payload.signature) with
// the given claims; the binder reads the payload only (the token came
// straight from the token endpoint over TLS).
func idToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	return enc(map[string]any{"alg": "RS256", "typ": "JWT"}) + "." + enc(claims) + ".c2ln"
}

// bindInput builds the BindInput the connect flow hands a binder: the
// vendor app (its UserInfoURL points the binder at the fixture server),
// the exchanged token and a client authenticated with it.
func bindInput(srv *apiServer, extra map[string]string, tok *oauth2.Token) connections.BindInput {
	app := connections.Defaults(connections.VendorMicrosoft, "")
	app.UserInfoURL = srv.URL + "/v1.0/me"
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
		RequestedScopes: workScopes,
	}
}

func TestBinderWorkAccountFromIDToken(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /v1.0/me": {status: 200, body: "me.json"}})
	tok := (&oauth2.Token{AccessToken: testToken}).WithExtra(map[string]any{
		"id_token": idToken(t, map[string]any{"tid": workTenant, "oid": workOID, "preferred_username": "alice@example.test"}),
		"scope":    "User.Read Mail.Read Mail.Send Team.ReadBasic.All Channel.ReadBasic.All ChannelMessage.Read.All ChannelMessage.Send offline_access",
	})
	bound, err := microsoft.Binder{}.Bind(context.Background(), bindInput(srv, map[string]string{microsoft.ExtraCompanyTenants: "Other-Tenant, " + strings.ToUpper(workTenant)}, tok))
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if bound.ExternalAccountID != workTenant+":"+workOID {
		t.Errorf("ExternalAccountID = %q, want %s:%s", bound.ExternalAccountID, workTenant, workOID)
	}
	if bound.DisplayName != "alice@example.test" {
		t.Errorf("DisplayName = %q, want the user principal name", bound.DisplayName)
	}
	if bound.Label != connectors.LabelCompany {
		t.Errorf("Label = %q, want company", bound.Label)
	}
	want := []string{"Channel.ReadBasic.All", "ChannelMessage.Read.All", "ChannelMessage.Send", "Mail.Read", "Mail.Send", "Team.ReadBasic.All", "User.Read", "offline_access"}
	if strings.Join(bound.Scopes, " ") != strings.Join(want, " ") {
		t.Errorf("Scopes = %v, want the token's scopes sorted: %v", bound.Scopes, want)
	}
	if n := srv.Count("GET /v1.0/organization"); n != 0 {
		t.Errorf("organization looked up %d times although the id token carried tid", n)
	}
}

func TestBinderWorkAccountOutsideCompanyIsPersonalLabel(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /v1.0/me": {status: 200, body: "me.json"}})
	tok := (&oauth2.Token{AccessToken: testToken}).WithExtra(map[string]any{
		"id_token": idToken(t, map[string]any{"tid": workTenant, "oid": workOID}),
		"scope":    "User.Read Team.ReadBasic.All",
	})
	bound, err := microsoft.Binder{}.Bind(context.Background(), bindInput(srv, map[string]string{microsoft.ExtraCompanyTenants: "ffffffff-0000-4000-8000-000000000000"}, tok))
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if bound.Label != connectors.LabelPersonal {
		t.Errorf("Label = %q, want personal (another tenant)", bound.Label)
	}
	// Another organization's account is still a work account: its Teams
	// scopes stay.
	if strings.Join(bound.Scopes, " ") != "Team.ReadBasic.All User.Read" {
		t.Errorf("Scopes = %v, want Teams kept for a work tenant", bound.Scopes)
	}
	// No company_tenants at all: personal.
	bound, err = microsoft.Binder{}.Bind(context.Background(), bindInput(srv, nil, tok))
	if err != nil || bound.Label != connectors.LabelPersonal {
		t.Errorf("Bind without company_tenants = %+v, %v; want personal", bound, err)
	}
}

func TestBinderPersonalAccountStripsTeamsScopes(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"GET /v1.0/me": {status: 200, body: "me_personal.json"}})
	tok := (&oauth2.Token{AccessToken: testToken}).WithExtra(map[string]any{
		"id_token": idToken(t, map[string]any{"tid": microsoft.PersonalTenant, "oid": "00000000-0000-0000-0003-bffd1a2b3c4d"}),
		"scope":    "User.Read Mail.Read Team.ReadBasic.All Channel.ReadBasic.All ChannelMessage.Read.All ChannelMessage.Send Sites.Read.All offline_access",
	})
	bound, err := microsoft.Binder{}.Bind(context.Background(), bindInput(srv, map[string]string{microsoft.ExtraCompanyTenants: workTenant}, tok))
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if bound.ExternalAccountID != microsoft.PersonalTenant+":0003bffd1a2b3c4d" {
		t.Errorf("ExternalAccountID = %q", bound.ExternalAccountID)
	}
	if bound.Label != connectors.LabelPersonal {
		t.Errorf("Label = %q, want personal", bound.Label)
	}
	if bound.DisplayName != "alice.example@outlook.example.test" {
		t.Errorf("DisplayName = %q", bound.DisplayName)
	}
	if strings.Join(bound.Scopes, " ") != "Mail.Read User.Read offline_access" {
		t.Errorf("Scopes = %v, want the Teams and SharePoint scopes stripped", bound.Scopes)
	}
	for _, s := range bound.Scopes {
		if microsoft.TeamsScope(s) {
			t.Errorf("Teams scope %q kept on a personal account", s)
		}
	}
}

func TestBinderTenantFromOrganizationWithoutIDToken(t *testing.T) {
	srv := newAPIServer(t, map[string]route{
		"GET /v1.0/me":           {status: 200, body: "me.json"},
		"GET /v1.0/organization": {status: 200, body: "organization.json"},
	})
	bound, err := microsoft.Binder{}.Bind(context.Background(), bindInput(srv, map[string]string{microsoft.ExtraCompanyTenants: workTenant}, nil))
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if bound.ExternalAccountID != workTenant+":"+workOID || bound.Label != connectors.LabelCompany {
		t.Errorf("bound = %+v, want tenant from /organization and company", bound)
	}
	// Without a scope field the requested scopes are the granted ones.
	if strings.Join(bound.Scopes, " ") != strings.Join(sorted(workScopes), " ") {
		t.Errorf("Scopes = %v, want the requested scopes", bound.Scopes)
	}
	if q := query(t, srv, "/v1.0/organization").Get("$select"); q != "id" {
		t.Errorf("$select = %q, want id only", q)
	}
}

func TestBinderPersonalWhenOrganizationIsRefused(t *testing.T) {
	// Consumer accounts have no organization: Graph refuses the call.
	for name, rt := range map[string]route{
		"403": {status: 403, body: "error_access_denied.json"},
		"404": {status: 404, body: "error_item_not_found.json"},
		"400": {status: 400, body: "error_invalid_request.json"},
	} {
		t.Run(name, func(t *testing.T) {
			srv := newAPIServer(t, map[string]route{
				"GET /v1.0/me":           {status: 200, body: "me_personal.json"},
				"GET /v1.0/organization": rt,
			})
			tok := (&oauth2.Token{AccessToken: testToken}).WithExtra(map[string]any{"scope": "User.Read Mail.Read Team.ReadBasic.All"})
			bound, err := microsoft.Binder{}.Bind(context.Background(), bindInput(srv, map[string]string{microsoft.ExtraCompanyTenants: workTenant}, tok))
			if err != nil {
				t.Fatalf("Bind: %v", err)
			}
			if bound.ExternalAccountID != microsoft.PersonalTenant+":0003bffd1a2b3c4d" || bound.Label != connectors.LabelPersonal {
				t.Errorf("bound = %+v, want the personal tenant", bound)
			}
			if strings.Join(bound.Scopes, " ") != "Mail.Read User.Read" {
				t.Errorf("Scopes = %v, want Teams stripped", bound.Scopes)
			}
		})
	}
}

func TestBinderDoesNotGuessOnFailures(t *testing.T) {
	t.Run("organization unavailable", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{
			"GET /v1.0/me":           {status: 200, body: "me.json"},
			"GET /v1.0/organization": {status: 503, body: "error_server.json"},
		})
		_, err := microsoft.Binder{}.Bind(context.Background(), bindInput(srv, nil, nil))
		wantClass(t, err, microsoft.ClassUnavailable, 503)
	})
	t.Run("rejected token", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"GET /v1.0/me": {status: 401, body: "error_invalid_token.json"}})
		_, err := microsoft.Binder{}.Bind(context.Background(), bindInput(srv, nil, nil))
		wantClass(t, err, microsoft.ClassReconnectRequired, http.StatusUnauthorized)
	})
	t.Run("me without id", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{"GET /v1.0/me": {status: 200, body: `{"displayName":"x"}`}})
		_, err := microsoft.Binder{}.Bind(context.Background(), bindInput(srv, nil, nil))
		var msErr *microsoft.Error
		if !errors.As(err, &msErr) || msErr.Class != microsoft.ClassVendorError {
			t.Errorf("err = %v, want vendor_error", err)
		}
	})
	t.Run("id token tid disagreeing with nothing is used; a malformed id token is ignored", func(t *testing.T) {
		srv := newAPIServer(t, map[string]route{
			"GET /v1.0/me":           {status: 200, body: "me.json"},
			"GET /v1.0/organization": {status: 200, body: "organization.json"},
		})
		tok := (&oauth2.Token{AccessToken: testToken}).WithExtra(map[string]any{"id_token": "not.a.jwt"})
		bound, err := microsoft.Binder{}.Bind(context.Background(), bindInput(srv, nil, tok))
		if err != nil || bound.ExternalAccountID != workTenant+":"+workOID {
			t.Errorf("bound = %+v err = %v, want the organization fallback", bound, err)
		}
	})
}

func TestBinderDerivesAPIBaseFromUserInfoURL(t *testing.T) {
	// A sovereign-cloud app sets UserInfoURL to its own Graph host; the
	// lookups must go to the same root (here a different path prefix).
	srv := newAPIServer(t, map[string]route{
		"GET /v1.0/beta-root/me":           {status: 200, body: "me.json"},
		"GET /v1.0/beta-root/organization": {status: 200, body: "organization.json"},
	})
	in := bindInput(srv, nil, nil)
	in.App.UserInfoURL = srv.URL + "/v1.0/beta-root/me"
	bound, err := microsoft.Binder{}.Bind(context.Background(), in)
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if bound.ExternalAccountID != workTenant+":"+workOID {
		t.Errorf("ExternalAccountID = %q", bound.ExternalAccountID)
	}
}

func sorted(in []string) []string {
	return connections.SplitScopes(strings.Join(in, " "))
}
