package slack_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"golang.org/x/oauth2"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/slack"
)

// v2Token is what x/oauth2 hands the binder after a Slack OAuth v2 code
// exchange of an app with bot and user scopes: the top-level access
// token is the BOT token; the user's own token, id and scopes sit under
// authed_user (quirk documented in decision q282qtlz).
func v2Token() *oauth2.Token {
	return (&oauth2.Token{AccessToken: botToken, TokenType: "bot"}).WithExtra(map[string]any{
		"scope":       "chat:write,im:write",
		"bot_user_id": "U0GATEWAYB",
		"team":        map[string]any{"id": "T0EXAMPLE1", "name": "Acme Corp"},
		"authed_user": map[string]any{
			"id": "U0ALICE001", "scope": "channels:read,chat:write,search:read", "access_token": testToken, "token_type": "user",
		},
	})
}

// bindInput builds the BindInput the connect flow hands a binder: the
// vendor app (its TokenURL points the binder at the fixture server),
// the exchanged token and a client authenticated with it.
func bindInput(srv *apiServer, extra map[string]string, tok *oauth2.Token) connections.BindInput {
	app := connections.Defaults(connections.VendorSlack, "")
	app.TokenURL = srv.API() + "oauth.v2.access"
	for k, v := range extra {
		app.Extra[k] = v
	}
	if tok == nil {
		tok = v2Token()
	}
	return connections.BindInput{
		App:    app,
		Token:  tok,
		Client: oauth2.NewClient(context.Background(), oauth2.StaticTokenSource(tok)),
	}
}

func TestBinderUsesTheAuthedUserToken(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"auth.test": {byToken: map[string]route{
		testToken: {body: "auth_test_user.json"},
		botToken:  {body: "auth_test_bot.json"},
	}}})
	bound, err := (slack.Binder{}).Bind(context.Background(), bindInput(srv, nil, nil))
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if bound.ExternalAccountID != connections.SlackAccountID("T0EXAMPLE1", "U0ALICE001") {
		t.Errorf("ExternalAccountID = %q, want T0EXAMPLE1:U0ALICE001", bound.ExternalAccountID)
	}
	if bound.DisplayName != "Acme Corp / alice" {
		t.Errorf("DisplayName = %q", bound.DisplayName)
	}
	if bound.Label != connectors.LabelPersonal {
		t.Errorf("Label = %q, want personal without a company team", bound.Label)
	}
	if got, want := bound.Scopes, []string{"channels:read", "chat:write", "search:read"}; !equalStrings(got, want) {
		t.Errorf("Scopes = %v, want the authed_user scopes %v (never the bot's)", got, want)
	}
	if n := srv.Count("auth.test"); n != 1 {
		t.Errorf("auth.test called %d times, want 1", n)
	}
	if got := srv.Last(t, "auth.test").Form.Get("token"); got != testToken {
		t.Errorf("auth.test ran with the bot token, want the authed_user token")
	}
	if got := srv.Last(t, "auth.test").Header.Get("Authorization"); got != "" {
		t.Errorf("Authorization header %q sent alongside the form token (the flow's bot-token client leaked through)", got)
	}
}

func TestBinderCompanyByTeamID(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"auth.test": {body: "auth_test_user.json"}})
	cases := map[string]map[string]string{
		"team id":               {slack.ExtraCompanyTeamID: "T0EXAMPLE1"},
		"team id, other case":   {slack.ExtraCompanyTeamID: "t0example1"},
		"team domain":           {slack.ExtraCompanyTeamDomain: "acme"},
		"team domain with host": {slack.ExtraCompanyTeamDomain: "acme.slack.com"},
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			bound, err := (slack.Binder{}).Bind(context.Background(), bindInput(srv, extra, nil))
			if err != nil {
				t.Fatalf("Bind: %v", err)
			}
			if bound.Label != connectors.LabelCompany {
				t.Errorf("Label = %q, want company", bound.Label)
			}
		})
	}
}

func TestBinderPersonalWhenTeamDiffers(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"auth.test": {body: "auth_test_user.json"}})
	cases := map[string]map[string]string{
		"other team id":     {slack.ExtraCompanyTeamID: "T0OTHER"},
		"other team domain": {slack.ExtraCompanyTeamDomain: "globex"},
		"no rule":           {},
	}
	for name, extra := range cases {
		t.Run(name, func(t *testing.T) {
			bound, err := (slack.Binder{}).Bind(context.Background(), bindInput(srv, extra, nil))
			if err != nil {
				t.Fatalf("Bind: %v", err)
			}
			if bound.Label != connectors.LabelPersonal {
				t.Errorf("Label = %q, want personal", bound.Label)
			}
		})
	}
}

// Without authed_user (a plain user token, as a static token source or
// a user-scopes-only exchange gives) auth.test identifies the account
// and the scopes come from Slack's X-OAuth-Scopes header.
func TestBinderFallsBackToAuthTest(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"auth.test": {body: "auth_test_user.json", headers: map[string]string{"X-OAuth-Scopes": "channels:history,users:read"}}})
	tok := &oauth2.Token{AccessToken: testToken}
	bound, err := (slack.Binder{}).Bind(context.Background(), bindInput(srv, map[string]string{slack.ExtraCompanyTeamID: "T0EXAMPLE1"}, tok))
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if bound.ExternalAccountID != "T0EXAMPLE1:U0ALICE001" || bound.DisplayName != "Acme Corp / alice" || bound.Label != connectors.LabelCompany {
		t.Errorf("bound = %+v", bound)
	}
	if got, want := bound.Scopes, []string{"channels:history", "users:read"}; !equalStrings(got, want) {
		t.Errorf("Scopes = %v, want %v from X-OAuth-Scopes", got, want)
	}
}

// authed_user without its own access token (token rotation or a
// trimmed response): the id and team come from the exchange, auth.test
// runs with the only token there is, and the user id of authed_user
// wins over the bot user auth.test reports.
func TestBinderAuthedUserWithoutToken(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"auth.test": {byToken: map[string]route{botToken: {body: "auth_test_bot.json"}}}})
	tok := (&oauth2.Token{AccessToken: botToken}).WithExtra(map[string]any{
		"team":        map[string]any{"id": "T0EXAMPLE1", "name": "Acme Corp"},
		"authed_user": map[string]any{"id": "U0ALICE001", "scope": "chat:write"},
	})
	bound, err := (slack.Binder{}).Bind(context.Background(), bindInput(srv, nil, tok))
	if err != nil {
		t.Fatalf("Bind: %v", err)
	}
	if bound.ExternalAccountID != "T0EXAMPLE1:U0ALICE001" {
		t.Errorf("ExternalAccountID = %q", bound.ExternalAccountID)
	}
	if bound.DisplayName != "Acme Corp / U0ALICE001" {
		t.Errorf("DisplayName = %q, want the team and the user id (the bot token cannot name the user)", bound.DisplayName)
	}
	if got, want := bound.Scopes, []string{"chat:write"}; !equalStrings(got, want) {
		t.Errorf("Scopes = %v, want %v", got, want)
	}
}

func TestBinderRejectedToken(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"auth.test": {body: "error_invalid_auth.json"}})
	_, err := (slack.Binder{}).Bind(context.Background(), bindInput(srv, nil, nil))
	var sErr *slack.Error
	if !errors.As(err, &sErr) || sErr.Class != slack.ClassReconnectRequired {
		t.Fatalf("Bind err = %v, want *slack.Error class %s", err, slack.ClassReconnectRequired)
	}
}

func TestBinderUnavailable(t *testing.T) {
	srv := newAPIServer(t, map[string]route{"auth.test": {status: http.StatusBadGateway, body: "<html>bad gateway</html>"}})
	_, err := (slack.Binder{}).Bind(context.Background(), bindInput(srv, nil, nil))
	var sErr *slack.Error
	if !errors.As(err, &sErr) || sErr.Class != slack.ClassUnavailable || sErr.Status != 502 {
		t.Fatalf("Bind err = %v, want *slack.Error class %s 502", err, slack.ClassUnavailable)
	}
}

func TestBinderNeedsAToken(t *testing.T) {
	srv := newAPIServer(t, nil)
	in := bindInput(srv, nil, nil)
	in.Token = nil
	if _, err := (slack.Binder{}).Bind(context.Background(), in); err == nil {
		t.Error("Bind without a token succeeded")
	}
	in = bindInput(srv, nil, &oauth2.Token{})
	if _, err := (slack.Binder{}).Bind(context.Background(), in); err == nil {
		t.Error("Bind with an empty token succeeded")
	}
	if n := len(srv.Requests()); n != 0 {
		t.Errorf("%d requests sent without a token", n)
	}
}

func TestBinderDerivesAPIBaseFromTokenURL(t *testing.T) {
	// The default vendor app's TokenURL is https://slack.com/api/oauth.v2.access,
	// so the API root is https://slack.com/api/; an explicit BaseURL wins.
	app := connections.Defaults(connections.VendorSlack, "")
	if got := (slack.Binder{}).APIBase(app); got != "https://slack.com/api/" {
		t.Errorf("APIBase(default app) = %q", got)
	}
	app.TokenURL = "https://slack.example.test/api/oauth.v2.access"
	if got := (slack.Binder{}).APIBase(app); got != "https://slack.example.test/api/" {
		t.Errorf("APIBase(custom token url) = %q", got)
	}
	override := slack.Binder{BaseURL: "http://127.0.0.1:1/api/"}
	if got := override.APIBase(app); got != "http://127.0.0.1:1/api/" {
		t.Errorf("APIBase(override) = %q", got)
	}
	app.TokenURL = ""
	if got := (slack.Binder{}).APIBase(app); got != "https://slack.com/api/" {
		t.Errorf("APIBase(no token url) = %q", got)
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
