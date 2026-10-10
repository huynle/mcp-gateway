package slack

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	goslack "github.com/slack-go/slack"
	"golang.org/x/oauth2"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
)

// Vendor app Extra keys the binder reads. They are binder hints, not
// authorization parameters: connections reserves them, so they never
// reach Slack's authorize URL.
const (
	// ExtraCompanyTeamID is the Slack team (workspace) id whose accounts
	// are company accounts ("T0..."; case-insensitive).
	ExtraCompanyTeamID = connections.ExtraCompanyTeamID
	// ExtraCompanyTeamDomain is the company workspace's domain, the
	// "acme" of acme.slack.com (a full host is accepted too), used when
	// the team id is unknown. Either match makes the account company.
	ExtraCompanyTeamDomain = connections.ExtraCompanyTeamDomain
	// ExtraMarkerReconcile, when "true", opts post_message and
	// reply_in_thread into marker reconciliation (Options.MarkerReconcile;
	// read at start-up by cmd/gateway).
	ExtraMarkerReconcile = connections.ExtraMarkerReconcile
)

// DefaultAPIBase is Slack's Web API root.
const DefaultAPIBase = "https://slack.com/api/"

// userAgent identifies the gateway to Slack.
const userAgent = "mcp-gateway"

// Binder identifies the Slack account behind an OAuth v2 token
// (connections.Binder for vendor "slack"). A Slack v2 code exchange of
// an app with bot and user scopes answers with the BOT token at the top
// level and the user's own token, id and scopes under authed_user;
// x/oauth2 keeps those fields in the token's extras. The binder reads
// authed_user when present (id, scope, access_token) and team (id,
// name), runs auth.test with the user token (or with the only token it
// has) for the user name and the workspace domain, and produces
// connections.SlackAccountID(team, user) = "<team id>:<user id>" as the
// external account id, "<team name> / <user name>" as the display name,
// company when the team matches the vendor app's company_team_id or
// company_team_domain, else personal, the authed_user scopes (else
// Slack's X-OAuth-Scopes header on the auth.test answer, else nil so the
// flow records the requested scopes), and the authed_user token as
// Bound.Token so the connection stores the USER token, never the bot's
// (with token rotation on, authed_user's own refresh_token and
// expires_in travel with it).
type Binder struct {
	// BaseURL overrides the API root (with trailing slash). Empty derives
	// it from the vendor app's TokenURL, then DefaultAPIBase.
	BaseURL string
}

// authedUser is the authed_user object of a Slack OAuth v2 answer.
// RefreshToken and ExpiresIn are set only when the app has token
// rotation on.
type authedUser struct {
	ID, Scope, AccessToken, RefreshToken string
	ExpiresIn                            int64
}

// token returns the user token the connection should store (nil without
// an authed_user access token). Slack's token_type "user" is not an
// HTTP scheme; the Web API takes the token as a bearer.
func (a authedUser) token() *oauth2.Token {
	if a.AccessToken == "" {
		return nil
	}
	return &oauth2.Token{AccessToken: a.AccessToken, TokenType: "Bearer", RefreshToken: a.RefreshToken, ExpiresIn: a.ExpiresIn}
}

// Bind implements connections.Binder.
func (b Binder) Bind(ctx context.Context, in connections.BindInput) (connections.Bound, error) {
	if in.Token == nil || in.Token.AccessToken == "" {
		return connections.Bound{}, &Error{Class: ClassReconnectRequired, Message: "identify account: the exchange returned no access token"}
	}
	authed := authedUserOf(in.Token)
	teamID, teamName := teamOf(in.Token)
	token := authed.AccessToken
	if token == "" {
		token = in.Token.AccessToken
	}
	api := goslack.New(token, goslack.OptionAPIURL(b.APIBase(in.App)), goslack.OptionHTTPClient(&http.Client{Transport: baseTransport(in.Client)}))
	resp, err := api.AuthTestContext(ctx)
	if err := classify("identify account", err); err != nil {
		return connections.Bound{}, err
	}
	userID := authed.ID
	if userID == "" {
		userID = resp.UserID
	}
	if teamID == "" {
		teamID = resp.TeamID
	}
	if userID == "" || teamID == "" {
		return connections.Bound{}, &Error{Class: ClassVendorError, Message: "identify account: Slack returned no user id or team id"}
	}
	if teamName == "" {
		teamName = resp.Team
	}
	userName := userID
	if resp.UserID == userID && resp.User != "" {
		userName = resp.User
	}
	bound := connections.Bound{
		ExternalAccountID: connections.SlackAccountID(teamID, userID),
		DisplayName:       teamName + " / " + userName,
		Label:             connectors.LabelPersonal,
		Scopes:            grantedScopes(authed, resp),
		Token:             authed.token(),
	}
	if isCompanyTeam(in.App, teamID, resp.URL) {
		bound.Label = connectors.LabelCompany
	}
	return bound, nil
}

// APIBase picks the Web API root: the explicit override, else the vendor
// app's TokenURL with its last path segment removed, else slack.com.
func (b Binder) APIBase(app connections.VendorApp) string {
	if b.BaseURL != "" {
		return b.BaseURL
	}
	if app.TokenURL != "" {
		if u, err := url.Parse(app.TokenURL); err == nil && u.Host != "" {
			u.RawQuery, u.Fragment = "", ""
			if i := strings.LastIndexByte(u.Path, '/'); i >= 0 {
				u.Path = u.Path[:i+1]
			}
			return u.String()
		}
	}
	return DefaultAPIBase
}

// authedUserOf reads authed_user from the token's extras (numbers are
// float64 or json.Number depending on who decoded the answer).
func authedUserOf(tok *oauth2.Token) authedUser {
	m, _ := tok.Extra("authed_user").(map[string]any)
	s := func(k string) string { v, _ := m[k].(string); return strings.TrimSpace(v) }
	var expiresIn int64
	switch v := m["expires_in"].(type) {
	case float64:
		expiresIn = int64(v)
	case json.Number:
		expiresIn, _ = v.Int64()
	}
	return authedUser{ID: s("id"), Scope: s("scope"), AccessToken: s("access_token"), RefreshToken: s("refresh_token"), ExpiresIn: expiresIn}
}

// teamOf reads team.id and team.name from the token's extras.
func teamOf(tok *oauth2.Token) (id, name string) {
	m, _ := tok.Extra("team").(map[string]any)
	id, _ = m["id"].(string)
	name, _ = m["name"].(string)
	return strings.TrimSpace(id), strings.TrimSpace(name)
}

// grantedScopes reads the authed_user scopes, else the X-OAuth-Scopes
// header of the auth.test answer; nil when neither says anything.
func grantedScopes(authed authedUser, resp *goslack.AuthTestResponse) []string {
	if authed.Scope != "" {
		return connections.SplitScopes(authed.Scope)
	}
	if resp != nil {
		if raw := strings.TrimSpace(resp.Header.Get("X-OAuth-Scopes")); raw != "" {
			return connections.SplitScopes(raw)
		}
	}
	return nil
}

// isCompanyTeam applies the vendor app's company_team_id and
// company_team_domain rules to the team id and the workspace URL
// auth.test reported.
func isCompanyTeam(app connections.VendorApp, teamID, workspaceURL string) bool {
	if want := strings.TrimSpace(app.Extra[ExtraCompanyTeamID]); want != "" && strings.EqualFold(want, teamID) {
		return true
	}
	want := strings.ToLower(strings.TrimSpace(app.Extra[ExtraCompanyTeamDomain]))
	if want == "" {
		return false
	}
	got := workspaceDomain(workspaceURL)
	if got == "" {
		return false
	}
	return want == got || strings.TrimSuffix(want, ".slack.com") == got || want == got+".slack.com"
}

// workspaceDomain extracts "acme" from https://acme.slack.com/.
func workspaceDomain(workspaceURL string) string {
	u, err := url.Parse(workspaceURL)
	if err != nil || u.Host == "" {
		return ""
	}
	host := strings.ToLower(u.Hostname())
	if i := strings.IndexByte(host, '.'); i > 0 {
		return host[:i]
	}
	return host
}

// baseTransport returns the transport under an oauth2-authenticated
// client (the flow's client sends the top-level, possibly bot, token as
// a bearer; slack-go sends its own token as a form field, and Slack
// must not see two), else the client's transport, else the default.
func baseTransport(client *http.Client) http.RoundTripper {
	if client == nil {
		return http.DefaultTransport
	}
	if t, ok := client.Transport.(*oauth2.Transport); ok {
		if t.Base != nil {
			return t.Base
		}
		return http.DefaultTransport
	}
	if client.Transport != nil {
		return client.Transport
	}
	return http.DefaultTransport
}
