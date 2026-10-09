package connections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

// errNoAccessToken is the exchange answer that carries no token anywhere
// the gateway knows to look.
var errNoAccessToken = errors.New("connections: token response has no access token")

// exchange swaps the authorization code for a token: x/oauth2 for every
// vendor but Slack. A Slack OAuth v2 answer (oauth.v2.access) puts the
// BOT token at the top level and the user's token under authed_user; an
// app that requests only user scopes has no top-level access_token at
// all, which x/oauth2 refuses. exchangeSlack reads the raw answer itself
// and lifts authed_user's token when the top level has none; the whole
// answer stays reachable through Token.Extra for the Slack binder.
func (s *Service) exchange(ctx context.Context, app VendorApp, conf *oauth2.Config, code, verifier string) (*oauth2.Token, error) {
	if app.Vendor == VendorSlack {
		return s.exchangeSlack(ctx, conf, code, verifier)
	}
	return conf.Exchange(s.oauthContext(ctx), code, oauth2.VerifierOption(verifier))
}

// exchangeSlack posts the code to Slack's token endpoint (client
// credentials as form fields, as Slack documents) and decodes the v2
// answer. Errors are *oauth2.RetrieveError so vendorErrorCode reports
// Slack's error code (Slack answers ok:false with HTTP 200).
func (s *Service) exchangeSlack(ctx context.Context, conf *oauth2.Config, code, verifier string) (*oauth2.Token, error) {
	form := url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {conf.RedirectURL}, "code_verifier": {verifier},
		"client_id": {conf.ClientID}, "client_secret": {conf.ClientSecret},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, conf.Endpoint.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	res, err := s.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connections: slack token endpoint: %w", err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("connections: slack token response: %w", err)
	}
	var raw map[string]any
	decodeErr := json.Unmarshal(body, &raw)
	ok, _ := raw["ok"].(bool)
	if res.StatusCode < 200 || res.StatusCode > 299 || decodeErr != nil || !ok {
		re := &oauth2.RetrieveError{Response: res, Body: body, ErrorCode: jsonString(raw["error"]), ErrorDescription: jsonString(raw["error_description"])}
		if re.ErrorCode == "" && res.StatusCode >= 200 && res.StatusCode <= 299 {
			re.ErrorCode = "invalid_response" // 2xx that is not a Slack answer
		}
		return nil, re
	}
	tok := slackToken(raw, s.clock())
	if tok.AccessToken == "" {
		return nil, errNoAccessToken
	}
	return tok.WithExtra(raw), nil
}

// slackToken builds the token from a decoded oauth.v2.access answer: the
// top-level fields as x/oauth2 would read them, else authed_user's own
// (then a bearer token: Slack's token_type "user" is not an HTTP scheme).
// Expiry is set from expires_in when there is one (token rotation);
// Slack tokens otherwise never expire.
func slackToken(raw map[string]any, now time.Time) *oauth2.Token {
	tok := &oauth2.Token{
		AccessToken: jsonString(raw["access_token"]), TokenType: jsonString(raw["token_type"]),
		RefreshToken: jsonString(raw["refresh_token"]), ExpiresIn: jsonInt(raw["expires_in"]),
	}
	if tok.AccessToken == "" {
		if authed, ok := raw["authed_user"].(map[string]any); ok {
			tok = &oauth2.Token{
				AccessToken: jsonString(authed["access_token"]), TokenType: "Bearer",
				RefreshToken: jsonString(authed["refresh_token"]), ExpiresIn: jsonInt(authed["expires_in"]),
			}
		}
	}
	if tok.ExpiresIn > 0 {
		tok.Expiry = now.Add(time.Duration(tok.ExpiresIn) * time.Second)
	}
	return tok
}

func jsonString(v any) string {
	s, _ := v.(string)
	return strings.TrimSpace(s)
}

func jsonInt(v any) int64 {
	switch n := v.(type) {
	case float64:
		return int64(n)
	case json.Number:
		i, _ := n.Int64()
		return i
	}
	return 0
}
