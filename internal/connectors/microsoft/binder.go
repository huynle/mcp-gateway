package microsoft

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
	"github.com/huynle/mcp-gateway/internal/connectors/microsoft/graph"
)

// ExtraCompanyTenants is the vendor app Extra key listing the company's
// Entra tenant ids (comma separated, case-insensitive). An account from
// any of them is a company account; every other account, and every
// account when the list is empty, is personal.
//
// NOTE: connections.reservedExtra does not know this key yet (the
// connections package is outside this connector's ownership), so the
// connect flow also sends it to Microsoft as an authorization parameter,
// which Entra ignores. Adding it to reservedExtra is a follow-up for the
// connections package.
const ExtraCompanyTenants = "company_tenants"

// Binder identifies the Microsoft account behind a token
// (connections.Binder for vendor "microsoft"): GET /me gives the
// permanent object id and the user principal name (the display name);
// the tenant id comes from the id token's tid claim when the token
// response carried one (the openid scope), else from GET /organization
// (work accounts answer with their tenant; Graph refuses it for personal
// accounts, which are then PersonalTenant). The external account id is
// "<tenant id>:<object id>"; the label is company when the tenant is in
// the app's company_tenants, else personal; the scopes are the token
// response's scope field, else the requested scopes, minus the
// work-only permissions (WorkOnlyScope: Teams, SharePoint, directory,
// shared calendars) for personal accounts, which cannot use them
// (decision mh7c6z3v).
type Binder struct {
	// BaseURL overrides the Graph root (with trailing slash). Empty
	// derives it from the vendor app's UserInfoURL, then
	// graph.DefaultBaseURL.
	BaseURL string
}

// graphUser is the part of GET /me the binder reads.
type graphUser struct {
	ID                string `json:"id"`
	DisplayName       string `json:"displayName"`
	UserPrincipalName string `json:"userPrincipalName"`
	Mail              string `json:"mail"`
}

// Bind implements connections.Binder.
func (b Binder) Bind(ctx context.Context, in connections.BindInput) (connections.Bound, error) {
	httpClient := in.Client
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	accessToken := ""
	if in.Token != nil {
		accessToken = in.Token.AccessToken
	}
	client, err := graph.New(graph.Options{HTTPClient: httpClient, BaseURL: b.baseURL(in.App), Token: oauth2.StaticTokenSource(&oauth2.Token{AccessToken: accessToken})})
	if err != nil {
		return connections.Bound{}, err
	}
	var me graphUser
	if err := classify("identify account", client.Get(ctx, "me", url.Values{"$select": {"id,displayName,userPrincipalName,mail"}}, &me)); err != nil {
		return connections.Bound{}, err
	}
	if me.ID == "" {
		return connections.Bound{}, &Error{Class: ClassVendorError, Message: "identify account: Microsoft Graph returned no user id"}
	}
	claims := idTokenClaims(in.Token)
	tenant := strings.ToLower(strings.TrimSpace(claims["tid"]))
	if tenant == "" {
		if tenant, err = b.tenantFromOrganization(ctx, client); err != nil {
			return connections.Bound{}, err
		}
	}
	display := me.UserPrincipalName
	if display == "" {
		display = me.Mail
	}
	if display == "" {
		display = me.DisplayName
	}
	if display == "" {
		display = me.ID
	}
	bound := connections.Bound{
		ExternalAccountID: tenant + ":" + me.ID,
		DisplayName:       display,
		Label:             connectors.LabelPersonal,
		Scopes:            grantedScopes(in),
	}
	if companyTenants(in.App)[tenant] {
		bound.Label = connectors.LabelCompany
	}
	if tenant == PersonalTenant {
		bound.Scopes = stripWorkOnlyScopes(bound.Scopes)
	}
	return bound, nil
}

// baseURL picks the Graph root: the explicit override, else the vendor
// app's UserInfoURL with its trailing "me" segment removed, else the
// default.
func (b Binder) baseURL(app connections.VendorApp) string {
	if b.BaseURL != "" {
		return b.BaseURL
	}
	if app.UserInfoURL != "" {
		if u, err := url.Parse(app.UserInfoURL); err == nil && u.Host != "" {
			u.Path = strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), "/me")
			u.RawQuery, u.Fragment = "", ""
			return strings.TrimSuffix(u.String(), "/") + "/"
		}
	}
	return graph.DefaultBaseURL
}

// companyTenants parses the app's company_tenants list, lower-cased.
func companyTenants(app connections.VendorApp) map[string]bool {
	out := map[string]bool{}
	for _, t := range strings.FieldsFunc(app.Extra[ExtraCompanyTenants], func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		if t = strings.ToLower(strings.TrimSpace(t)); t != "" {
			out[t] = true
		}
	}
	return out
}

// idTokenClaims decodes the payload of the token response's id_token
// without verifying it: it came straight from the token endpoint over
// TLS in the code exchange, so only its shape is checked. A missing or
// malformed id token yields no claims.
func idTokenClaims(tok *oauth2.Token) map[string]string {
	out := map[string]string{}
	if tok == nil {
		return out
	}
	raw, _ := tok.Extra("id_token").(string)
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return out
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return out
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return out
	}
	for k, v := range claims {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}

// tenantFromOrganization reads the tenant id from GET /organization. A
// work account answers with its organization; Graph refuses the call for
// personal accounts (400/403/404), which are then PersonalTenant. A
// rejected token, a throttle, a 5xx or a network failure is returned:
// binding must not guess.
func (b Binder) tenantFromOrganization(ctx context.Context, client *graph.Client) (string, error) {
	var out struct {
		Value []struct {
			ID string `json:"id"`
		} `json:"value"`
	}
	err := classify("identify tenant", client.Get(ctx, "organization", url.Values{"$select": {"id"}}, &out))
	switch {
	case err == nil:
		if len(out.Value) > 0 && out.Value[0].ID != "" {
			return strings.ToLower(out.Value[0].ID), nil
		}
		return PersonalTenant, nil
	case classOf(err) == ClassForbidden, classOf(err) == ClassNotFound, classOf(err) == ClassInvalidArgument:
		return PersonalTenant, nil
	}
	return "", err
}

// grantedScopes reads the token response's scope field, else the
// requested scopes; sorted and unique.
func grantedScopes(in connections.BindInput) []string {
	if in.Token != nil {
		if raw, ok := in.Token.Extra("scope").(string); ok && strings.TrimSpace(raw) != "" {
			return connections.SplitScopes(raw)
		}
	}
	return connections.SplitScopes(strings.Join(in.RequestedScopes, " "))
}
