package google

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"

	"google.golang.org/api/googleapi"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
)

// ExtraCompanyDomains is the vendor app Extra key listing the company's
// email domains (comma separated, case-insensitive). An account whose
// hosted domain (the hd claim) or email domain is one of them is a
// company account; every other account is personal. Without the list,
// default_label decides, else the variant (internal = company).
const ExtraCompanyDomains = connections.ExtraCompanyDomains

// DefaultUserInfoURL is Google's OpenID Connect userinfo endpoint, used
// when the vendor app has no User info URL.
const DefaultUserInfoURL = "https://openidconnect.googleapis.com/v1/userinfo"

// Binder identifies the Google account behind a token (connections.Binder
// for vendor "google", both variants): the OpenID Connect userinfo
// document gives the permanent sub ("google:<sub>" is the external
// account id) and the email (the display name); the label is company
// when the hd claim or the email's domain is in the app's
// company_domains, personal otherwise (see ExtraCompanyDomains for the
// fallbacks); the scopes are the token response's scope field (Google
// returns exactly what the user granted, which with granular consent may
// be fewer than requested), nil when the response carried none (the
// connect flow then records the requested scopes). An account without a
// hosted domain (hd: a consumer account) never keeps the Workspace-only
// scopes (WorkspaceOnlyScope), whatever its label.
type Binder struct {
	// UserInfoURL overrides the userinfo endpoint. Empty uses the vendor
	// app's UserInfoURL, then DefaultUserInfoURL.
	UserInfoURL string
}

// userInfo is the subset of the OpenID Connect userinfo document the
// binder reads.
type userInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	HD            string `json:"hd"`
}

// Bind implements connections.Binder.
func (b Binder) Bind(ctx context.Context, in connections.BindInput) (connections.Bound, error) {
	info, err := b.fetchUserInfo(ctx, in)
	if err != nil {
		return connections.Bound{}, err
	}
	if info.Sub == "" {
		return connections.Bound{}, &Error{Class: ClassVendorError, Message: "identify account: Google returned no account id (sub)"}
	}
	name := strings.TrimSpace(info.Email)
	if name == "" {
		name = strings.TrimSpace(info.Name)
	}
	if name == "" {
		name = info.Sub
	}
	return connections.Bound{
		ExternalAccountID: "google:" + info.Sub,
		DisplayName:       name,
		Label:             labelFor(in.App, info),
		Scopes:            boundScopes(in, info),
	}, nil
}

// boundScopes are the scopes Bind records: grantedScopes, minus the
// Workspace-only scopes (WorkspaceOnlyScope) when the account has no
// hosted domain (a consumer account cannot use them, whatever its label).
// Without a scope field a consumer account that was asked for one gets
// the requested scopes minus them; otherwise nil leaves the flow to
// record what it requested.
func boundScopes(in connections.BindInput, info userInfo) []string {
	scopes := grantedScopes(in)
	if strings.TrimSpace(info.HD) != "" {
		return scopes
	}
	if scopes == nil {
		if stripped, removed := stripWorkspaceOnlyScopes(connections.SplitScopes(strings.Join(in.RequestedScopes, " "))); removed {
			return stripped
		}
		return nil
	}
	stripped, _ := stripWorkspaceOnlyScopes(scopes)
	return stripped
}

// fetchUserInfo GETs the userinfo document with the authenticated client.
func (b Binder) fetchUserInfo(ctx context.Context, in connections.BindInput) (userInfo, error) {
	u := b.UserInfoURL
	if u == "" {
		u = in.App.UserInfoURL
	}
	if u == "" {
		u = DefaultUserInfoURL
	}
	httpClient := in.Client
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return userInfo{}, &Error{Class: ClassInvalidArgument, Message: "identify account: user info URL: " + err.Error(), Err: err}
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", userAgent)
	res, err := httpClient.Do(req)
	if err != nil {
		return userInfo{}, classify("identify account", err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		return userInfo{}, classify("identify account", err)
	}
	if err := googleapi.CheckResponseWithBody(res, body); err != nil {
		return userInfo{}, classify("identify account", err)
	}
	var info userInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return userInfo{}, &Error{Class: ClassVendorError, Message: "identify account: Google returned no user info document", Err: err}
	}
	return info, nil
}

// labelFor applies the company_domains rule to the hosted domain and the
// email domain, then default_label, then the variant rule.
func labelFor(app connections.VendorApp, info userInfo) connectors.AccountLabel {
	if domains := companyDomains(app); len(domains) > 0 {
		hd := strings.ToLower(strings.TrimSpace(info.HD))
		if (hd != "" && slices.Contains(domains, hd)) || slices.Contains(domains, domainOf(info.Email)) {
			return connectors.LabelCompany
		}
		return connectors.LabelPersonal
	}
	switch strings.ToLower(strings.TrimSpace(app.Extra[connections.ExtraDefaultLabel])) {
	case string(connectors.LabelCompany):
		return connectors.LabelCompany
	case string(connectors.LabelPersonal):
		return connectors.LabelPersonal
	}
	if app.Variant == connections.GoogleInternal {
		return connectors.LabelCompany
	}
	return connectors.LabelPersonal
}

// companyDomains parses the app's company_domains list, lower-cased.
func companyDomains(app connections.VendorApp) []string {
	var out []string
	for _, d := range strings.FieldsFunc(app.Extra[ExtraCompanyDomains], func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		if d = strings.ToLower(strings.TrimSpace(d)); d != "" {
			out = append(out, d)
		}
	}
	return out
}

// grantedScopes reads the token response's scope field; nil when it
// carried none.
func grantedScopes(in connections.BindInput) []string {
	if in.Token == nil {
		return nil
	}
	if raw, ok := in.Token.Extra("scope").(string); ok && strings.TrimSpace(raw) != "" {
		return connections.SplitScopes(raw)
	}
	return nil
}

var _ connections.Binder = Binder{}
