package atlassian

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/huynle/mcp-gateway/internal/connections"
	"github.com/huynle/mcp-gateway/internal/connectors"
)

// ExtraCompanySites is the vendor app Extra key listing the company's
// Atlassian sites by hostname (comma separated, case-insensitive;
// "acme.atlassian.net" or "https://acme.atlassian.net"). A connection
// bound to any of them is a company account; every other connection,
// and every connection when the list is empty, is personal.
//
// The connections package does not know this key, so it is not in its
// reserved list and would be sent to Atlassian as an authorization
// parameter (connections.VendorApp.AuthParams); registering it there is
// a one-line follow-up outside this package (see docs/connectors/atlassian.md).
const ExtraCompanySites = "company_sites"

// ErrNoSite says the account can reach no Atlassian site with the app
// (accessible-resources was empty): there is nothing to bind to.
var ErrNoSite = errors.New("atlassian: the account has no accessible Atlassian site for this app")

// Binder identifies the Atlassian account behind an OAuth 2.0 (3LO) token
// (connections.Binder for vendor "atlassian"): GET /me gives the
// permanent account id and the name, GET /oauth/token/accessible-resources
// the sites the token can reach; the connection binds to the FIRST site
// (the connect flow has no per-site selection yet), so the external
// account id is "<account id>@<cloud id>" and the display name
// "<name> @ <site url>". The label is company when the site's hostname
// is in the app's company_sites, else personal. Scopes are the token
// response's scope field (Atlassian returns the granted scopes there),
// else nil (the flow then records the requested scopes).
type Binder struct {
	// BaseURL overrides the API root (https://api.atlassian.com). Empty
	// derives it from the vendor app's UserInfoURL, then DefaultAPIBase.
	BaseURL string
}

// Bind implements connections.Binder.
func (b Binder) Bind(ctx context.Context, in connections.BindInput) (connections.Bound, error) {
	httpClient := in.Client
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	cl := &client{http: httpClient, base: b.baseURL(in.App)}
	var me struct {
		AccountID string `json:"account_id"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		Nickname  string `json:"nickname"`
	}
	if err := classify(Vendor, "identify account", cl.getJSON(ctx, cl.url("/me", nil), &me)); err != nil {
		return connections.Bound{}, err
	}
	if me.AccountID == "" {
		return connections.Bound{}, &Error{Class: ClassVendorError, Message: "identify account: Atlassian returned no account id"}
	}
	var resources []struct {
		ID   string `json:"id"`
		URL  string `json:"url"`
		Name string `json:"name"`
	}
	if err := classify(Vendor, "list accessible sites", cl.getJSON(ctx, cl.url("/oauth/token/accessible-resources", nil), &resources)); err != nil {
		return connections.Bound{}, err
	}
	if len(resources) == 0 || resources[0].ID == "" {
		return connections.Bound{}, ErrNoSite
	}
	site := resources[0]
	name := me.Name
	if name == "" {
		name = me.Nickname
	}
	if name == "" {
		name = me.Email
	}
	if name == "" {
		name = me.AccountID
	}
	bound := connections.Bound{
		ExternalAccountID: me.AccountID + "@" + site.ID,
		DisplayName:       name + " @ " + site.URL,
		Label:             connectors.LabelPersonal,
		Scopes:            grantedScopes(in),
	}
	if isCompanySite(site.URL, companySites(in.App)) {
		bound.Label = connectors.LabelCompany
	}
	return bound, nil
}

// baseURL picks the API root: the explicit override, else the vendor
// app's UserInfoURL with its trailing "me" segment removed, else
// DefaultAPIBase.
func (b Binder) baseURL(app connections.VendorApp) string {
	if b.BaseURL != "" {
		return strings.TrimSuffix(b.BaseURL, "/")
	}
	if app.UserInfoURL != "" {
		if u, err := url.Parse(app.UserInfoURL); err == nil && u.Host != "" {
			u.Path = strings.TrimSuffix(strings.TrimSuffix(u.Path, "/"), "/me")
			u.RawQuery, u.Fragment = "", ""
			return strings.TrimSuffix(u.String(), "/")
		}
	}
	return DefaultAPIBase
}

// companySites parses the app's company_sites list into lower-cased
// hostnames (a URL entry is reduced to its host).
func companySites(app connections.VendorApp) []string {
	var out []string
	for _, s := range strings.FieldsFunc(app.Extra[ExtraCompanySites], func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		if h := hostOf(s); h != "" {
			out = append(out, h)
		}
	}
	return out
}

// hostOf lower-cases a hostname, taking the host of a URL when given one.
func hostOf(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if strings.Contains(s, "://") {
		if u, err := url.Parse(s); err == nil {
			return u.Hostname()
		}
		return ""
	}
	return strings.TrimSuffix(strings.TrimSuffix(s, "/"), ".")
}

// isCompanySite reports whether the site URL's hostname is one of hosts.
func isCompanySite(siteURL string, hosts []string) bool {
	h := hostOf(siteURL)
	if h == "" {
		return false
	}
	for _, c := range hosts {
		if c == h {
			return true
		}
	}
	return false
}

// grantedScopes reads the token response's scope field; nil when absent.
func grantedScopes(in connections.BindInput) []string {
	if in.Token != nil {
		if raw, ok := in.Token.Extra("scope").(string); ok && strings.TrimSpace(raw) != "" {
			return connections.SplitScopes(raw)
		}
	}
	return nil
}

// ParseExternalAccountID splits a connection's external account id
// "<account id>@<cloud id>" (as Binder writes it) into its parts; ok is
// false when either is empty. The cloud id is what follows the last "@".
func ParseExternalAccountID(id string) (accountID, cloudID string, ok bool) {
	i := strings.LastIndexByte(id, '@')
	if i < 0 {
		return "", "", false
	}
	accountID, cloudID = strings.TrimSpace(id[:i]), strings.TrimSpace(id[i+1:])
	if accountID == "" || cloudID == "" {
		return "", "", false
	}
	return accountID, cloudID, true
}
